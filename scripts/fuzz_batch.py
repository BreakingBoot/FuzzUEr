import os
import sys
import time
import shutil
import argparse
import subprocess


# Fuzz many protocols without doing them one after another. A single campaign is dominated
# by the boot, not by the fuzzing: the firmware takes minutes to reach the shell and then
# runs at a couple of executions a second, so running one protocol at a time spends almost
# all of the wall clock booting the same image over and over. Each protocol gets its own
# container, several run at once, and every run drops its log.json where
# scripts/coverage_matrix.py can summarise the lot.
DEFAULT_IMAGE = 'fuzzuer-cur:latest'


def running(names):
    if not names:
        return []
    result = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'],
                            capture_output=True, text=True)
    alive = set(result.stdout.split())
    return [n for n in names if n in alive]


def launch(protocol, args):
    out = os.path.join(args.output, protocol)
    os.makedirs(out, exist_ok=True)
    name = f'fuzz-{protocol.lower()}'
    subprocess.run(['docker', 'rm', '-f', name],
                   capture_output=True, text=True)
    # firness.py works out of its own cwd: it expects -s to point at a tree holding edk2
    # and writes everything, log.json included, into <cwd>/firness_output.
    #
    # -g as well as -f, and seed firness_output from the cached analysis first. With -f
    # alone firness.py skips generation entirely and fuzzes whatever Firness.efi is already
    # baked into the image -- one harness, the same one for every protocol -- so a whole
    # matrix of "per-protocol" coverage was really one harness measured over and over.
    command = (
        f'cd /workspace && rm -rf firness_output && mkdir -p firness_output && '
        f'cp /input/anacache/{protocol}/*.json firness_output/ && '
        f'python3 /workspace/firness.py -s /workspace/tmp '
        f'-i /input/evalset/{protocol}.txt -g -f '
        f'-t {args.budget} --boot-timeout {args.boot_timeout}'
    )
    if args.backend != 'tsffs':
        command += f' --backend {args.backend}'
    if args.iteration_timeout:
        command += f' --iteration-timeout {args.iteration_timeout}'
    # keep firness.py's own output: it is where "Fuzzer exited after Ns of its 900s
    # budget" and "Harness reached after Ns of boot" are printed, and without it a run
    # that lost 90% of its budget looks identical to one that used all of it
    command = f'({command}) 2>&1 | tee /output/run.log'
    # copy out even when the run failed, so a boot that never reached the harness still
    # leaves the serial capture behind to explain why
    command += ' ; cp -r /workspace/firness_output/. /output/ 2>/dev/null'
    command += ' ; cp /workspace/projects/example/fuzz.txt /output/ 2>/dev/null ; true'
    argv = ['docker', 'run', '--name', name, '-d',
            '-v', f'{args.repo}/eval_source:/input:ro',
            '-v', f'{os.path.abspath(out)}:/output']
    if args.cpus:
        argv += ['--cpus', str(args.cpus)]
    argv += [args.image, 'bash', '-c', command]
    if args.dry_run:
        print('  would run:', ' '.join(argv[:8]), '...', command)
        return name
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        print(f'  {protocol}: launch failed: {result.stderr.strip()[:120]}')
        return None
    return name


def already_done(output, protocol):
    return os.path.isfile(os.path.join(output, protocol, 'log.json'))


def main():
    parser = argparse.ArgumentParser(
        description='Fuzz many protocols in parallel and collect one log per protocol')
    parser.add_argument('-r', '--repo', type=str,
                        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        help='Repository root')
    parser.add_argument('-o', '--output', type=str, required=True,
                        help='Directory to hold one subdirectory per protocol')
    parser.add_argument('-p', '--protocols', type=str, nargs='*',
                        help='Protocols to run (default: every request file that has a harness)')
    parser.add_argument('-j', '--jobs', type=int, default=6,
                        help='How many protocols to fuzz at once')
    parser.add_argument('-t', '--budget', type=int, default=600,
                        help='Fuzzing seconds per protocol, counted from the harness being hit')
    parser.add_argument('--iteration-timeout', type=float, default=0,
                        help='Simulated seconds per fuzzing iteration before it times out')
    parser.add_argument('--boot-timeout', type=int, default=2700,
                        help='Seconds to allow for the boot before giving up on a protocol')
    parser.add_argument('--image', type=str, default=DEFAULT_IMAGE)
    parser.add_argument('--cpus', type=str, default='',
                        help='Per-container cpu limit, e.g. 2 -- leaves the box usable by others')
    parser.add_argument('--backend', type=str, default='tsffs',
                        choices=['tsffs', 'qemu', 'nyx', 'none'])
    parser.add_argument('--max-load', type=float, default=0.0,
                        help='Wait rather than launch while the 1 minute load is above this')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print what would run without starting anything')
    args = parser.parse_args()

    if args.protocols:
        todo = list(args.protocols)
    else:
        requests = os.path.join(args.repo, 'eval_source', 'evalset')
        todo = sorted(f[:-4] for f in os.listdir(requests) if f.endswith('.txt'))

    os.makedirs(args.output, exist_ok=True)
    todo = [p for p in todo if not already_done(args.output, p)]
    print(f'{len(todo)} protocol(s) to fuzz, {args.jobs} at a time, '
          f'{args.budget}s each')

    active, started, failed = [], 0, 0
    while todo or active:
        active = running(active)
        while todo and len(active) < args.jobs:
            if args.max_load and not args.dry_run:
                with open('/proc/loadavg') as handle:
                    load = float(handle.read().split()[0])
                if load > args.max_load:
                    print(f'  load {load:.0f} above {args.max_load:.0f}, holding')
                    break
            protocol = todo.pop(0)
            name = launch(protocol, args)
            if name is None:
                failed += 1
                continue
            started += 1
            print(f'  started {protocol} ({started} launched, {len(todo)} queued)')
            if not args.dry_run:
                active.append(name)
        if args.dry_run:
            break
        if active or todo:
            time.sleep(30)

    print(f'\nlaunched {started}, failed to launch {failed}')
    print(f'summarise with: python3 {os.path.join(args.repo, "scripts", "coverage_matrix.py")} '
          f'-r {args.output}')
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
