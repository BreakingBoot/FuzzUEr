import csv
import glob
import hashlib
import os
import re
import sys
import json
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


# Launching against an image built before a flag existed wastes a whole batch: every
# container exits instantly with "unrecognized arguments" and the run looks like a fuzzing
# failure. Ask the image what it supports before starting anything.
# A protocol whose calls are slow spends the whole budget inside one chain of 8: EfiShell
# completed zero iterations that way, and at 2 it covered 23,621 edges. Shortening the
# chain everywhere is wrong -- EfiDevicePathUtilities lost 1,461 edges at 2, because a
# shorter sequence reaches less state -- so it is applied only where the last run shows
# the protocol was starved.
def starved_in(previous, protocol, threshold):
    log = os.path.join(previous, protocol, 'log.json')
    if not os.path.isfile(log):
        return False
    iterations = 0
    try:
        with open(log, 'r', encoding='utf-8', errors='ignore') as handle:
            for line in handle:
                if '"Heartbeat"' in line:
                    try:
                        iterations = int((json.loads(line).get('Heartbeat') or {})
                                         .get('iterations') or 0)
                    except ValueError:
                        continue
    except OSError:
        return False
    return iterations < threshold


def image_supports(image, flags):
    if not flags:
        return []
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'bash', image, '-c',
         'python3 /workspace/firness.py --help 2>&1'],
        capture_output=True, text=True)
    help_text = result.stdout + result.stderr
    return [flag for flag in flags if flag not in help_text]


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
    # Name by the output directory as well as the protocol. Keying on the protocol alone
    # means two campaigns over the same target -- a rerun started before the first
    # finished, an A/B across two output directories -- collide, and the rm -f below makes
    # that silent: each launch destroys the other's container, both keep restarting, and
    # neither reaches the harness while the logs look merely slow. Worse, a container
    # removed before it exits never runs its copy-out, so the run leaves an empty
    # directory and reads as a campaign that found nothing. Four overlapping runs lost
    # their results that way. Different output directories are different runs, so give
    # them different names and let them coexist.
    tag = hashlib.sha1(os.path.abspath(args.output).encode()).hexdigest()[:6]
    # The prefix is configurable because "docker rm -f $(docker ps -aq --filter
    # name=^fuzz-)" is the obvious way to clear a stuck matrix, and it takes every other
    # campaign on the host with it. Give a run that must not be swept its own prefix.
    prefix = os.environ.get('FIRNESS_CONTAINER_PREFIX', 'fuzz')
    name = f'{prefix}-{protocol.lower()}-{tag}'
    # Same output directory and same protocol really is a collision, so still refuse.
    running = subprocess.run(['docker', 'ps', '--filter', f'name=^{name}$',
                              '--format', '{{.Names}}'], capture_output=True, text=True)
    if name in running.stdout.split():
        print(f'  {protocol}: {name} is already running -- another campaign has this '
              f'target. Stop it first, or run this one from a different protocol.')
        return None
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
    if args.smi:
        command += ' --smi'
    if args.backend != 'tsffs':
        command += f' --backend {args.backend}'
    if args.iteration_timeout:
        command += f' --iteration-timeout {args.iteration_timeout}'
    if args.snapshot:
        command += ' --snapshot'
    steps = args.max_steps
    if args.tune_from and starved_in(os.path.abspath(args.tune_from), protocol,
                                     args.starved_under):
        steps = args.starved_steps
        print(f'  {protocol}: starved last run, chaining {steps} calls instead of 8')
    if steps:
        command += f' --max-steps {steps}'
    if args.seed_from and os.path.isdir(
            os.path.join(os.path.abspath(args.seed_from), protocol, 'corpus')):
        command += ' --seed-corpus /seed'
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
    # start from the corpus a previous run of this protocol produced, so coverage
    # compounds across campaigns instead of every run beginning from random inputs
    if args.seed_from:
        seed = os.path.join(os.path.abspath(args.seed_from), protocol, 'corpus')
        if os.path.isdir(seed):
            argv += ['-v', f'{seed}:/seed:ro']
    if args.cpus:
        argv += ['--cpus', str(args.cpus)]
    # Forward the FIRNESS_* settings. Without this a value set on the host -- the QEMU
    # backend's per-iteration timeout in particular -- silently does not reach the
    # campaign, and the run looks like a target that always times out rather than one
    # that was never given long enough.
    for name_, value in sorted(os.environ.items()):
        if name_.startswith('FIRNESS_'):
            argv += ['-e', f'{name_}={value}']
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


def declared_guids(repo):
    """Every GUID symbol the source tree declares, from its .dec files."""
    found = set()
    for tree in sorted(glob.glob(os.path.join(repo, 'edk2*'))):
        for dec in glob.glob(os.path.join(tree, '**', '*.dec'), recursive=True):
            try:
                text = open(dec, errors='ignore').read()
            except OSError:
                continue
            found.update(re.findall(r'(g\w+Guid)\s*=\s*\{', text))
    return found


def undeclared(protocol, guids):
    """True when this edk2 declares no GUID for the protocol.

    Not the same question as whether the firmware installs it. edk2 removes deprecated
    protocols, and moving to mainline drops seven of the targets here -- EFI_UNICODE_COLLATION
    (v1), UGA_DRAW, SCSI_PASS_THRU, DEVICE_IO, UGA_IO, USB_HC and IP4_CONFIG. A campaign
    against one of those spends a full analysis and build to end at "undefined reference to
    gEfiUnicodeCollationProtocolGuid", which says nothing about the protocol having been
    deleted upstream.

    This warns rather than skips: a target named for a group of protocols rather than one
    (ShellPaths, HiiConfig, TcpStack) has no single GUID either and is perfectly valid.
    """
    if not guids:
        return False
    return not any(f'g{protocol}{suffix}Guid' in guids for suffix in ('Protocol', ''))


def bindable(output, image):
    """Can the daemon actually bind this directory, or only something that looks like it?

    A bind whose source the daemon cannot see is not an error: docker creates the path
    inside its own namespace, the container writes there happily, every campaign exits 0
    and every result directory on the host is empty. A whole batch was lost that way, and
    nothing in the output said so -- it reads as campaigns that found nothing.

    So write a file through the daemon and look for it here before committing to a run.
    """
    probe = os.path.join(os.path.abspath(output), '.bindprobe')
    os.makedirs(os.path.dirname(probe), exist_ok=True)
    if os.path.exists(probe):
        os.unlink(probe)
    subprocess.run(['docker', 'run', '--rm', '-v', f'{os.path.abspath(output)}:/probe',
                    image, 'bash', '-c', 'touch /probe/.bindprobe'],
                   capture_output=True, text=True)
    ok = os.path.exists(probe)
    if ok:
        os.unlink(probe)
    return ok


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
    parser.add_argument('--presence', type=str, default=None,
                        help='A csv from scripts/protocol_presence.py. Protocols this '
                             'firmware does not install are skipped, with the reason '
                             'recorded in <output>/skipped.csv')
    parser.add_argument('-j', '--jobs', type=int, default=6,
                        help='How many protocols to fuzz at once')
    parser.add_argument('-t', '--budget', type=int, default=600,
                        help='Fuzzing seconds per protocol, counted from the harness being hit')
    parser.add_argument('--snapshot', action='store_true',
                        help='Restore the booted checkpoint instead of booting each campaign')
    parser.add_argument('--tune-from', type=str, default='',
                        help='A previous run directory: protocols that were starved there '
                             'get a shorter call chain this time')
    parser.add_argument('--starved-under', type=int, default=50,
                        help='Iterations below which a protocol counts as starved (default 50)')
    parser.add_argument('--starved-steps', type=int, default=2,
                        help='Calls chained for a starved protocol (default 2)')
    parser.add_argument('--max-steps', type=int, default=0,
                        help='Calls chained per fuzzing iteration (generator default 8)')
    parser.add_argument('--seed-from', type=str, default='',
                        help='A previous run directory: each protocol starts from the '
                             'corpus its campaign there produced')
    parser.add_argument('--iteration-timeout', type=float, default=0,
                        help='Simulated seconds per fuzzing iteration before it times out')
    parser.add_argument('--boot-timeout', type=int, default=2700,
                        help='Seconds to allow for the boot before giving up on a protocol')
    parser.add_argument('--image', type=str, default=DEFAULT_IMAGE)
    parser.add_argument('--cpus', type=str, default='',
                        help='Per-container cpu limit, e.g. 2 -- leaves the box usable by others')
    parser.add_argument('--backend', type=str, default='tsffs',
                        choices=['tsffs', 'qemu', 'nyx', 'none'])
    parser.add_argument('--smi', action='store_true',
                        help='Fuzz SMI handlers rather than protocols. The request file '
                             'lists handler names and the cache must hold a '
                             'smi-function-guid-map.json, so these are separate targets '
                             'from the protocol ones, not a mode on top of them.')
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

    # A protocol the firmware never installs cannot be fuzzed: the harness's opening
    # LocateProtocol fails and every Fuzz* function returns at once, but the campaign still
    # pays a full boot and its whole budget. On matrix v8 that was 65 of 142 protocols --
    # 46% of the run producing nothing but harness startup coverage. Skip them by name and
    # record why, rather than silently dropping them.
    if args.presence:
        status = {}
        try:
            with open(args.presence, newline='') as handle:
                for row in csv.DictReader(handle):
                    status[row['protocol']] = row['status']
        except OSError as exc:
            print(f'Error: cannot read {args.presence}: {exc}')
            return 1
        stale = [p for p in todo if p not in status]
        absent = [p for p in todo if status.get(p) == 'absent']
        todo = [p for p in todo if status.get(p) != 'absent']
        if absent:
            print(f'Skipping {len(absent)} protocol(s) this firmware does not install: '
                  f'{", ".join(absent[:6])}{"..." if len(absent) > 6 else ""}')
            os.makedirs(args.output, exist_ok=True)
            with open(os.path.join(args.output, 'skipped.csv'), 'w', newline='') as handle:
                writer = csv.writer(handle)
                writer.writerow(['protocol', 'reason'])
                for name in absent:
                    writer.writerow([name, 'protocol not installed by this firmware'])
        if stale:
            # a census taken against different firmware would silently mis-skip
            print(f'Warning: {len(stale)} protocol(s) are absent from the census '
                  f'({", ".join(stale[:4])}...); running them rather than guessing')

    wanted = []
    if args.iteration_timeout:
        wanted.append('--iteration-timeout')
    if args.max_steps or args.tune_from:
        wanted.append('--max-steps')
    if args.seed_from:
        wanted.append('--seed-corpus')
    if args.snapshot:
        wanted.append('--snapshot')
    missing = image_supports(args.image, wanted)
    if missing:
        print(f'Error: {args.image} does not accept {", ".join(missing)}. It was built '
              f'before those existed -- rebuild it (docker build -f run.Dockerfile -t '
              f'{args.image} .) or drop the flag.')
        return 2

    os.makedirs(args.output, exist_ok=True)
    if not args.dry_run and not bindable(args.output, args.image):
        print(f'the docker daemon cannot bind {os.path.abspath(args.output)} -- it would '
              f'mount a directory of its own there and every campaign would exit 0 having '
              f'written nothing to the host. Choose a path the daemon shares, such as one '
              f'under the repo.', file=sys.stderr)
        return 2

    tree_guids = declared_guids(args.repo)
    missing = [p for p in todo if undeclared(p, tree_guids)]
    if missing:
        print(f'  note: this edk2 declares no GUID for {len(missing)} target(s): '
              f'{", ".join(missing)}')
        print('  a deprecated protocol removed upstream will fail to link; a target named '
              'for a group of protocols is fine')

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
