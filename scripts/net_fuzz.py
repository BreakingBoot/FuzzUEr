"""Fuzz the network stack by corrupting what the peer answers.

scripts/net_peer.py is the server; this is the loop around it. Each iteration picks an
input, boots the guest against a peer whose replies are corrupted from that input, and
classifies what the firmware did. An input that produced something worth looking at is
kept, so the run is reproducible: net_peer.py replays the same packets from the same file.

What this reaches that a protocol harness does not: Dhcp4Dxe's option parser, Mtftp4Dxe's
OACK and DATA handling, UefiPxeBcDxe's boot file logic, and -- when a real application is
served -- the PE loader and everything the downloaded image touches. None of that is
reachable by calling protocol members with fuzzed arguments, because none of it is driven
by the caller.

  python3 scripts/net_fuzz.py --code OVMF_CODE.fd --vars OVMF_VARS.fd \\
      --serve-file some.efi --iterations 20 --mutate 6

Outcomes, in the order they are checked:
  exception  the firmware faulted; the debug log names the type
  asan       a sanitizer report reached the serial log
  hang       the guest stopped talking before the peer's budget ran out
  rejected   the image was fetched and the loader refused it, which is correct behaviour
  boot       the image was fetched and run, which is the uncorrupted path
  nofetch    the transfer never completed; the mutation broke the exchange too early
"""

import argparse
import hashlib
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time


REPORT_SITE = re.compile(r'Return IP address is (0x[0-9A-Fa-f]+)')


def report_sites(serial_text):
    """The set of sites that reported, not the number of reports.

    An instrumented boot raises the same findings every time -- 31 of them on the
    per-module image, from HiiDatabase and the DXE page allocator -- so a run that simply
    counts reports calls every iteration a finding. Grouping by return IP and subtracting
    the baseline is what makes a new site stand out. Same lesson as triage_crashes.py.
    """
    return set(REPORT_SITE.findall(serial_text))


def classify(debug_text, serial_text, peer_text, baseline):
    if 'Exception Type' in debug_text or 'Exception Type' in serial_text:
        for line in debug_text.splitlines() + serial_text.splitlines():
            if 'Exception Type' in line:
                return 'exception', line.strip()
        return 'exception', 'unattributed'
    new_sites = report_sites(serial_text) - baseline
    if new_sites:
        shown = ' '.join(sorted(new_sites)[:4])
        return 'asan', f'{len(new_sites)} new site(s): {shown}'
    if 'frames in: 0' in peer_text:
        return 'hang', 'the guest never spoke'
    if 'transfers completed: 0' in peer_text:
        # How far it got matters for triage: a corrupted DHCP option that still completes
        # the exchange means the option parser ran and coped, which is a result. No
        # exchange at all usually means the mutation broke the reply's framing.
        exchanges = 0
        for line in peer_text.splitlines():
            if line.startswith('exchanges:'):
                exchanges = int(line.split(':')[1])
        reached = 'DHCP completed, PXE gave up' if exchanges >= 3 else \
                  f'stopped after {exchanges} exchange(s)'
        return 'nofetch', f'no transfer -- {reached}'
    # Fetched and refused is the healthy answer to a corrupted image, and worth telling
    # apart from a clean boot: it says the bytes reached the loader and it validated them.
    if 'start failed' in debug_text or 'Image Error' in debug_text:
        for line in debug_text.splitlines():
            if 'start failed' in line:
                return 'rejected', line.strip()
        return 'rejected', 'the loader refused the image'
    return 'boot', 'image fetched and run'


def run_once(args, seed_path, index, work, baseline=frozenset()):
    port = args.base_port + (index % 200)
    peer_log = os.path.join(work, 'peer.log')
    debug_log = os.path.join(work, 'debug.log')
    serial_log = os.path.join(work, 'serial.log')
    vars_copy = os.path.join(work, 'vars.fd')
    # A written OVMF_VARS remembers a boot order that no longer points at PXE, so every
    # iteration starts from the pristine one.
    shutil.copyfile(args.vars, vars_copy)

    peer_cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             'net_peer.py'),
                '--port', str(port), '--duration', str(args.duration),
                '--accept-timeout', str(args.accept_timeout),
                '--mutate', str(args.mutate), '--skip-packets', str(args.skip_packets),
                '--mutate-labels', args.mutate_labels,
                '--input', seed_path, '--quiet']
    if args.serve_file:
        peer_cmd += ['--serve-file', args.serve_file]
    with open(peer_log, 'w') as handle:
        peer = subprocess.Popen(peer_cmd, stdout=handle, stderr=subprocess.STDOUT)
    time.sleep(0.5)

    qemu_cmd = [
        args.qemu, '-machine', 'q35', '-m', args.memory, '-no-reboot', '-smp', '1',
        '-fw_cfg', 'name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes',
        '-debugcon', f'file:{debug_log}', '-global', 'isa-debugcon.iobase=0x402',
        '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={args.code}',
        '-drive', f'if=pflash,format=raw,unit=1,file={vars_copy}',
        '-netdev', f'socket,id=n0,connect=127.0.0.1:{port}',
        '-device', f'virtio-net-pci,netdev=n0,mac={args.client_mac}',
        '-display', 'none', '-serial', f'file:{serial_log}',
    ]
    try:
        subprocess.run(qemu_cmd, timeout=args.duration + 20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    try:
        peer.send_signal(signal.SIGINT)
        peer.wait(timeout=15)
    except Exception:
        peer.kill()

    def read(path):
        try:
            with open(path, 'rb') as handle:
                return handle.read().decode('utf-8', errors='replace').replace('\r', '')
        except OSError:
            return ''

    debug_text, serial_text, peer_text = read(debug_log), read(serial_log), read(peer_log)
    return classify(debug_text, serial_text, peer_text, baseline), \
        peer_text, debug_text, serial_text


def main():
    parser = argparse.ArgumentParser(description='Fuzz a UEFI network stack from the wire')
    parser.add_argument('--code', required=True, help='OVMF_CODE.fd')
    parser.add_argument('--vars', required=True, help='pristine OVMF_VARS.fd')
    parser.add_argument('--serve-file', default='', help='boot file to hand out')
    parser.add_argument('--out', default='net_fuzz_out')
    parser.add_argument('--seed-dir', default='', help='inputs to start from')
    parser.add_argument('--iterations', type=int, default=10)
    parser.add_argument('--mutate', type=int, default=4)
    parser.add_argument('--mutate-labels', default='DATA',
                        help='which replies to corrupt: OFFER, ACK, OACK, DATA. '
                             'DATA is the default because corrupting the negotiation '
                             'ends the transfer before any parser runs')
    parser.add_argument('--skip-packets', type=int, default=0,
                        help='leave the first N replies alone. 2 keeps the DHCP exchange '
                             'intact so the run reaches TFTP and the loader')
    parser.add_argument('--seed-size', type=int, default=64)
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--accept-timeout', type=float, default=45)
    parser.add_argument('--base-port', type=int, default=5600)
    parser.add_argument('--memory', default='2048')
    parser.add_argument('--client-mac', default='52:54:00:12:34:56')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--rng-seed', type=int, default=0)
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    findings = os.path.join(args.out, 'findings')
    os.makedirs(findings, exist_ok=True)
    work = os.path.join(args.out, 'work')
    os.makedirs(work, exist_ok=True)

    seeds = []
    if args.seed_dir and os.path.isdir(args.seed_dir):
        for name in sorted(os.listdir(args.seed_dir)):
            path = os.path.join(args.seed_dir, name)
            if os.path.isfile(path):
                with open(path, 'rb') as handle:
                    seeds.append(handle.read())
    rng = random.Random(args.rng_seed)
    if not seeds:
        seeds = [bytes(rng.randrange(256) for _ in range(args.seed_size))]

    # An uncorrupted run first: whatever it reports is what this firmware always
    # reports, and only sites beyond that set count as a finding.
    baseline_seed = os.path.join(work, 'baseline')
    with open(baseline_seed, 'wb') as handle:
        handle.write(b'\x00' * args.seed_size)
    saved_mutate, args.mutate = args.mutate, 0
    print('taking a baseline with no mutations ...')
    (_, _), _, base_debug, base_serial = run_once(args, baseline_seed, 999, work)
    args.mutate = saved_mutate
    baseline = report_sites(base_serial)
    print(f'baseline: {len(baseline)} reporting site(s) on a clean boot')
    if 'Exception Type' in base_debug:
        print('warning: the clean boot already faults; findings below are not trustworthy')

    tally = {}
    print(f'{args.iterations} iteration(s), {args.mutate} mutation(s) per reply, '
          f'targeting {args.mutate_labels or "every reply"}')
    for index in range(args.iterations):
        data = bytearray(rng.choice(seeds))
        if not data:
            data = bytearray(rng.randrange(256) for _ in range(args.seed_size))
        for _ in range(rng.randrange(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        digest = hashlib.sha256(bytes(data)).hexdigest()[:12]
        seed_path = os.path.join(work, f'seed_{digest}')
        with open(seed_path, 'wb') as handle:
            handle.write(bytes(data))

        (outcome, detail), peer_text, debug_text, serial_text = \
            run_once(args, seed_path, index, work, baseline)
        tally[outcome] = tally.get(outcome, 0) + 1
        print(f'  [{index + 1}/{args.iterations}] {digest} -> {outcome}: {detail}')

        if outcome in ('exception', 'asan', 'hang'):
            keep = os.path.join(findings, f'{outcome}_{digest}')
            os.makedirs(keep, exist_ok=True)
            shutil.copyfile(seed_path, os.path.join(keep, 'input'))
            for name, text in (('peer.log', peer_text), ('debug.log', debug_text),
                               ('serial.log', serial_text)):
                with open(os.path.join(keep, name), 'w') as handle:
                    handle.write(text)
            seeds.append(bytes(data))

    print('\n--- outcomes ---')
    for name in sorted(tally):
        print(f'  {name:10} {tally[name]}')
    kept = len(os.listdir(findings))
    print(f'kept {kept} input(s) under {findings}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
