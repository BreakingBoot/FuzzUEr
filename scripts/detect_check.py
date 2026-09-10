"""Does the pipeline still detect what it used to detect?

verify_all.sh proves the tree analyses, generates, builds and runs. None of that says a
memory error would still be reported: the shadow can go unmapped, the runtime can
deactivate itself for want of a HOB, the report can be gated shut, and every one of those
failures looks exactly like a clean campaign. Three separate times a change made the
firmware silent and the campaign still looked healthy.

So this asserts on findings, not on exit codes. Each check states what it expects, runs
it, and says PASS or FAIL with the evidence.

  python3 scripts/detect_check.py --code OVMF_CODE.fd --vars OVMF_VARS.fd \\
      --selftest AsanSelfTest.efi --matrix <dir> --known results/known-bugs.json

Any check whose inputs are not given is skipped and reported as such, so a partial run
never reads as a pass.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# What a working AsanSelfTest boot prints. The control case matters as much as the rest:
# a runtime that reports everything is as broken as one that reports nothing.
SELFTEST_EXPECT = [
    ('heap-buffer-overflow', 'expect heap-buffer-overflow'),
    ('heap-buffer-underflow', 'expect heap-buffer-underflow'),
    ('use-after-free', 'expect use-after-free'),
    ('double-free', 'expect double-free'),
]


def read(path):
    try:
        with open(path, 'rb') as handle:
            return handle.read().decode('utf-8', errors='replace').replace('\r', '')
    except OSError:
        return ''


def boot(args, work, extra=None, serve=None, peer_port=0):
    """Boot the firmware once and hand back what it said."""
    debug = os.path.join(work, 'debug.log')
    serial = os.path.join(work, 'serial.log')
    varsfd = os.path.join(work, 'vars.fd')
    shutil.copyfile(args.vars, varsfd)
    peer = None
    peer_log = os.path.join(work, 'peer.log')
    if peer_port:
        cmd = [sys.executable, os.path.join(HERE, 'net_peer.py'), '--port', str(peer_port),
               '--duration', str(args.timeout), '--accept-timeout', str(args.timeout),
               '--quiet']
        if serve:
            cmd += ['--serve-file', serve]
        peer = subprocess.Popen(cmd, stdout=open(peer_log, 'w'),
                                stderr=subprocess.STDOUT)
        time.sleep(0.5)

    qemu = [args.qemu, '-machine', 'q35', '-m', '2048', '-no-reboot', '-smp', '1',
            '-fw_cfg', 'name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes',
            '-debugcon', f'file:{debug}', '-global', 'isa-debugcon.iobase=0x402',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={args.code}',
            '-drive', f'if=pflash,format=raw,unit=1,file={varsfd}',
            '-display', 'none', '-serial', f'file:{serial}']
    qemu += extra or []
    try:
        subprocess.run(qemu, timeout=args.timeout + 25,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    if peer:
        try:
            peer.send_signal(signal.SIGINT)
            peer.wait(timeout=15)
        except Exception:
            peer.kill()
    return read(debug), read(serial), read(peer_log)


def check_selftest(args, work):
    """Every deliberate error is reported and the correct one is not."""
    esp = os.path.join(work, 'esp')
    os.makedirs(os.path.join(esp, 'EFI', 'BOOT'), exist_ok=True)
    shutil.copyfile(args.selftest, os.path.join(esp, 'EFI', 'BOOT', 'BOOTX64.EFI'))
    debug, serial, _ = boot(args, work,
                            extra=['-drive', f'file=fat:rw:{esp},format=raw,if=ide'])
    if 'AsanSelfTest' not in debug:
        return False, 'the self test never ran -- the guest did not boot it'
    missing = [name for name, marker in SELFTEST_EXPECT if marker not in debug]
    if missing:
        return False, f'never reached: {", ".join(missing)}'
    # the control must be silent: it announces itself, then nothing may be reported for it
    if 'control, expect NO report' not in debug:
        return False, 'the control case did not run, so a silent runtime would pass'
    found = []
    if 'double free' in serial.lower():
        found.append('double-free')
    stores = serial.count('__asan_store')
    if stores < 3:
        return False, (f'only {stores} __asan_store report(s); overflow, underflow and '
                       f'use-after-free should each produce one')
    found.append(f'{stores} store reports')
    if 'double-free' not in found:
        return False, 'the double free was not reported'
    return True, ' + '.join(found)


def check_network(args, work):
    """The peer completes a PXE boot and the guest runs what it is handed."""
    debug, _, peer = boot(args, work, serve=args.selftest, peer_port=args.peer_port,
                          extra=['-netdev',
                                 f'socket,id=n0,connect=127.0.0.1:{args.peer_port}',
                                 '-device',
                                 'virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56'])
    if 'transfers completed: 1' not in peer:
        tail = [line for line in peer.splitlines() if line.startswith(('frames', 'tftp'))]
        return False, f'the TFTP transfer did not complete ({"; ".join(tail) or "no peer output"})'
    if 'AsanSelfTest' not in debug:
        return False, 'the image was fetched but never executed'
    return True, 'DHCP, ARP, TFTP transfer complete, image executed'


def check_triage(args):
    """The clustering filter still separates the harness from the firmware."""
    out = os.path.join(tempfile.mkdtemp(), 'bugs.json')
    result = subprocess.run(
        [sys.executable, os.path.join(HERE, 'bug_report.py'), '-r', args.matrix,
         '--json', out] + (['--known', args.known] if args.known else []),
        capture_output=True, text=True)
    if result.returncode != 0:
        return False, result.stderr.strip()[:200] or 'bug_report.py failed'
    with open(out) as handle:
        payload = json.load(handle)
    harness = len(payload['filtered']['harness'])
    if harness == 0:
        return False, ('nothing was filtered as the harness, which means the Module '
                       'column stopped being populated or the filter stopped matching')
    if not payload['candidates'] and not payload['ubiquitous']:
        return False, 'no findings at all, which is not what this corpus contains'
    new = [line for line in result.stdout.splitlines() if '[NEW]' in line]
    detail = (f"{payload['clusters']} clusters from {payload['rows']} rows, "
              f"{harness} filtered as harness, {len(payload['candidates'])} candidates")
    if args.known and new:
        return False, detail + f'; {len(new)} cluster(s) not in the known set'
    return True, detail + ('; none new against the known set' if args.known else '')


def main():
    parser = argparse.ArgumentParser(description='Assert the pipeline still finds things')
    parser.add_argument('--code', help='OVMF_CODE.fd built with ASan')
    parser.add_argument('--vars', help='pristine OVMF_VARS.fd')
    parser.add_argument('--selftest', help='AsanSelfTest.efi')
    parser.add_argument('--matrix', help='a campaign directory for the triage check')
    parser.add_argument('--known', default='', help='known-bugs.json to diff against')
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--peer-port', type=int, default=5900)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--skip-network', action='store_true')
    args = parser.parse_args()

    work = tempfile.mkdtemp(prefix='detect_check_')
    results = []

    firmware_ready = all([args.code, args.vars, args.selftest]) and \
        all(os.path.isfile(p) for p in (args.code or '', args.vars or '',
                                        args.selftest or ''))
    if firmware_ready:
        results.append(('asan detection classes',) + check_selftest(args, work))
        if not args.skip_network:
            netwd = os.path.join(work, 'net')
            os.makedirs(netwd, exist_ok=True)
            results.append(('network peer pxe boot',) + check_network(args, netwd))
    else:
        results.append(('asan detection classes', None,
                        'skipped: needs --code, --vars and --selftest'))
        if not args.skip_network:
            results.append(('network peer pxe boot', None, 'skipped: needs the same'))

    if args.matrix and os.path.isdir(args.matrix):
        results.append(('bug triage',) + check_triage(args))
    else:
        results.append(('bug triage', None, 'skipped: needs --matrix'))

    print()
    failed = skipped = 0
    for name, ok, detail in results:
        if ok is None:
            state, skipped = 'SKIP', skipped + 1
        elif ok:
            state = 'PASS'
        else:
            state, failed = 'FAIL', failed + 1
        print(f'  [{state}] {name:26} {detail}')
    print()
    if failed:
        print(f'{failed} check(s) failed')
    elif skipped:
        print(f'all run checks passed, {skipped} skipped -- not a full pass')
    else:
        print('all checks passed')
    shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
