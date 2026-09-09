import argparse
import os
import re
import subprocess
import sys
import time


# Drive a Linux guest over its serial console and collect the output of a script.
#
# The alternative is mounting the disk image to drop in a systemd unit, which needs
# loop devices or libguestfs and a privileged container. Talking to the console needs
# neither, and it is also how a person would check the same thing by hand.
PROMPT = re.compile(rb'root@[^:]*:[^#]*# $')


def read_until(process, pattern, timeout, log):
    """Read until pattern matches, returning everything seen."""
    deadline = time.time() + timeout
    seen = bytearray()
    while time.time() < deadline:
        try:
            chunk = os.read(process.stdout.fileno(), 4096)
        except BlockingIOError:
            # non-blocking with nothing ready yet, which is most of a boot
            time.sleep(0.05)
            continue
        if not chunk:
            time.sleep(0.05)
            continue
        seen += chunk
        log.write(chunk)
        log.flush()
        if pattern.search(bytes(seen)):
            return bytes(seen), True
    return bytes(seen), False


def main():
    parser = argparse.ArgumentParser(
        description='Boot a Linux guest and run a script on its serial console')
    parser.add_argument('--code', required=True, help='OVMF_CODE.fd')
    parser.add_argument('--vars', required=True, help='writable OVMF_VARS copy')
    parser.add_argument('--disk', required=True, help='guest disk, qcow2')
    parser.add_argument('--extra-disk', help='second disk, exposed as /dev/vdb')
    parser.add_argument('--script', required=True, help='shell to run once logged in')
    parser.add_argument('--user', default='root')
    parser.add_argument('--boot-timeout', type=int, default=420)
    parser.add_argument('--run-timeout', type=int, default=600)
    parser.add_argument('--log', default='guest.log')
    parser.add_argument('--network', action='store_true',
                        help='give the guest user-mode networking')
    args = parser.parse_args()

    command = [
        'qemu-system-x86_64', '-machine', 'q35,smm=on', '-m', '2048',
        '-no-reboot', '-smp', '1',
        # OVMF asserts against QEMU 6.2 without this, and X64 + SMM needs S3 off
        '-fw_cfg', 'name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes',
        '-global', 'ICH9-LPC.disable_s3=1',
        '-global', 'driver=cfi.pflash01,property=secure,value=on',
        '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={args.code}',
        '-drive', f'if=pflash,format=raw,unit=1,file={args.vars}',
        '-drive', f'file={args.disk},format=qcow2,if=virtio',
        '-display', 'none', '-serial', 'mon:stdio',
    ]
    if args.extra_disk:
        command += ['-drive', f'file={args.extra_disk},format=raw,if=virtio']
    command += ['-nic', 'user'] if args.network else ['-nic', 'none']

    with open(args.log, 'wb') as log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        os.set_blocking(process.stdout.fileno(), False)

        _, ok = read_until(process, re.compile(rb'login: $'), args.boot_timeout, log)
        if not ok:
            print('guest never reached a login prompt', file=sys.stderr)
            process.kill()
            return 1
        process.stdin.write(args.user.encode() + b'\n')
        process.stdin.flush()

        _, ok = read_until(process, PROMPT, 120, log)
        if not ok:
            print('logged in but never saw a shell prompt', file=sys.stderr)
            process.kill()
            return 1

        # a sentinel rather than the prompt: the script's own output can contain
        # anything, including something that looks like a prompt
        with open(args.script) as handle:
            body = handle.read()
        process.stdin.write(body.encode() + b'\necho __FIRNESS_DONE__\n')
        process.stdin.flush()
        output, ok = read_until(process, re.compile(rb'__FIRNESS_DONE__'),
                                args.run_timeout, log)
        process.stdin.write(b'\npoweroff -f\n')
        process.stdin.flush()
        time.sleep(5)
        process.kill()

    sys.stdout.write(output.decode('utf-8', errors='replace'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
