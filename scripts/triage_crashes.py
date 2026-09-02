import os
import csv
import sys
import argparse
from collections import defaultdict


# Which sanitizer reports are actually worth looking at.
#
# firness.py splits reports at the line where DXE dispatches Firness.efi: everything after
# it is labelled "fuzz". That is too generous. The firmware keeps doing its own work after
# the harness loads -- the S3 boot script save, variable writes, timer callbacks -- and
# those reports land in the fuzz phase of every campaign no matter which protocol ran.
#
# The tell is that they are identical across unrelated protocols. A report at
# BootScriptSave.c:144 that appears in EfiShell, EfiTcp4, EfiUdp4 and EfiAcpiSdt alike is
# firmware background, while one that appears under a single protocol is a candidate that
# the harness's own inputs provoked.
def read_crashes(path, phase):
    sites = {}
    try:
        with open(path, newline='') as handle:
            for row in csv.DictReader(handle):
                if (row.get('Phase') or '').strip() != phase:
                    continue
                key = (row.get('File') or '', row.get('Line') or '', row.get('Asan Msg') or '')
                try:
                    count = int(row.get('Count') or 0)
                except ValueError:
                    count = 0
                sites[key] = sites.get(key, 0) + count
    except OSError:
        return {}
    return sites


def collect(root):
    per_protocol, boot_sites = {}, set()
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, 'crashes.csv')
        if os.path.isfile(path):
            per_protocol[name] = read_crashes(path, 'fuzz')
            # a site the firmware reaches during boot, with no input in play, is background
            # wherever it turns up later
            boot_sites |= set(read_crashes(path, 'boot'))
    return per_protocol, boot_sites


def main():
    parser = argparse.ArgumentParser(
        description='Separate protocol-specific sanitizer findings from firmware background')
    parser.add_argument('-r', '--root', required=True,
                        help='Directory holding one subdirectory per protocol')
    parser.add_argument('--shared-at', type=int, default=3,
                        help='A site seen in this many protocols or more is background '
                             '(default 3)')
    parser.add_argument('-o', '--output', default='', help='Optional csv of the candidates')
    args = parser.parse_args()

    per_protocol, boot_sites = collect(args.root)
    if not per_protocol:
        print(f'No crashes.csv under {args.root}')
        return 1

    seen_in = defaultdict(set)
    for protocol, sites in per_protocol.items():
        for key in sites:
            seen_in[key].add(protocol)

    background = {k for k, v in seen_in.items()
                  if len(v) >= args.shared_at or k in boot_sites}
    candidates = {k: v for k, v in seen_in.items() if k not in background}

    ran = [p for p, s in per_protocol.items() if s]
    print(f'{len(per_protocol)} protocol(s) with a crash table, {len(ran)} with fuzz-phase '
          f'reports')
    print(f'background ({len(boot_sites)} boot site(s) plus anything seen in '
          f'>= {args.shared_at} protocols): {len(background)} site(s)')
    for key in sorted(background)[:6]:
        print(f'  {os.path.basename(key[0])}:{key[1]} {key[2]}')
    if len(background) > 6:
        print(f'  ... and {len(background) - 6} more')

    print(f'\ncandidates (protocol-specific): {len(candidates)} site(s)')
    rows = []
    for key, protocols in sorted(candidates.items(), key=lambda kv: sorted(kv[1])):
        who = ', '.join(sorted(protocols))
        hits = sum(per_protocol[p].get(key, 0) for p in protocols)
        print(f'  {who:22} {os.path.basename(key[0])}:{key[1]} {key[2]} x{hits}')
        rows.append({'protocols': who, 'file': key[0], 'line': key[1],
                     'report': key[2], 'count': hits})
    if not candidates:
        print('  (none -- every fuzz-phase report is firmware background)')

    if args.output and rows:
        with open(args.output, 'w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f'\nWrote {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
