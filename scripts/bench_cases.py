"""Score every benchmark class, one boot per class.

The exerciser can run all its cases in a single boot and that is the cheap measurement,
but two of the cases are destructive by construction -- a double free takes the pool free
list with it, and a wrapped size allocates a few bytes and writes hundreds into them --
so everything after the first of them is measuring wreckage rather than the sanitizer.
In practice the sequence stops at double-free and the last two classes never score at
all, which reads as "not detected" when the truth is "not attempted".

So this boots once per class, selecting the class over fw_cfg, and scores each boot on
its own. Twelve boots is a few minutes and it is the difference between a scoreboard and
an anecdote.

  python3 scripts/bench_cases.py --code OVMF_CODE.fd --vars OVMF_VARS.fd \\
      --app SanBenchDrive.efi --out bench-cases

Run it where qemu and the OVMF roms are -- inside the campaign image -- or pass --qemu
and --roms. A class the firmware never installed reports as UNBUILT rather than a
failure, because a build without -D SAN_BENCH cannot say anything about detection.
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys

# Every class the benchmark implements, with what a detection looks like. The second
# element is the substring a report must contain: 'asan' means any ASan report will do
# (the class is a read or write through poisoned shadow and which of the load/store
# reports fires is an implementation detail), while a named class has to report itself.
#
# A class marked unreachable is one the firmware cannot exercise in this phase at all.
# It is kept in the table on purpose: dropping it would quietly shrink the denominator,
# and a benchmark that hides its own gaps is worth less than one that names them.
CASES = [
    ('control',                 None,                       'no report at all'),
    ('heap-buffer-overflow',    'heap-buffer-overflow',      None),
    ('heap-buffer-underflow',   'asan',                      None),
    ('tlv-overread',            'asan',                      None),
    ('foreign-pointer',         'foreign-region',            None),
    ('double-fetch',            'double-fetch',              None),
    ('stale-interface',         'asan',                      None),
    ('boot-service-after-exit', None,                        'needs the runtime phase'),
    ('variable-size-trusted',   'asan',                      None),
    ('use-after-free',          'asan',                      None),
    ('double-free',             'double-free',               None),
    ('size-overflow',           'asan',                      None),
]

# A line that is a sanitizer saying something, as opposed to the exerciser narrating.
# Both arrive on the same wire, which is what makes a report attributable to a case.
REPORT = re.compile(
    r'(ERROR: AddressSanitizer|FWSAN:|heap-buffer-overflow|heap-buffer-underflow|'
    r'use-after-free|double-free|stale-protocol-interface|asan-(load|store)|'
    r'CPU Exception|runtime error)', re.I)

NARRATION = 'SanBenchDrive:'


def read(path):
    try:
        with open(path, 'rb') as handle:
            return handle.read().decode('utf-8', errors='replace').replace('\r', '')
    except OSError:
        return ''


def boot(args, case, work):
    """Boot once with one case selected. Returns (serial, debug)."""
    os.makedirs(os.path.join(work, 'esp', 'EFI', 'BOOT'), exist_ok=True)
    shutil.copyfile(args.app, os.path.join(work, 'esp', 'EFI', 'BOOT', 'BOOTX64.EFI'))
    varsfd = os.path.join(work, 'vars.fd')
    shutil.copyfile(args.vars, varsfd)
    serial = os.path.join(work, 'serial.log')
    debug = os.path.join(work, 'debug.log')

    cmd = [
        args.qemu, '-machine', 'q35', '-m', '2048', '-no-reboot', '-smp', '1',
        # The bugcheck override is what keeps a single-CPU boot from stopping on the
        # CPU hotplug check; without it the firmware never reaches BDS.
        '-fw_cfg', 'name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes',
        '-fw_cfg', 'name=opt/sanbench/case,string=%s' % case,
        '-debugcon', 'file:%s' % debug, '-global', 'isa-debugcon.iobase=0x402',
        '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=%s' % args.code,
        '-drive', 'if=pflash,format=raw,unit=1,file=%s' % varsfd,
        '-drive', 'file=fat:rw:%s,format=raw,if=ide' % os.path.join(work, 'esp'),
        '-display', 'none', '-serial', 'file:%s' % serial,
    ]
    if args.roms:
        cmd += ['-L', args.roms]

    try:
        subprocess.run(cmd, timeout=args.timeout, stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        # Not a failure by itself. A destructive case can leave the firmware unable to
        # reach the end of the application, and the report it already emitted still
        # counts -- which is exactly why the scoring reads the log rather than the
        # exit status.
        pass
    return read(serial), read(debug)


def score_one(args, case, expect, unreachable, work):
    serial, debug = boot(args, case, work)

    if 'no memory protocol' in serial or 'no memory protocol' in debug:
        return dict(case=case, verdict='UNBUILT', detail='built without -D SAN_BENCH',
                    reports=[])
    if NARRATION not in serial:
        return dict(case=case, verdict='NO BOOT',
                    detail='the exerciser never announced itself', reports=[])

    # Only what was said after this case announced itself. With one case per boot there
    # is nothing else on the wire, but a stray report from firmware start-up would
    # otherwise be credited to the case.
    after = serial
    marker = 'expect %s' % case
    if marker in serial:
        after = serial[serial.index(marker):]
    elif case == 'control':
        after = serial[serial.index('control'):] if 'control' in serial else serial

    reports = [line.strip() for line in after.splitlines()
               if REPORT.search(line) and NARRATION not in line]

    if case == 'control':
        if reports:
            return dict(case=case, verdict='FAIL',
                        detail='reported on correct code -- every other result is worth less',
                        reports=reports[:4])
        return dict(case=case, verdict='PASS', detail='silent, as it should be', reports=[])

    if unreachable:
        attempted = 'not attempted' in after
        return dict(case=case, verdict='N/A',
                    detail=unreachable if attempted else
                    '%s (but the case ran anyway -- check it)' % unreachable,
                    reports=reports[:4])

    if not reports:
        return dict(case=case, verdict='MISS', detail='no report', reports=[])

    if expect == 'asan':
        return dict(case=case, verdict='PASS', detail=reports[0][:90], reports=reports[:4])

    for line in reports:
        if expect.lower() in line.lower():
            return dict(case=case, verdict='PASS', detail=line[:90], reports=reports[:4])

    return dict(case=case, verdict='WRONG',
                detail='reported, but not as %s: %s' % (expect, reports[0][:70]),
                reports=reports[:4])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--code', required=True, help='OVMF_CODE.fd built with -D SAN_BENCH')
    parser.add_argument('--vars', required=True, help='OVMF_VARS.fd')
    parser.add_argument('--app', required=True, help='SanBenchDrive.efi')
    parser.add_argument('--out', default='bench-cases', help='where the per-case logs land')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--roms', default='', help='-L path for the OVMF roms')
    parser.add_argument('--timeout', type=int, default=150)
    parser.add_argument('--jobs', type=int, default=3,
                        help='boots at once. Each is a whole firmware boot, so more than '
                             'a few contend and a contended boot times out before BDS')
    parser.add_argument('--case', action='append', default=[],
                        help='score only this case (repeatable)')
    args = parser.parse_args()

    for attr in ('code', 'vars', 'app'):
        path = getattr(args, attr)
        if not os.path.isfile(path):
            sys.exit('no such file: %s' % path)
        setattr(args, attr, os.path.abspath(path))
    args.out = os.path.abspath(args.out)

    wanted = [c for c in CASES if not args.case or c[0] in args.case]
    if not wanted:
        sys.exit('no case matched %s' % ', '.join(args.case))

    os.makedirs(args.out, exist_ok=True)
    print('Scoring %d case(s), one boot each, %d at a time' % (len(wanted), args.jobs))

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for case, expect, unreachable in wanted:
            work = os.path.join(args.out, case)
            os.makedirs(work, exist_ok=True)
            futures[pool.submit(score_one, args, case, expect, unreachable, work)] = case
        for future in concurrent.futures.as_completed(futures):
            case = futures[future]
            try:
                results[case] = future.result()
            except Exception as exc:                      # a boot that died oddly
                results[case] = dict(case=case, verdict='ERROR', detail=str(exc)[:90],
                                     reports=[])
            print('  %-24s %s' % (case, results[case]['verdict']))

    print()
    print('%-24s %-8s %s' % ('CASE', 'VERDICT', 'EVIDENCE'))
    print('-' * 100)
    scored = detected = 0
    for case, _expect, _unreachable in wanted:
        row = results[case]
        print('%-24s %-8s %s' % (case, row['verdict'], row['detail']))
        if row['verdict'] in ('PASS', 'MISS', 'WRONG'):
            scored += 1
            if row['verdict'] == 'PASS':
                detected += 1

    print('-' * 100)
    print('%d of %d scorable classes detected' % (detected, scored))
    skipped = [r['case'] for r in results.values() if r['verdict'] in ('N/A', 'UNBUILT')]
    if skipped:
        print('not scorable here: %s' % ', '.join(sorted(skipped)))
    print('logs under %s' % args.out)

    # A control that reports, or a boot that never happened, invalidates the run rather
    # than costing it a point -- so those fail the exit status while a MISS does not.
    broken = [r for r in results.values()
              if r['verdict'] in ('FAIL', 'NO BOOT', 'ERROR')]
    return 1 if broken else 0


if __name__ == '__main__':
    sys.exit(main())
