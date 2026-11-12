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
    # Names the class rather than accepting any sanitizer line. FwSanDxe prints
    # "FWSAN: interface uninstalled, storage poisoned" on every SUCCESSFUL poison, which
    # satisfied a bare 'asan' expectation -- the recorded scoreboard in
    # results/bench-final/ scores this row PASS against exactly that status line, so the
    # case could not fail. The real detection is a load through the poisoned interface.
    ('stale-interface',         'stale-protocol-interface',  None),
    ('boot-service-after-exit', None,                        'needs the runtime phase'),
    ('variable-size-trusted',   'asan',                      None),
    ('use-after-free',          'asan',                      None),
    # The only case whose verdict depends on stack instrumentation being on. The compiler
    # writes a frame's redzones inline, so this reports only when SanBenchDxe was built
    # WITHOUT -mllvm -asan-stack=0 -- and every other case here passes either way, so a
    # green board without this row says nothing about the stack at all.
    ('stack-buffer-overflow',   'asan',                      None),
    ('double-free',             'double-free',               None),
    ('size-overflow',           'asan',                      None),
    # The SMM classes. These are not protocol calls: SanBenchDrive raises a software SMI
    # through EFI_SMM_COMMUNICATION_PROTOCOL and the fault happens inside SMRAM, in
    # SanBenchSmm's own instrumented statements, on SMM pool and SMM page allocations.
    # Nothing above this line can measure that -- every SMM finding on record so far came
    # from an instrumented LIBRARY linked into an SMM image, never from an SMM driver's
    # own code, and these rows are what tells those two apart.
    #
    # Each names its class rather than accepting a bare 'asan'. A bare expectation is
    # what let 'stale-interface' score PASS off a status line, and in SMM it would be
    # worse: the firmware raises reports from inside SMRAM for other reasons, so "any
    # sanitizer line after the marker" is not evidence about THIS class.
    ('smm-control',             None,                        None),
    ('smm-pool-overflow',       'heap-buffer-overflow',      None),
    ('smm-pool-use-after-free', 'heap-use-after-free',       None),
    ('smm-page-use-after-free', 'heap-use-after-free',       None),
    ('smm-double-free',         'double-free',               None),
]

# Of the SMM rows, the three whose report must be attributed to SanBenchSmm's OWN image.
#
# An ASan report names no module: it says "in file: asan-outline-instrumentation" and
# carries an ip. So for these three the class alone is not the result -- a
# heap-buffer-overflow raised by a memory wrapper linked into the module is exactly the
# result already on record, and scoring it here would claim something that had not been
# shown. The module publishes its own base and size on the same wire and the ip has to
# fall inside it.
#
# 'smm-double-free' is deliberately NOT in this set. That class is detected by the
# allocator, in PiSmmCore/Pool.c, which is where the quarantine signature is read: the
# faulting caller is SanBenchSmm but the report is the SMM core's own and carries no ip
# at all. Requiring an ip inside SanBenchSmm would fail a correct detection.
SMM_OWN_CODE = {
    'smm-pool-overflow',
    'smm-pool-use-after-free',
    'smm-page-use-after-free',
}

# "SanBenchSmm: image base=0x0000000000000000 size=0x0000000000000000", printed by the
# module at registration. Num2Str64bit emits 0x plus 16 uppercase hex digits.
SMM_IMAGE_RE = re.compile(
    r'SanBenchSmm: image base=(0x[0-9A-Fa-f]+) size=(0x[0-9A-Fa-f]+)')

# The ip an ASan report carries, which is the only thing in it that identifies code.
#
# Two spellings, because AsanEmitReport prints the ip twice and only one of the two lines
# survives the report filter. The "address ..., size ..., ip ..." line names no class, so
# REPORT does not match it and it is not in `reports` at all -- attributing from `ip`
# alone found nothing and scored a correct detection as FOREIGN. The bug_descr line
# carries the same ip where a line number would go, which also ties the ip to the class
# on the very same line rather than to whichever report happened to be adjacent.
IP_RE = re.compile(r'(?:\bip|at line:) (0x[0-9A-Fa-f]+)')

# A line that is a sanitizer saying something, as opposed to the exerciser narrating.
# Both arrive on the same wire, which is what makes a report attributable to a case.
# The underscore form is the one that matters and it was missing. DEFINE_ASAN_LOAD in
# AsanLib prints "__asan_load0x02" -- underscore, no class name, no "ERROR:
# AddressSanitizer" banner -- because the named-class reporter lives on a different path.
# Matching only the hyphenated "asan-load" scored two real detections as MISS and left the
# sanitizer looking blind to sub-granule overreads, which it is not.
#
# "ASAN MEMORY ACCESS check fail" is deliberately NOT an alternative here: __ubsan_handle_*
# shares that prefix, so it would credit every boot's HII UB to whatever case was running.
#
# The class names are matched as a family rather than listed heap-first. Only the heap ones
# were here, so a real stack detection scored MISS: the sanitizer said
# "bug_descr=stack-buffer-overflow in file: .../CopyMemWrapper.c" and nothing in this
# pattern could see it, which left the one case that answers "is stack instrumentation
# actually on" permanently unscorable. The exerciser's own "expect <case>" line also names
# a class, and the NARRATION filter at the call site is what keeps that from scoring itself.
REPORT = re.compile(
    r'(ERROR: AddressSanitizer|'
    # FWSAN lines come in two kinds on the same wire. A report names a class and
    # separates it with " -- " ("FWSAN: double-fetch -- untrusted word read
    # twice"); the two informational ones do not ("firmware sanitizer armed",
    # "interface uninstalled, storage poisoned"). Requiring the separator is what
    # keeps a setup message from scoring as a detection.
    r'FWSAN: [a-z][a-z-]* [a-z ]*-- |'
    r'(heap|stack|global|container|intra-object)[a-z-]*-(overflow|underflow)|'
    r'use-after-free|use-after-return|use-after-scope|double-free|'
    r'stale-protocol-interface|asan[-_](load|store)|'
    r'__asan_report|CPU Exception|runtime error)', re.I)

# Lines the exerciser and the SMM module say about themselves. A tuple rather than one
# string because both ends narrate now, and a narration line that reaches the report
# filter is a case scoring itself: this file has been bitten by that twice, once by a case
# named after its own class and once by a status line that read as a detection.
NARRATION = ('SanBenchDrive:', 'SanBenchSmm:')


def is_narration(line):
    return any(prefix in line for prefix in NARRATION)


# What counts as a measurement, and what is exempt from being one.
#
# NOT RUN, FOREIGN and NO MAP are non-detections: the class COULD have been demonstrated
# on this image and was not. Leaving any of them out would print "n of n" for a board
# where a class was never shown, which is the shape this file exists to avoid.
#
# N/A, UNBUILT and NO SMM are exemptions: the image cannot run the case at all. They are
# listed under "not scorable here" instead of entering the total, because fuzz_edk2.py
# fails the detects stage on any shortfall in that total -- so a class the build was
# never configured to run must not be in the denominator.
#
# FAIL, NO BOOT and ERROR are non-detections too, and they were in NEITHER list. A verdict
# in neither one is dropped from both counts, so the board shrinks and still reads "n of n"
# -- the stage passes. For FAIL that is the worst case of all: FAIL is a CONTROL that
# reported, i.e. the sanitizer firing on code that does nothing wrong, and a board that
# hides it is worse than no board. Measured before the fix: a control reporting printed
# "16 of 16" and the detects stage PASSED.
SCORED = ('PASS', 'MISS', 'WRONG', 'NOT RUN', 'FOREIGN', 'NO MAP',
          'FAIL', 'NO BOOT', 'ERROR')
EXEMPT = ('N/A', 'UNBUILT', 'NO SMM')


def graded_line(detected, scored):
    """The one line fuzz_edk2.py grades.

    A function rather than a format string inlined at the print, so the wording and the
    numbers can be exercised as a unit: that script selects this line by the substring
    'scorable classes detected' and then fails the detects stage unless the two numbers
    "(\\d+) of (\\d+)" in it agree.
    """
    return '%d of %d scorable classes detected' % (detected, scored)


def tally(results, wanted):
    """(detected, scored, exempt cases) over the rows that were asked for.

    Split out of main() so the accounting itself can be exercised. What matters is not
    what this file prints but what fuzz_edk2.py's "(\\d+) of (\\d+)" grep makes of it,
    and an assertion that re-implemented the sums would not be testing them.
    """
    detected = scored = 0
    exempt = []
    for case, _expect, _unreachable in wanted:
        verdict = results[case]['verdict']
        if verdict in SCORED:
            scored += 1
            if verdict == 'PASS':
                detected += 1
        elif verdict in EXEMPT:
            exempt.append(case)
    return detected, scored, sorted(exempt)


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

    # SMM on by default, because the SMM rows cannot be measured without it and a run
    # that forgets the flag scores them exempt -- a control that is built, shipped and
    # never fired, which is the failure this file exists to prevent.
    #
    # Off by default all the same. The three settings are the ones guest_run.py and
    # detect_check.py use for an SMM image, and an SMM_REQUIRE OVMF does not boot
    # without the secure pflash property -- but that property also makes the varstore
    # writable only from SMM, and whether a non-SMM image still boots that way has NOT
    # been measured here. Defaulting it on would put that untested change on the
    # pipeline's existing green path, where it buys nothing: on a non-SMM image the
    # smm-* rows are exempt with or without the flag. So the default is the command line
    # that is known to work, and measuring the SMM rows is one explicit flag away.
    machine = 'q35,smm=on' if args.smm else 'q35'
    cmd = [
        args.qemu, '-machine', machine, '-m', '2048', '-no-reboot', '-smp', '1',
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
    if args.smm:
        # disable_s3 keeps the SMM build off the S3 path it has no LockBox for, and the
        # secure pflash property is what an SMM_REQUIRE OVMF requires of its varstore.
        cmd += ['-global', 'ICH9-LPC.disable_s3=1',
                '-global', 'driver=cfi.pflash01,property=secure,value=on']
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


# The low byte of the EFI_STATUS SanBenchDrive prints when Communicate() fails. These
# are four different failures and this row used to call all of them "it reached no
# handler" -- which named the one cause that was NOT happening. The real one for the
# whole life of the smm-* rows was 0F: the core rejecting a comm buffer that was not
# inside the published communication region, long before SmiManage ran.
SMI_REFUSAL = {
    '02': 'EFI_INVALID_PARAMETER -- the core would not call SmiManage',
    '03': 'EFI_UNSUPPORTED -- the software SMI never triggered',
    '04': 'EFI_BAD_BUFFER_SIZE -- the payload is larger than SMM accepts',
    '0E': 'EFI_NOT_FOUND -- SmiManage has no handler for that GUID',
    '0F': 'EFI_ACCESS_DENIED -- the core refused the communication buffer',
}


def smi_refusal(after):
    """Why SanBenchDrive said the SMI was not attempted, in the driver's own words."""
    if 'no SMM communication protocol' in after:
        return 'no communication protocol'
    if 'no SMM communication region' in after:
        return 'the firmware published no SMM communication region to raise it from'
    code = re.search(r'the SMI was not delivered, status=([0-9A-Fa-f]{2})', after)
    if code:
        digits = code.group(1).upper()
        return SMI_REFUSAL.get(digits, f'Communicate() returned 0x{digits}')
    # An older SanBenchDrive printed no status. Say that rather than inventing a cause.
    return 'Communicate() failed and this build does not say with what'


def score_one(args, case, expect, unreachable, work):
    serial, debug = boot(args, case, work)

    if 'no memory protocol' in serial or 'no memory protocol' in debug:
        return dict(case=case, verdict='UNBUILT', detail='built without -D SAN_BENCH',
                    reports=[])
    if not is_narration(serial):
        return dict(case=case, verdict='NO BOOT',
                    detail='the exerciser never announced itself', reports=[])

    # Only what was said after this case announced itself. With one case per boot there
    # is nothing else on the wire, but a stray report from firmware start-up would
    # otherwise be credited to the case.
    after = serial
    marker = 'expect %s' % case

    def from_line_start(text, at):
        # From the start of the LINE, not from the marker. Slicing at the marker cuts off
        # the "SanBenchDrive: " prefix that the narration filter below depends on, so the
        # case's own announcement survives the filter -- and a case NAMED after a report
        # class then scores PASS off its own echo, with the sanitizer switched off.
        return text[text.rfind('\n', 0, at) + 1:]

    if marker in serial:
        after = from_line_start(serial, serial.index(marker))
    elif case == 'control' and 'control' in serial:
        after = from_line_start(serial, serial.index('control'))
    else:
        # The case never announced itself, so it never ran -- an exerciser too old to know
        # the name says "no such case" and carries on. Falling through to the whole log here
        # is what made that a PASS: every boot carries the HiiDatabase null-pointer reports,
        # and an 'asan' expectation matches the first sanitizer line it finds whatever
        # produced it. A case that did not run scored exactly like one that was caught.
        return dict(case=case, verdict='NOT RUN',
                    detail='the exerciser never announced this case -- it is not in the '
                           'SanBenchDrive that booted, so nothing was measured',
                    reports=[])

    reports = [line.strip() for line in after.splitlines()
               if REPORT.search(line) and not is_narration(line)]

    # The SMM reachability test comes FIRST, ahead of the control rule. Behind it,
    # 'smm-control' on an image with no SanBenchSmm took the control branch, found no
    # reports and scored PASS -- an unexercised control reported as a passing one,
    # and it inflated both halves of the graded line (12 of 12 became 13 of 13 on a
    # board where nothing SMM had run at all).
    # An SMM row that could not be raised splits two ways, and only ONE of them is a
    # non-detection. Conflating them put five rows in the denominator on every non-SMM
    # build, so the board printed "12 of 17" -- and fuzz_edk2.py fails the detects stage
    # on ANY shortfall, which turned a plain protocol sweep red over classes its firmware
    # was never built to run.
    #
    # The evidence is already on the wire. SanBenchSmm prints its image range at
    # registration, so:
    #
    #   no image line     the module is not in this volume: either SMM_REQUIRE was not
    #                     set, so OvmfPkgX64.dsc never built the SMM components, or
    #                     SAN_BENCH was not. The image structurally cannot run the case.
    #                     That is what UNBUILT already means for "built without
    #                     -D SAN_BENCH" and what N/A means for boot-service-after-exit,
    #                     and it is exempted here for the same reason.
    #
    #   image line, but   the module IS here and registered, and the loop still did not
    #   the SMI did not   close. A MISS, and it stays in the denominator: this is the
    #   arrive            result these rows exist to catch.
    #
    # Exempting everything that fails would put the dishonest shape back. An image that
    # HAS SanBenchSmm and stays silent still fails.
    if case.startswith('smm-'):
        registered = SMM_IMAGE_RE.search(serial) is not None
        if 'not attempted' in after and not registered:
            return dict(case=case, verdict='NO SMM',
                        detail='no SanBenchSmm in this image -- needs -D SMM_REQUIRE '
                               '-D SAN_BENCH, and this script run with --smm',
                        reports=[])
        if 'not attempted' in after:
            return dict(case=case, verdict='MISS',
                        detail='SanBenchSmm IS in this image but the SMI did not '
                               'arrive: ' + smi_refusal(after),
                        reports=reports[:4])

    # A control must be silent. Tested on the NAME, because the third column of CASES is
    # overloaded: for 'control' it holds a description ('no report at all') and for
    # 'boot-service-after-exit' it holds the reason that row cannot run. An earlier
    # version of this tested "expect is None and not unreachable" so that 'smm-control'
    # would stop falling through to MISS -- and that silently reclassified the DXE
    # 'control' row as N/A, which took the one row that proves the runtime is not crying
    # wolf out of the denominator altogether. Measured: 12 of 12 became 11 of 11, still
    # n of n, still green, and no longer scoring the control.
    # stale-protocol-interface is OFF unless the image was built for it, so the row is
    # exempt rather than a miss. Measured 2026-11-12 on run 43227236777: the class fired
    # three times during the BOOT, at the same addresses in every case's log, and took
    # the `control` row -- the row whose entire job is to report nothing on correct code
    # -- to FAIL. UninstallProtocolInterface unbinds a handle from an interface and says
    # nothing about the storage, which stays the owner's to keep using, so a read after
    # uninstall is not a defect. FwSanDxe now poisons only under -D ASAN_STALE_INTERFACE.
    #
    # Still SCORED when asked for: a campaign hunting a suspected stale-interface bug in
    # one driver is reasonable, and this row is what says whether the class still works.
    if case == 'stale-interface' and not getattr(args, 'stale_interface', False):
        return dict(case=case, verdict='N/A',
                    detail='off unless built with -D ASAN_STALE_INTERFACE -- the class '
                           'reports correct firmware and cost the control row',
                    reports=reports[:4])

    if case == 'control' or case.endswith('-control'):
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

    matched = [line for line in reports if expect.lower() in line.lower()]

    if matched and case in SMM_OWN_CODE:
        # The whole point of these three rows: the report has to come from this module's
        # own code. The ip is the only thing in an ASan report that identifies code, and
        # the range it is tested against is the one the module published for itself.
        image = SMM_IMAGE_RE.search(serial)
        if image is None:
            return dict(case=case, verdict='NO MAP',
                        detail='reported as %s, but the module never published its image '
                               'range, so nothing can say whose code raised it' % expect,
                        reports=matched[:4])
        base = int(image.group(1), 16)
        end = base + int(image.group(2), 16)
        # The ip is on the "address ..., ip ..." line rather than on the bug_descr line,
        # and the two are printed as a pair, so every report line is searched.
        inside, outside = [], []
        for line in matched:
            found = IP_RE.search(line)
            if found is None:
                continue
            (inside if base <= int(found.group(1), 16) < end
             else outside).append(found.group(1))
        if inside:
            return dict(case=case, verdict='PASS',
                        detail='%s from SanBenchSmm.efi at ip %s' % (expect, inside[0]),
                        reports=matched[:4])
        return dict(case=case, verdict='FOREIGN',
                    detail='reported as %s, but no ip is inside SanBenchSmm '
                           '[%s,0x%016X) -- saw %s. A fault in a library linked into the '
                           'module is not a fault in the module' %
                           (expect, image.group(1), end,
                            outside[0] if outside else 'no ip in any report'),
                    reports=matched[:4])

    if matched:
        return dict(case=case, verdict='PASS', detail=matched[0][:90], reports=reports[:4])

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
    parser.add_argument('--stale-interface', action=argparse.BooleanOptionalAction,
                        default=False,
                        help='score the stale-protocol-interface row. Only meaningful on '
                             'an image built with -D ASAN_STALE_INTERFACE; the class is '
                             'off by default because it reports correct firmware')
    parser.add_argument('--smm', action=argparse.BooleanOptionalAction, default=False,
                        help='boot q35 with SMM on, plus the SMM varstore globals, for '
                             'an image built with -D SMM_REQUIRE -- which does not boot '
                             'without them. OFF by default: those globals make the '
                             'varstore writable only from SMM, and whether a NON-SMM '
                             'image still boots that way is untested here. Without it '
                             'the smm-* rows come back exempt, which costs a '
                             'measurement and cannot cost a working board its verdict')
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
    skipped = tally(results, wanted)[2]
    for case, _expect, _unreachable in wanted:
        row = results[case]
        print('%-24s %-8s %s' % (case, row['verdict'], row['detail']))

    print('-' * 100)
    # Composed in one expression on purpose. With the numbers held in locals first, any
    # later arithmetic between tally() and the print would change what the pipeline
    # grades while every test of tally() still passed -- so there is deliberately
    # nowhere here for arithmetic to live.
    print(graded_line(*tally(results, wanted)[:2]))
    if skipped:
        print('not scorable here: %s' % ', '.join(sorted(skipped)))
    print('logs under %s' % args.out)

    stale = [r['case'] for r in results.values() if r['verdict'] == 'NOT RUN']
    if stale:
        print('NOT RUN: %s -- the SanBenchDrive in this firmware predates these cases. '
              'Rebuild it; a missing case is not a passing one.' % ', '.join(sorted(stale)))

    wrong_module = [r['case'] for r in results.values() if r['verdict'] == 'FOREIGN']
    if wrong_module:
        print("FOREIGN: %s -- the class was reported but not by SanBenchSmm's own code. "
              'That is the result already on record for SMM, not the one these rows exist '
              'to measure; do not read it as a detection.'
              % ', '.join(sorted(wrong_module)))
    unmapped = [r['case'] for r in results.values() if r['verdict'] == 'NO MAP']
    if unmapped:
        print('NO MAP: %s -- reported, but the module published no image range, so the '
              'report could not be attributed either way.' % ', '.join(sorted(unmapped)))
    no_smm = [r['case'] for r in results.values() if r['verdict'] == 'NO SMM']
    if no_smm:
        print('NO SMM: %s -- this image carries no SanBenchSmm, so these classes are '
              'exempt rather than missed and are NOT in the total above. To measure '
              'them: build with -D SMM_REQUIRE -D SAN_BENCH and pass --smm.'
              % ', '.join(sorted(no_smm)))

    # A control that reports, or a boot that never happened, invalidates the run rather
    # than costing it a point -- so those fail the exit status while a MISS does not.
    broken = [r for r in results.values()
              if r['verdict'] in ('FAIL', 'NO BOOT', 'ERROR')]
    return 1 if broken else 0


if __name__ == '__main__':
    sys.exit(main())
