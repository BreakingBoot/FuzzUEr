#!/usr/bin/env python3
"""Assert a firmware-sanitizer detection cannot be announced without being reported.

EVAL-1 run 42186976238 put 6403878 "FWSAN: double-fetch -- untrusted word read twice in one
call" lines into a 387 MB capture and not one fwsan- report beside them. So 6.4 million
detections of the canonical cross-privilege SMM bug class produced nothing a triage pass
could key on, cluster or attribute: bugs.json held 73 rows and zero double-fetch sites.

Three separate things let that happen and stay unnoticed:

  the banner was printed before the report was attempted, unconditionally, so the two could
  disagree and the loud half was the one that did not carry an address, a size or an ip;

  bench_cases.py scores a detection off the banner's " -- " separator, so the benchmark
  reported 11 of 11 classes detected while the reporting path produced nothing;

  every return in the report path was silent, and the dedup table was shared with the
  generic outline handlers, so a budget spent by one family closed the other with nothing
  said about it.

The fix is structural rather than a diagnosis: the banner now comes from inside the report
function, after its guards, so a suppressed detection is quiet and a narrated one always
carries its address. What the guards do is counted and narrated at powers of two, which is
what will say which guard was closing on the next run.

AND THEN: a report that comes out has to say something a developer can act on. The one the
detector produced, in full, was

    sev1 x2759  VariableSmm.efi  Unaligned.c:32:10  fwsan-double-fetch (read)
            read of 2 bytes at 0x000000001B56802C

MdePkg/Library/BaseLib/Unaligned.c:32 is ReadUnaligned16, a leaf utility called from
everywhere; nobody can patch that. The detector already knew the offset of the read inside
the buffer the harness registered -- the offset of the FIELD in the caller-controlled
struct -- and threw it away, and it recorded only the granule of the first fetch, so the
report named the read that used the value and lost the read that validated it. The second
half of this file is about those facts: that they are recorded, that they reach the wire,
that nothing already parsing the line can confuse them for the access, and that
scripts/bug_report.py turns the offset into a field name or says why it could not.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASAN = os.path.join(ROOT, 'uefi_asan', 'AsanLib', 'Asan.c')
INFO = os.path.join(ROOT, 'uefi_asan', 'AsanInfo.h')
HELPERS = [os.path.join(ROOT, 'uefi_asan', lib, 'AsanHelper.c')
           for lib in ('AsanMemoryLib', 'AsanMemoryLibRepStr')]
BENCH = os.path.join(ROOT, 'scripts', 'bench_cases.py')

FAILURES = []

# The buffer the fetch driver registers, and where it reads inside it. These are the real
# numbers from the EVAL-1 finding this file's docstring quotes: a 2-byte read 0x2C into the
# comm buffer, which is RW_VARIABLE_INFO.VarGuid.Data2 once the message header is taken off.
#
# 0x450 is sizeof (EFI_SMM_COMMUNICATE_HEADER) plus sizeof (RW_VARIABLE_INFO) as the
# analyser records that block -- 8 members ending UINT8 Data[MAX_LENGTH], 0x438 bytes.
BASE, EXTENT, OFFSET_IN = 0x1B568000, 0x450, 0x2C
FIRST_IP, SECOND_IP = 0x1FFC9B20, 0x1FFC9B37

# SHADOW_SCALE is kDefaultShadowScale in asan_mapping.h, which the stub below cannot
# include. Pinned here and asserted against the header, because the granule is what makes
# a 4-byte read and an 8-byte read of the same word one fetch.
SHADOW_SCALE = 3

STUB = """
typedef unsigned long long UINT64; typedef unsigned long UINTN;
typedef unsigned int UINT32; typedef unsigned char UINT8;
typedef char CHAR8; typedef unsigned char BOOLEAN; typedef void VOID;
#define IN
#define OUT
#define CONST const
#define STATIC static
#define OPTIONAL
#define TRUE 1
#define FALSE 0
#define NULL ((void*)0)
#define SHADOW_SCALE %d
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char LOG[1 << 20];
static int LOGN;
void SerialOutput(const CHAR8 *s) { LOGN += snprintf(LOG+LOGN, sizeof LOG - LOGN, "%%s", s); }
void Num2Str64bit(UINT64 v, CHAR8 *o) { snprintf(o, 19, "0x%%016llX", (unsigned long long)v); }
static BOOLEAN asan_inited = TRUE;
static BOOLEAN asan_is_deactivated = FALSE;
""" % SHADOW_SCALE

# One translation unit, not two. AsanReportFirmwareClassField and AsanEmitReport are static
# in Asan.c, so a driver compiled separately cannot reach them -- and the point of this
# check is to drive the real code rather than a copy of it.
DRIVER = r"""
static int count(const char *needle) {
    int n = 0; const char *p = LOG;
    while ((p = strstr(p, needle)) != NULL) { n++; p++; }
    return n;
}

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "class";

    if (!strcmp(mode, "class")) {
        int ips  = atoi(argv[2]);
        int hits = atoi(argv[3]);
        for (int h = 0; h < hits; h++)
            for (int i = 0; i < ips; i++)
                AsanReportFirmwareClass("double-fetch",
                                        "untrusted word read twice in one call",
                                        0xdead, 8, 0, 0x1000 + i);
    } else if (!strcmp(mode, "fetch")) {
        /* first size, second size, first offset, second offset */
        UINTN s1 = (UINTN)strtoul(argv[2], NULL, 0);
        UINTN s2 = (UINTN)strtoul(argv[3], NULL, 0);
        UINTN o1 = (UINTN)strtoul(argv[4], NULL, 0);
        UINTN o2 = (UINTN)strtoul(argv[5], NULL, 0);
        AsanRegisterUntrusted(BASE_ADDR, EXTENT_BYTES);
        AsanNoteUntrustedRead(BASE_ADDR + o1, s1, FIRST_IP_VAL);
        if (s2) {
            AsanNoteUntrustedRead(BASE_ADDR + o2, s2, SECOND_IP_VAL);
        }
    } else if (!strcmp(mode, "outside")) {
        AsanRegisterUntrusted(BASE_ADDR, EXTENT_BYTES);
        /* both reads past the registered end: nothing here is untrusted */
        AsanNoteUntrustedRead(BASE_ADDR + EXTENT_BYTES + 8, 4, FIRST_IP_VAL);
        AsanNoteUntrustedRead(BASE_ADDR + EXTENT_BYTES + 8, 4, SECOND_IP_VAL);
    } else if (!strcmp(mode, "closed")) {
        /* the window shut, which is what FirnessSanitizer(FALSE) does after the call */
        AsanRegisterUntrusted(BASE_ADDR, EXTENT_BYTES);
        AsanNoteUntrustedRead(BASE_ADDR + 0x2C, 2, FIRST_IP_VAL);
        AsanRegisterUntrusted(0, 0);
        AsanNoteUntrustedRead(BASE_ADDR + 0x2C, 2, SECOND_IP_VAL);
    } else if (!strcmp(mode, "reopen")) {
        /* two calls over the same buffer, which is every iteration of a campaign */
        AsanRegisterUntrusted(BASE_ADDR, EXTENT_BYTES);
        AsanNoteUntrustedRead(BASE_ADDR + 0x2C, 2, FIRST_IP_VAL);
        AsanRegisterUntrusted(0, 0);
        AsanRegisterUntrusted(BASE_ADDR, EXTENT_BYTES);
        AsanNoteUntrustedRead(BASE_ADDR + 0x2C, 2, SECOND_IP_VAL);
    }

    printf("banners %d\n",   count("FWSAN: double-fetch -- "));
    printf("reports %d\n",   count("bug_descr=fwsan-double-fetch"));
    printf("notes %d\n",     count("FWSAN: suppressed ("));
    printf("lines %d\n",     count("\n"));
    printf("fields %d\n",    count("untrusted_field offset="));
    printf("---LOG---\n%s", LOG);
    return 0;
}
"""


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def definition(src, sig):
    """The definition of sig with its body, skipping any forward declaration.

    A forward declaration and a definition share the whole signature, so the two are told
    apart by what follows the closing parenthesis of the parameter list -- ';' or '{'.
    Matching on "the next '{' anywhere after the name" would hand back the declaration
    followed by whatever function came next, which is how this check first read
    AsanRegisterUntrusted as part of AsanEmitReport.
    """
    pos = -1
    while True:
        pos = src.find(sig, pos + 1)
        if pos < 0:
            raise LookupError(sig[:40])
        close = src.find(')', pos + len(sig))
        if close >= 0 and src[close + 1:].lstrip().startswith('{'):
            break
    depth = 0
    start = src.index('{', src.find(')', pos + len(sig)))
    for k in range(start, len(src)):
        if src[k] == '{':
            depth += 1
        elif src[k] == '}':
            depth -= 1
            if depth == 0:
                return 'VOID\n' + src[pos:k + 1] + '\n'
    raise LookupError('unbalanced')


# The lines each signature below is the definition of. Named once so a mutation that
# renames a function fails in one place with a readable message instead of in four.
EMIT_SIG = 'AsanEmitReport (\n  IN CONST CHAR8  *bug_descr,'
FIELD_SIG = 'AsanReportFirmwareClassField (\n  IN CONST CHAR8  *BugDescr,'
ENTRY_SIG = 'AsanReportFirmwareClass (\n  IN CONST CHAR8  *BugDescr,'
NOTE_SIG = 'AsanNoteUntrustedRead (\n  IN UINTN  Addr,'
REGISTER_SIG = 'AsanRegisterUntrusted (\n  IN UINT64  Base,'

ASAN_INFO_STRUCT = re.compile(r'typedef struct \{.*?\} ASAN_INFO;', re.S)


def info_struct(info_src):
    """The real ASAN_INFO out of AsanInfo.h.

    Lifted rather than stubbed so this cannot pass against a header that never got the
    first-fetch arrays: the detection path below reads them by name, and a copy of the
    struct written here would compile whatever the header says. Line endings are
    normalised for the temporary file only -- AsanInfo.h is CRLF in both trees and stays
    that way.
    """
    found = ASAN_INFO_STRUCT.search(info_src.replace('\r\n', '\n'))
    if not found:
        raise LookupError('ASAN_INFO is not a typedef struct in AsanInfo.h any more')
    return found.group(0) + '\n'


def unit_source(src, info_src):
    """The real report and detection paths, in one translation unit."""
    tables = src[src.index('#define ASAN_FWSAN_IP_SEEN'):src.index('\nVOID\nAsanReportOutline')]
    record = src[src.index('typedef struct {\n  UINT64  Base;'):]
    record = record[:record.index('} ASAN_UNTRUSTED_FIELD;') + len('} ASAN_UNTRUSTED_FIELD;')]
    return (STUB
            + info_struct(info_src)
            + 'static ASAN_INFO AsanInfoStorage;\n'
              'static ASAN_INFO *mAsanInfo = &AsanInfoStorage;\n'
            + f'#define BASE_ADDR 0x{BASE:X}ULL\n'
            + f'#define EXTENT_BYTES 0x{EXTENT:X}ULL\n'
            + f'#define FIRST_IP_VAL 0x{FIRST_IP:X}ULL\n'
            + f'#define SECOND_IP_VAL 0x{SECOND_IP:X}ULL\n'
            + tables
            + record + '\n'
            + definition(src, EMIT_SIG)
            + definition(src, FIELD_SIG)
            + definition(src, ENTRY_SIG)
            + definition(src, REGISTER_SIG)
            + definition(src, NOTE_SIG)
            + DRIVER)


def drive(src, info_src, *argv):
    """Compile the real path and run it. Returns (counts, log, errors)."""
    try:
        unit = unit_source(src, info_src)
    except LookupError as missing:
        return None, '', [f'cannot assemble the unit: {missing}']
    with tempfile.TemporaryDirectory() as work:
        cfile = os.path.join(work, 'unit.c')
        exe = os.path.join(work, 'drive')
        open(cfile, 'w').write(unit)
        built = subprocess.run(
            ['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-o', exe, cfile],
            capture_output=True, text=True)
        if built.returncode != 0:
            return None, '', built.stderr.strip().splitlines()[:6]
        ran = subprocess.run([exe] + [str(a) for a in argv],
                             capture_output=True, text=True)
        # Only the header is counted. The log that follows is full of "0x0000..." and a
        # (\w+) (\d+) sweep over it would take the 0 out of every hex number as a count.
        head, _, log = ran.stdout.partition('---LOG---\n')
        got = dict(re.findall(r'(\w+) (\d+)', head))
        return {k: int(v) for k, v in got.items()}, log, None


def build_and_run(src, ips, hits, info_src=None):
    """The report path alone, driven by ips distinct sites reporting hits times each."""
    counts, _log, err = drive(src, info_src if info_src is not None else INFO_SRC,
                              'class', ips, hits)
    return counts, err


INFO_SRC = ''


def main():
    global INFO_SRC
    print('A firmware-sanitizer detection cannot be announced without being reported')
    src = open(ASAN, encoding='utf-8').read()
    INFO_SRC = open(INFO, encoding='utf-8', newline='').read()

    # --- structure: the banner lives in exactly one place ---
    # One class banner in the file, and it has to be the one inside the report function.
    # Counting zero would be wrong -- the banner still has to be emitted, just not before
    # the guards -- so this checks WHERE it is rather than whether it exists.
    #
    # Located inside the extracted DEFINITION, not by offsets into the file: the signature
    # also matches the forward declaration near the top, and a window anchored there spans
    # the wrong region entirely.
    # AsanReportFirmwareClassField is the body; AsanReportFirmwareClass is a wrapper over
    # it that passes no field, and is the six-argument entry point AsanHelper.c and
    # FwSanDxe.c declare by hand. The guards, the counters and the banner are checked on
    # the body, and the wrapper is checked for going through it.
    report = definition(src, FIELD_SIG)
    entry = definition(src, ENTRY_SIG)
    banners = len(re.findall(r'SerialOutput \("FWSAN: (?!suppressed)', src))
    in_report = len(re.findall(r'SerialOutput \("FWSAN: (?!suppressed)', report))
    check('the class banner is printed only from the report path',
          banners == 1 and in_report == 1,
          f'{banners} banner(s) in Asan.c, {in_report} inside '
          f'AsanReportFirmwareClassField')
    # A second body would be a second set of guards to forget. The whole reason the banner
    # moved inside the report is that two places could disagree about one detection.
    check('the six-argument entry point reports nothing of its own',
          'SerialOutput' not in entry and 'mFwsan' not in entry,
          'a caller that went round the guards would put back the defect this file is '
          'named for, one class at a time')
    check('it forwards to the body with no field',
          entry.count('AsanReportFirmwareClassField (') == 1 and 'NULL);' in entry,
          entry.strip().splitlines()[-2:])
    # Both AsanHelper copies carry the foreign-region check and both have to change
    # together: one left printing its own banner is one class that can still announce a
    # detection it never reports. Restored after an edit to the block above deleted this
    # loop -- the mutation case "A6 helper prints its own banner" is what found that.
    for path in HELPERS:
        helper = open(path, encoding='utf-8').read()
        name = os.path.basename(os.path.dirname(path))
        check(f'{name} does not print its own banner',
              'SerialOutput ("FWSAN: ' not in helper,
              'both AsanHelper copies have to change together')
        check(f'{name} passes a detail to the report',
              'AsanReportFirmwareClass ("foreign-region", region,' in helper)

    check('the banner is emitted after the guards',
          report.index('mFwsanSeenIp[mFwsanSeenCount++]') < report.index('SerialOutput ("FWSAN: "'),
          'a banner before the guards is the defect this check exists for')
    check('the report takes the detail text as a parameter',
          'IN CONST CHAR8  *Detail,' in report)
    check('a missing detail does not dereference NULL',
          'Detail != NULL' in report)

    # --- the budgets are separate ---
    check('the firmware classes have their own dedup table',
          'mFwsanSeenIp' in src and 'ASAN_FWSAN_IP_SEEN' in src)
    check('the report path does not touch the outline table',
          'mOutlineSeen' not in report,
          'sharing it lets one family spend the other family\'s budget')
    outline = definition(src, 'AsanReportOutline (')
    check('the outline path does not touch the firmware table',
          'mFwsanSeen' not in outline)

    # --- every return is counted ---
    for counter in ('mFwsanDetected', 'mFwsanReported',
                    'mFwsanSuppressedSeen', 'mFwsanSuppressedFull', 'mFwsanSuppressedOff'):
        check(f'{counter} exists', counter in src)
    returns = len(re.findall(r'\n    return;', report))
    notes = len(re.findall(r'AsanFwsanNote \(', report))
    check('every suppressing return is narrated', notes >= 3 and notes >= returns - 1,
          f'{returns} return(s), {notes} note call(s)')
    check('the note reports the totals, not just the reason',
          'mFwsanDetected' in src[src.index('AsanFwsanNote ('):src.index('AsanFwsanNote (') + 1500])

    # --- bench_cases must still score the banner, since that is what it keys on ---
    bench = open(BENCH, encoding='utf-8').read()
    pattern = re.search(r"r'(FWSAN: \[a-z\]\[a-z-\]\* \[a-z \]\*-- )\|", bench)
    check('bench_cases still keys on the " -- " banner shape', pattern is not None,
          'if this moved, the emitted banner has to move with it')
    if pattern:
        emitted = 'FWSAN: double-fetch -- untrusted word read twice in one call'
        check('the emitted banner matches what bench_cases scores',
              re.search(pattern.group(1), emitted) is not None, emitted)

    # =================================================================================
    # Everything above is about a detection reaching the wire at all. Everything from here
    # is about what it then SAYS: the field it names, both reads, and nothing it cannot
    # prove. The source-only checks come first on purpose -- a header that lost one of
    # these arrays would otherwise be reported as a gcc error from the compile below.
    # =================================================================================
    print('the detection record keeps the first fetch')
    info = INFO_SRC
    seen = re.search(r'AsanUntrustedSeen\[(\d+)\]', info)
    check('AsanInfo.h still has the granule table', seen is not None)
    for name in ('AsanUntrustedSeenIp', 'AsanUntrustedSeenAddr', 'AsanUntrustedSeenSize'):
        found = re.search(rf'{name}\[(\d+)\]', info)
        check(f'AsanInfo.h records {name[len("AsanUntrusted"):]}', found is not None,
              'the granule alone names the second read and loses the first')
        check(f'{name} is the same fixed size as the granule table',
              found is not None and seen is not None
              and found.group(1) == seen.group(1),
              f'{found.group(1) if found else "-"} vs {seen.group(1) if seen else "-"} '
              f'-- they are indexed together, so they cannot differ')
    check('AsanInfo.h is still CRLF, as both trees have it',
          '\r\n' in info and '\n' not in info.replace('\r\n', ''),
          'a text-mode rewrite of a port file once reflowed all 972 lines of one')

    note = definition(src, NOTE_SIG)
    check('the first fetch is recorded beside the granule it matches on',
          all(f'mAsanInfo->{n}[mAsanInfo->AsanUntrustedSeenCount]' in note
              for n in ('AsanUntrustedSeen', 'AsanUntrustedSeenIp',
                        'AsanUntrustedSeenAddr', 'AsanUntrustedSeenSize')),
          'recorded apart, they can come to describe different fetches')
    check('the table is still bounded', 'AsanUntrustedSeenCount < 8' in note,
          'the snapshot restore rewinds this every iteration; it cannot grow')
    # Two rules in the detector that the field work must not quietly undo.
    check('the match is still by granule, not by exact address',
          'Word = (UINT64)Addr & ~((UINT64)SHADOW_GRANULARITY - 1);' in note,
          'a length read as four bytes and then as eight is one fetch of one word')
    check('SHADOW_GRANULARITY is what this check compiles with',
          f'kDefaultShadowScale = {SHADOW_SCALE}' in open(
              os.path.join(ROOT, 'uefi_asan', 'AsanLib', 'asan_mapping.h'),
              encoding='utf-8').read(),
          f'the stub pins SHADOW_SCALE at {SHADOW_SCALE}')
    check('the ip still comes from the access macro',
          '__builtin_return_address' not in note,
          'computing it here gives the return address inside __asan_loadN, so every '
          'report symbolises to AsanLib instead of the firmware line that read')
    check('escalation to a solution is still opt-in',
          '#ifdef FWSAN_DOUBLE_FETCH_SOLUTION' in note,
          '30 seeds in, 29 objectives, corpus 0 -- the campaign re-confirmed one benign '
          'pattern and never explored past its seeds')

    record = re.search(r'typedef struct \{(.*?)\} ASAN_UNTRUSTED_FIELD;', src, re.S)
    check('there is a record for what a double fetch knows', record is not None)
    for member in ('Base', 'Size', 'Offset', 'FirstIp', 'FirstAddr', 'FirstSize'):
        check(f'it carries {member}', record is not None and member in record.group(1))
    outline = definition(src, 'AsanReportOutline (')
    check('the generic outline report carries no field',
          '"asan-outline-instrumentation", NULL' in outline,
          'a heap overflow has no untrusted buffer behind it and must not claim one')

    # --- behaviour: compile the real path and drive it ---
    got, err = build_and_run(src, ips=3, hits=1000)
    if err:
        check('the report path compiles', False, '; '.join(err))
        print(f'{len(FAILURES)} failure(s)')
        return 1
    check('the report path compiles under -Wall -Wextra -Werror', True)
    check('one report per distinct ip', got['reports'] == 3, str(got))
    check('a banner never outnumbers its reports', got['banners'] == got['reports'], str(got))
    # A healthy path must be quiet. The counters rewind with the snapshot every iteration,
    # so a line per suppressed detection is a line per detection: 991623 of them on EVAL-1
    # run 42310220335, which is the volume problem the banner had, moved.
    check('a reporting path does not narrate its own suppressions',
          got['notes'] == 0, str(got))
    check('3000 detections do not cost 3000 lines', got['lines'] < 60, str(got))

    # The table-full arm: more distinct ips than the table holds must still not go silent.
    cap = int(re.search(r'#define ASAN_FWSAN_IP_SEEN\s+(\d+)', src).group(1))
    got, err = build_and_run(src, ips=cap + 50, hits=2)
    check('a full table still reports up to its cap',
          err is None and got['reports'] == cap, str(err or got))
    check('a full table says so rather than going quiet',
          err is None and got['notes'] > 0, str(err or got))

    # And the diagnostic case the narration exists for: detections arriving with nothing
    # reported beside them has to be audible, which is the state that produced 6403878
    # banners and 0 reports.
    silent = re.sub(r'(\n  mFwsanSeenIp\[mFwsanSeenCount\+\+\] = Ip;)',
                    r'\n  if (TRUE) { mFwsanSuppressedOff++; AsanFwsanNote ("off", '
                    r'mFwsanSuppressedOff); return; }\1', src, count=1)
    got, err = build_and_run(silent, ips=3, hits=1000)
    check('a path that reports nothing says so',
          err is None and got['reports'] == 0 and got['notes'] > 0, str(err or got))

    # A report this path emits must not be mistaken for a source location by the crash
    # extractor. The UBSan shape is "<path>, line:0x008B, column:0x003A"; the firmware
    # sanitizer's report ends "at line: 0x1FFC9B37", and a test for a bare "line:" matched
    # both -- so a compiler-inserted check that followed a fwsan report took the whole
    # report line as its path. Run 42483193618 filed that as issue #51 with the report
    # line in the title. Only reachable once this path emitted a report at all.
    extractor = open(os.path.join(ROOT, 'scripts', 'firness.py'), encoding='utf-8').read()
    loose = re.findall(r"check fail' in line and 'line:' in prev", extractor)
    check('the extractor does not treat a bare "line:" as a source location',
          not loose, f'{len(loose)} loose shape test(s) left')
    tight = re.findall(r"', line:' in prev\w* and 'column:' in prev", extractor)
    check('it requires the comma-and-column shape instead', len(tight) >= 2,
          f'{len(tight)} tightened site(s); both extractors need it')

    # And the shapes themselves, so the rule is pinned to real capture text.
    banner = 'ASAN MEMORY ACCESS check fail! __asan_load0x02 is called'
    ubsan = ('/workspace/tmp/edk2/UefiPayloadPkg/Library/SpiFlashLib/SpiFlashLib.c, '
             'line:0x008B, column:0x003A')
    fwsan = 'bug_descr=fwsan-double-fetch in file: fwsan at line: 0x000000001FFC9B37'

    def shaped(prev):
        return ('ASAN MEMORY ACCESS check fail' in banner
                and ', line:' in prev and 'column:' in prev)

    check('a real UBSan location is still recognised', shaped(ubsan))
    check('a firmware sanitizer report is not', not shaped(fwsan))

    print('and the report names the field and both reads')
    counts, log, err = drive(src, INFO_SRC, 'fetch', 2, 2, OFFSET_IN, OFFSET_IN)
    if err:
        check('the detection path compiles', False, '; '.join(err))
        print(f'{len(FAILURES)} failure(s)')
        return 1
    check('the detection path compiles under -Wall -Wextra -Werror', True)
    check('a word read twice is reported once', counts['reports'] == 1, str(counts))
    check('the report carries an untrusted field', counts['fields'] == 1, str(counts))

    error = ''
    for line in log.splitlines():
        if 'ERROR: Invalid memory access' in line:
            error = line
    check('the field is on the ERROR line, where firness.py reads the message from',
          'untrusted_field' in error, error[:140])

    said = dict(re.findall(r'(\w+)=(0x[0-9A-Fa-f]+)', error))
    check(f'the offset is the one inside the buffer (0x{OFFSET_IN:X})',
          said.get('offset', '').lower() == f'0x{OFFSET_IN:016x}',
          f'{said.get("offset")!r}: Addr - Base is the offset of the FIELD in the '
          f'caller-controlled struct, which is the whole of what makes this actionable')
    check('the base is the registered buffer',
          said.get('base', '').lower() == f'0x{BASE:016x}', said.get('base'))
    check('the extent is how far it reaches',
          said.get('extent', '').lower() == f'0x{EXTENT:016x}',
          f'{said.get("extent")!r}: without it a reader cannot tell a field from the tail')
    check('the first read is named by ip',
          said.get('first_ip', '').lower() == f'0x{FIRST_IP:016x}',
          f'{said.get("first_ip")!r}: the first read is the one that VALIDATED, and a '
          f'developer handed only the re-read has no way to find the check it got past')
    check('and it is not the re-read',
          said.get('first_ip', '').lower() != f'0x{SECOND_IP:016x}')
    access = re.search(r'\bip (0x[0-9A-Fa-f]+)', error)
    check('the re-read is the ip of the access itself',
          access is not None and access.group(1).lower() == f'0x{SECOND_IP:016x}',
          f'{access.group(1) if access else None!r}: the row\'s own location is the '
          f'second read, and both have to be in the line')
    check('the first read carries its own address',
          said.get('first_addr', '').lower() == f'0x{BASE + OFFSET_IN:016x}',
          said.get('first_addr'))

    # The granule rule, end to end: four bytes to check a length and eight to use it is
    # one fetch of one word, and the two sizes are the only thing that says so.
    counts, log, err = drive(src, INFO_SRC, 'fetch', 4, 8, OFFSET_IN & ~7, OFFSET_IN & ~7)
    wide = [l for l in log.splitlines() if 'ERROR: Invalid memory access' in l]
    check('a 4-byte read then an 8-byte read of the same word is one fetch',
          err is None and counts['reports'] == 1, str(err or counts))
    said = dict(re.findall(r'(\w+)=(0x[0-9A-Fa-f]+)', wide[0])) if wide else {}
    check('and the first read\'s own size is reported, not the second\'s',
          said.get('first_bytes', '').lower() == '0x0000000000000004',
          f'{said.get("first_bytes")!r} with the access at 8 bytes')

    counts, _log, err = drive(src, INFO_SRC, 'fetch', 2, 0, OFFSET_IN, OFFSET_IN)
    check('one read of an untrusted word is not a double fetch',
          err is None and counts['reports'] == 0 and counts['fields'] == 0,
          str(err or counts))
    counts, _log, err = drive(src, INFO_SRC, 'outside')
    check('a word outside the registered buffer is not watched at all',
          err is None and counts['reports'] == 0, str(err or counts))
    counts, _log, err = drive(src, INFO_SRC, 'closed')
    check('a read after the window closes is not watched',
          err is None and counts['reports'] == 0,
          f'{err or counts}: the harness closes it after the call, and a read afterwards '
          f'is firmware reading its own memory')
    counts, _log, err = drive(src, INFO_SRC, 'reopen')
    check('closing the window forgets what was read in it',
          err is None and counts['reports'] == 0,
          f'{err or counts}: the next call registers the same buffer at the same address, '
          f'and a granule left in the table from the last one would be reported as a '
          f'double fetch that never happened -- with the previous call\'s ip beside it')

    print('and nothing already parsing that line can mistake the field for the access')
    # key=0xVALUE with no space, so these cannot match it. Relying instead on the real
    # key appearing earlier in the line would be a coincidence: every one of these is a
    # leftmost-first search.
    sys.path.insert(0, os.path.join(ROOT, 'scripts'))
    import bug_report as br
    # Where the handler's own parameter block starts inside the registered buffer, which
    # is the whole of what bug_report.py assumes about the layout above the offset.
    COMM_AT = br.COMM_PAYLOAD_AT
    counts, log, err = drive(src, INFO_SRC, 'fetch', 2, 2, OFFSET_IN, OFFSET_IN)
    error = [l for l in log.splitlines() if 'ERROR: Invalid memory access' in l][0]
    tail = error.split('Invalid memory access:', 1)[1].strip()
    suffix = ', untrusted_field ' + tail.split(', untrusted_field ', 1)[1]
    for name, pattern, want in (('ip', br.IP_RE, SECOND_IP),
                                ('address', br.ADDR_RE, BASE + OFFSET_IN),
                                ('size', br.SIZE_RE, 2)):
        found = pattern.search(tail)
        check(f'{name} still resolves to the access, not to a field key',
              found is not None and int(found.group(1), 16) == want,
              f'{found.group(1) if found else None} wanted {want:#x}')
        # And on the field text by itself, which is the invariant rather than the
        # consequence. Testing only the whole line passes for the wrong reason: every one
        # of these is a leftmost-first search and the access always comes first, so a
        # field spelled "first_ip 0x.." would be matched by IP_RE and the line would still
        # resolve correctly -- until something used findall, or the order changed.
        check(f'and the field text alone matches no {name}',
              pattern.search(suffix) is None,
              f'{suffix!r} is matched by {pattern.pattern!r}; key=0xVALUE with no space '
              f'after the = is what makes that impossible')
    own = re.search(r'(?:Return IP address is|\bip) (0x[0-9A-Fa-f]+)', tail)
    check('firness.py attributes the module from the access ip',
          own is not None and int(own.group(1), 16) == SECOND_IP,
          'attribute_from_own_ip takes the first ip in the message')
    lines = log.splitlines()
    at = [i for i, l in enumerate(lines) if 'ERROR: Invalid memory access' in l][0]
    check('bug_descr= still follows the ERROR line immediately',
          lines[at + 1].startswith('bug_descr=fwsan-double-fetch'),
          f'{lines[at + 1][:60]!r}: firness.py reads the message off prev_line, so a '
          f'line between the two loses the row')
    check('the whole report is still three lines plus the banner', len(lines) == 4,
          f'{len(lines)}: the field is appended to a line, not given one')

    # bench_cases.py scores a detection by counting lines its REPORT pattern matches, so
    # anything new on the wire is a possible extra detection credited to whatever case was
    # running. The field text must add none: it is appended to a line that already matched
    # nothing, and the banner it is scored on has not moved.
    import bench_cases
    stripped = re.sub(r', untrusted_field [^\n]*', '', log)
    check('the field text adds no bench_cases detection',
          len(bench_cases.REPORT.findall(log)) ==
          len(bench_cases.REPORT.findall(stripped)) == 1,
          f'{len(bench_cases.REPORT.findall(log))} with the field, '
          f'{len(bench_cases.REPORT.findall(stripped))} without')

    print('and triage turns the offset into a field of the handler\'s struct')
    # The row as firness.py writes it: the class goes in Asan Msg and ErrorType is the
    # literal 'asan', because that is what record() is called with on the bug_descr= line.
    # Writing the class into ErrorType instead would make bug_type() return it verbatim
    # and this would pass without the direction ever being read out of the message.
    row = {'Phase': 'fuzz', 'Module': 'VariableSmm.efi',
           'File': 'MdePkg/Library/BaseLib/Unaligned.c', 'Line': '32',
           'Asan Msg': 'fwsan-double-fetch', 'ErrorType': 'asan',
           'Message': tail, 'Count': '2759'}
    parsed = br.Report(row, 'DiscoveredSmi')
    check('the field reaches bug_report.py off the capture line',
          parsed.field.get('offset') == OFFSET_IN
          and parsed.field.get('first_ip') == FIRST_IP
          and parsed.field.get('extent') == EXTENT, str(parsed.field))
    check('the cluster key is unchanged', parsed.bug_type() == 'fwsan-double-fetch (read)',
          f'{parsed.bug_type()!r}: module_attribution_check.py asserts on this exact '
          f'string, and a key that moved would refile every open issue')
    check('the direction still comes out of the enriched message',
          '(read)' in parsed.bug_type() and 'is_write 0x0000000000000000' in tail,
          'is_write is before the field text and has to stay readable')

    # The real EVAL-1 block, field for field as this campaign's types.json records it:
    # eight members ending UINT8 Data[MAX_LENGTH], MAX_LENGTH 1024. scalar_choice_check.py
    # carries a ninth `Next` member in its own fixture; the recorded type has no such
    # field, and copying that list into here made this assert a 0x440 block that does not
    # exist. Taken from the analyser output rather than from another check.
    types = br._types_from_json([
        {'TypeName': 'GUID', 'File': 'MdePkg/Include/Base.h', 'Fields': [
            {'Name': 'Data1', 'Type': 'UINT32'}, {'Name': 'Data2', 'Type': 'UINT16'},
            {'Name': 'Data3', 'Type': 'UINT16'}, {'Name': 'Data4', 'Type': 'UINT8[8]'}]},
        {'TypeName': 'RW_VARIABLE_INFO', 'File': 'OvmfPkg/RWVariable/RWVariable.h',
         'Fields': [
            {'Name': 'Status', 'Type': 'EFI_STATUS'},
            {'Name': 'Signature', 'Type': 'UINT32'},
            {'Name': 'AccessType', 'Type': 'UINT32'},
            {'Name': 'VarGuid', 'Type': 'EFI_GUID'},
            {'Name': 'Attributes', 'Type': 'UINT32'},
            {'Name': 'VariableNameSize', 'Type': 'UINTN'},
            {'Name': 'Offset', 'Type': 'UINTN'},
            {'Name': 'Data', 'Type': 'UINT8[1024]'}]}])
    aliases = {'EFI_STATUS': 'RETURN_STATUS', 'RETURN_STATUS': 'UINTN',
               'UINTN': 'UINT64', 'EFI_GUID': 'GUID'}
    laid = br.struct_layout('RW_VARIABLE_INFO', types, aliases)
    check('the block lays out at the ABI the firmware is built for',
          laid['size'] == 0x438 and laid['align'] == 8,
          f'{laid["size"]} bytes, align {laid["align"]}: EFI_STATUS is 8 and EFI_GUID '
          f'aligns to 4, so VariableNameSize is padded to 0x28')
    check('every field is placed', laid['stopped'] == '', laid['stopped'])
    placed = dict((p, (o, s)) for p, o, s in laid['fields'])
    for name, offset, size in (('Status', 0x000, 8), ('Signature', 0x008, 4),
                               ('AccessType', 0x00C, 4), ('VarGuid', 0x010, 16),
                               ('VarGuid.Data2', 0x014, 2), ('Attributes', 0x020, 4),
                               ('VariableNameSize', 0x028, 8), ('Offset', 0x030, 8),
                               ('Data', 0x038, 1024)):
        check(f'{name} is at 0x{offset:X} for {size} byte(s)',
              placed.get(name) == (offset, size), str(placed.get(name)))

    hit = br.field_at(laid['fields'], OFFSET_IN - br.COMM_PAYLOAD_AT, 2)
    check('offset 0x2C of the comm buffer is RW_VARIABLE_INFO.VarGuid.Data2',
          hit == ('VarGuid.Data2', 0x14, 2),
          f'{hit}: the harness registers the whole message, so 0x18 of header comes off '
          f'first and the remaining 0x14 is the second member of the GUID')
    check('the exact fit wins over the struct that contains it',
          hit[0] != 'VarGuid',
          'naming the GUID when a 2-byte field starts exactly there is less than this '
          'knows')
    check('a read spanning two fields names neither',
          br.field_at(laid['fields'], 0x24, 8) is None,
          'it starts in Attributes and ends in VariableNameSize, and calling it either '
          'would be a guess')
    check('a read past the end of the block names nothing',
          br.field_at(laid['fields'], 0x438, 2) is None,
          'Data ends at 0x438 and there is no member after it')

    print('and it degrades rather than guessing')
    unsizable = br._types_from_json([
        {'TypeName': 'ODD_BLOCK', 'File': 'x.h', 'Fields': [
            {'Name': 'Known', 'Type': 'UINT32'},
            {'Name': 'Mystery', 'Type': 'SOME_VENDOR_UNION'},
            {'Name': 'After', 'Type': 'UINT32'}]}])
    laid = br.struct_layout('ODD_BLOCK', unsizable, {})
    check('a member of unknown size stops the layout',
          laid['size'] is None and 'Mystery' in laid['stopped'], str(laid))
    check('the fields before it are still placed',
          [p for p, _o, _s in laid['fields']] == ['Known'],
          'their offsets are certain; nothing after it is')
    check('and nothing after it can be named',
          br.field_at(laid['fields'], 8, 4) is None,
          'an offset resolved through a guessed size names the wrong field with full '
          'confidence, which is worse than naming none')
    check('a type the campaign never recorded stops it too',
          br.struct_layout('NOT_RECORDED', types, {})['size'] is None)
    check('and it is not guessed at a pointer width',
          br.type_extent('SOME_VENDOR_UNION', {}, {}) is None,
          'eight bytes is the most common answer and the wrong one often enough that '
          'every offset after such a member would be a fiction')
    # A cyclic alias map is a real shape -- scalar_choice_check.py carries the case. Caught
    # here rather than left to recurse, so the failure is this line and not a traceback.
    try:
        cyclic = br.type_extent('A', {}, {'A': 'B', 'B': 'A'})
    except RecursionError:
        cyclic = 'recursed past the interpreter limit'
    check('a cyclic alias map terminates', cyclic is None, str(cyclic))

    class _Join(br.CommBufferJoin):
        """A join over layouts built here, so these cases need no campaign directory.

        The real class stores a LIST of candidate blocks per handler, because a handler
        that declares its buffer VOID * can cast it to more than one type; singles are
        normalised here so a fixture stays readable. `via` defaults to 'declared', which
        is what a handler with a resolved parameter block has.
        """

        def __init__(self, handlers, why=''):
            self.handlers, self.why = {}, why
            for name, blocks in handlers.items():
                blocks = blocks if isinstance(blocks, list) else [blocks]
                for block in blocks:
                    block.setdefault('via', 'declared')
                self.handlers[name] = blocks

    join = _Join({'RWVariableHandler': br.struct_layout('RW_VARIABLE_INFO', types, aliases)})
    said = join.describe(OFFSET_IN, 2)
    check('the rendered join names the handler, the type, the field and its extent',
          'RWVariableHandler' in said and 'RW_VARIABLE_INFO.VarGuid.Data2' in said
          and '0x14' in said and 'byte' in said, said)
    check('and the handler is what a narrowed caller list keeps',
          join.handler_names(OFFSET_IN, 2) == ('RWVariableHandler',),
          str(join.handler_names(OFFSET_IN, 2)))

    # One campaign drives every handler it found, so several blocks can have something at
    # one offset. A 256-byte payload array CONTAINS almost any read; a two-byte field that
    # starts exactly there is what a two-byte read of that field looks like. Offering both
    # puts the answer next to a handler that has nothing to do with it.
    spi = br._types_from_json([
        {'TypeName': 'SPI_COMM_HEADER', 'File': 'OvmfPkg/SmmSpi/SmmSpi.h', 'Fields': [
            {'Name': 'Function', 'Type': 'UINTN'},
            {'Name': 'Address', 'Type': 'UINT32'},
            {'Name': 'ByteCount', 'Type': 'UINT32'},
            {'Name': 'Buffer', 'Type': 'UINT8[256]'}]}])
    two = _Join({'RWVariableHandler': br.struct_layout('RW_VARIABLE_INFO', types, aliases),
                 'SmmSpiHandler': br.struct_layout('SPI_COMM_HEADER', spi, {})})
    check('a block that merely contains the offset loses to one that fits it exactly',
          two.handler_names(OFFSET_IN, 2) == ('RWVariableHandler',),
          f'{two.handler_names(OFFSET_IN, 2)}: SPI_COMM_HEADER.Buffer spans payload '
          f'0x10..0x10F and would match nearly any read')
    # ... and where nothing fits exactly, every block that could hold it is offered. Both
    # of these have a payload array spanning payload offset 0x80, and picking one would be
    # a claim about which handler ran that nothing in a report says.
    check('with no exact fit anywhere, every candidate block is offered',
          two.handler_names(COMM_AT + 0x80, 2) == ('RWVariableHandler', 'SmmSpiHandler'),
          f'{two.handler_names(COMM_AT + 0x80, 2)}: RW_VARIABLE_INFO.Data and '
          f'SPI_COMM_HEADER.Buffer both span it, and narrowing to one would be a guess')
    header = join.describe(0x04, 2)
    check('an offset inside the message header is named as the header',
          'EFI_SMM_COMMUNICATE_HEADER.HeaderGuid.Data2' in header, header)
    check('and it is not offered as a payload field',
          join.handler_names(0x04, 2) == (), str(join.handler_names(0x04, 2)))
    past = join.describe(0x18 + 0x4E8, 2)
    check('an offset no block has says so, and names the blocks it tried',
          'no field at payload offset 0x4E8' in past and 'RWVariableHandler' in past, past)
    empty = _Join({}, 'no smi-function-guid-map.json in the campaign')
    bare = empty.describe(OFFSET_IN, 2)
    check('a campaign with no handler layout says that, and invents no field',
          'no smi-function-guid-map.json' in bare and 'VarGuid' not in bare, bare)

    print('and a handler that declares its buffer VOID * still resolves its field')
    # The gap this section exists for. RWVariableHandler -- the handler EVAL-1's injected
    # bugs live in -- records Type 'void *' in smi-function-guid-map.json, because it takes
    # CommBuffer as VOID * and casts it inside the body. void has no fields, so the join
    # had nothing to say about precisely the handler the headline finding is about, and
    # answered with whichever OTHER handler's block happened to span the offset.
    #
    # The cast is already recorded. bugs.md's "derived from" column prints it for this very
    # campaign, straight out of smi-call-edges.json.
    REAL_CAST = ('(VOID *)((CHAR16 *)((RW_VARIABLE_INFO *)CommBuffer)->Data '
                 '+ CommData->Offset)')
    edges = [{'EnclosingFunction': 'RWVariableHandler',
              'EnclosingFile': '/workspace/tmp/edk2/OvmfPkg/RWVariable/RWVariable.c',
              'Function': 'SmmSetVariable', 'Service': 'protocol', 'CallOrder': 4,
              'Arguments': {
                  'Arg_0': {'data_type': 'CHAR16 *', 'variable': '__PROTOCOL__',
                            'usage': 'VarName',
                            'assignment': '(CHAR16 *)CommData->Data'},
                  'Arg_4': {'data_type': 'void *', 'variable': 'DestBuffer',
                            'usage': 'DestBuffer', 'assignment': REAL_CAST}}}]
    casts = br.comm_buffer_casts(edges)
    check('the block type is recovered from the cast on CommBuffer',
          casts.get('RWVariableHandler') == ['RW_VARIABLE_INFO'], str(casts))
    check('the outer casts in the same expression are not taken for it',
          'VOID' not in casts.get('RWVariableHandler', [])
          and 'CHAR16' not in casts.get('RWVariableHandler', []),
          f'{casts}: (VOID *) and (CHAR16 *) are both followed by "(" where a target '
          f'identifier has to be, and (CHAR16 *)CommData->Data casts the local copy')
    check('a cast of the size parameter is not taken for the buffer',
          br.comm_buffer_casts(
              [{'EnclosingFunction': 'H',
                'Arguments': {'A': {'assignment': '(SOME_BLOCK *)CommBufferSize'}}}]) == {},
          'the two names differ by a suffix')
    check('an expression naming no handler is ignored',
          br.comm_buffer_casts(
              [{'EnclosingFunction': '',
                'Arguments': {'A': {'assignment': REAL_CAST}}}]) == {})

    # End to end: the map says void *, and the join still names the field.
    with tempfile.TemporaryDirectory() as camp:
        def put(name, data):
            with open(os.path.join(camp, name), 'w') as handle:
                json.dump(data, handle)

        recorded = [
            {'TypeName': 'GUID', 'File': 'MdePkg/Include/Base.h', 'Fields': [
                {'Name': 'Data1', 'Type': 'UINT32'}, {'Name': 'Data2', 'Type': 'UINT16'},
                {'Name': 'Data3', 'Type': 'UINT16'},
                {'Name': 'Data4', 'Type': 'UINT8[8]'}]},
            {'TypeName': 'RW_VARIABLE_INFO',
             'File': 'OvmfPkg/RWVariable/RWVariable.h', 'Fields': [
                {'Name': 'Status', 'Type': 'EFI_STATUS'},
                {'Name': 'Signature', 'Type': 'UINT32'},
                {'Name': 'AccessType', 'Type': 'UINT32'},
                {'Name': 'VarGuid', 'Type': 'EFI_GUID'},
                {'Name': 'Attributes', 'Type': 'UINT32'},
                {'Name': 'VariableNameSize', 'Type': 'UINTN'},
                {'Name': 'Offset', 'Type': 'UINTN'},
                {'Name': 'Data', 'Type': 'UINT8[1024]'}]},
        ]
        put('types.json', recorded)
        put('aliases.json', {'EFI_STATUS': 'RETURN_STATUS', 'RETURN_STATUS': 'UINTN',
                             'UINTN': 'UINT64', 'EFI_GUID': 'GUID'})
        put('smi-function-guid-map.json',
            {'RWVariableHandler': {'Type': 'void *', 'Guid': 'gRwVariableGuid'}})
        put('smi-call-edges.json', edges)
        voidstar = br.CommBufferJoin(camp)
        check('a void * handler gets a layout anyway',
              [b['type'] for b in voidstar.handlers.get('RWVariableHandler', [])]
              == ['RW_VARIABLE_INFO'], str(voidstar.handlers))
        check('and it is laid out at the recorded size',
              voidstar.handlers['RWVariableHandler'][0]['size'] == 0x438,
              str(voidstar.handlers['RWVariableHandler'][0]['size']))
        recovered = voidstar.describe(OFFSET_IN, 2)
        check('so the field at offset 0x2C is named after all',
              'RW_VARIABLE_INFO.VarGuid.Data2' in recovered
              and 'payload offset 0x14' in recovered, recovered)
        check('and the row says the block came from a cast, not a declaration',
              'recovered from the cast' in recovered, recovered)
        check('a declared handler is not annotated that way',
              'recovered from the cast' not in join.describe(OFFSET_IN, 2),
              join.describe(OFFSET_IN, 2))

        # A real declared type must NOT be replaced by a cast the body also performs:
        # the declaration is what the analyser resolved and what the harness sends.
        put('smi-function-guid-map.json',
            {'RWVariableHandler': {'Type': 'QUERY_VARIABLE_INFO *'}})
        put('types.json', recorded + [
            {'TypeName': 'QUERY_VARIABLE_INFO', 'File': 'x.h', 'Fields': [
                {'Name': 'Attributes', 'Type': 'UINT32'},
                {'Name': 'MaximumVariableStorageSize', 'Type': 'UINTN'}]}])
        declared = br.CommBufferJoin(camp)
        check('a handler with a declared block keeps it over its own cast',
              [b['type'] for b in declared.handlers['RWVariableHandler']]
              == ['QUERY_VARIABLE_INFO'], str(declared.handlers))

        # Two distinct casts: both are offered, because choosing one would be a guess.
        put('smi-function-guid-map.json', {'RWVariableHandler': {'Type': 'void *'}})
        put('types.json', recorded + [
            {'TypeName': 'OTHER_BLOCK', 'File': 'y.h', 'Fields': [
                {'Name': 'Code', 'Type': 'UINT64'},
                {'Name': 'Flag', 'Type': 'UINT16'}]}])
        put('smi-call-edges.json', edges + [
            {'EnclosingFunction': 'RWVariableHandler',
             'Arguments': {'Arg_0': {'assignment': '(OTHER_BLOCK *)CommBuffer'},
                           # no fields recorded for this one, so it drops out by itself
                           'Arg_1': {'assignment': '(UINT8 *)CommBuffer'}}}])
        several = br.CommBufferJoin(camp)
        check('several distinct casts are all offered',
              [b['type'] for b in several.handlers['RWVariableHandler']]
              == ['RW_VARIABLE_INFO', 'OTHER_BLOCK'], str(several.handlers))
        # Asserted on the filter itself, not only on the result. Checking the result
        # alone passes whenever anything earlier in __init__ short-circuited the cast
        # loop, which is a pass for the wrong reason.
        laid_uint8 = br.CommBufferJoin._lay('UINT8', br._types_from_json(recorded), {},
                                            'cast')
        check('and a cast to something with no recorded fields is dropped',
              laid_uint8 is None
              and 'UINT8' not in [b['type'] for b in several.handlers['RWVariableHandler']],
              f'{laid_uint8}: a byte-pointer cast is not a parameter block, and it falls '
              f'out by having no fields rather than by being on a list of spellings')
        # Payload 0x0 for four bytes: RW_VARIABLE_INFO.Status and OTHER_BLOCK.Code are
        # both eight-byte members starting there, so neither is an exact fit and both are
        # offered rather than one chosen.
        both = several.describe(COMM_AT + 0x0, 4)
        check('an offset both casts cover names both',
              'RW_VARIABLE_INFO' in both and 'OTHER_BLOCK' in both, both)
        check('but the handler is named once, however many of its blocks match',
              several.handler_names(COMM_AT + 0x0, 4) == ('RWVariableHandler',),
              f'{several.handler_names(COMM_AT + 0x0, 4)}: this list narrows the caller '
              f'hint, and a handler repeated once per candidate block would weight it')

    # And the same thing against the campaign the finding came from, when it is here. This
    # is corroboration, not the assertion: the directory is outside the repository, so in
    # CI there is nothing to read and the fixture above is what runs.
    real = os.environ.get('FWSAN_CAMPAIGN',
                          '/home/gl055/fuzzuer-eval1/42933720452/campaigns/DiscoveredSmi')
    if os.path.isdir(real):
        live = br.CommBufferJoin(real)
        said = live.describe(OFFSET_IN, 2)
        check('the real campaign resolves offset 0x2C to VarGuid.Data2',
              'RWVariableHandler' in said
              and 'RW_VARIABLE_INFO.VarGuid.Data2' in said
              and 'payload offset 0x14' in said, said)
        check('and it did it through the cast, as that map records void *',
              'recovered from the cast' in said, said)
        # Different offsets must give different answers. Before the cast recovery both of
        # these came back as QUERY_VARIABLE_INFO.RemainingVariableStorageSize, which is
        # how a join that resolves nothing looks like one that resolves everything.
        check('a different offset gives a different field',
              live.describe(0x28, 8) != said
              and 'RemainingVariableStorageSize' in live.describe(0x28, 8),
              live.describe(0x28, 8))
        check('and a third one differs again',
              live.describe(0x40, 2) != said
              and 'VariableNameSize' in live.describe(0x40, 2),
              live.describe(0x40, 2))
    else:
        print(f'  note  {real} is not here, so only the fixture ran')

    print('and the row a developer reads carries all of it')
    parsed.field_note = said
    parsed.first_site = 'MdePkg/Library/BaseLib/Unaligned.c:28'
    parsed.field_handlers = ('RWVariableHandler',)
    cluster = br.Cluster(parsed.group_key())
    cluster.add(parsed)
    rendered = cluster.detail()
    for want, why in (
            ('read of 2 bytes', 'the access'),
            (f'untrusted offset 0x{OFFSET_IN:X}', 'where in the caller\'s buffer'),
            ('RWVariableHandler', 'which handler'),
            ('RW_VARIABLE_INFO.VarGuid.Data2', 'which field'),
            ('payload offset 0x14', 'where the field is'),
            ('Unaligned.c:28', 'the first read\'s source location'),
            ('Unaligned.c:32', 'the re-read\'s source location'),
            ('TOCTOU', 'why it matters'),
            ('between the read that validated', 'the one sentence that explains the class'),
    ):
        check(f'the detail gives {why}', want in rendered, rendered)
    check('it stays one line, for a table cell and a console row',
          '\n' not in rendered and '|' not in rendered, rendered[:80])
    # A row with no untrusted buffer behind it reads exactly as it did before.
    plain = br.Report({'Phase': 'fuzz', 'Module': 'VariableSmm.efi', 'File': 'x.c',
                       'Line': '1', 'Asan Msg': 'heap-buffer-overflow',
                       'ErrorType': 'asan', 'Count': '1',
                       'Message': 'address 0x1000, size 0x4, is_write 0x1, ip 0x2000'},
                      'DiscoveredSmi')
    flat = br.Cluster(plain.group_key())
    flat.add(plain)
    check('a class with no untrusted buffer renders as it always did',
          flat.detail() == 'write of 4 bytes at 0x1000', flat.detail())

    print('and the caller list is narrowed by the offset, not pasted on every row')
    crossings = [
        {'handler': 'RWVariableHandler', 'service': 'mSmmVariable',
         'function': 'SmmSetVariable'},
        {'handler': 'SmmSpiHandler', 'service': 'mSpiProtocol', 'function': 'Execute'},
    ]
    both = br.likely_callers('MdePkg/Library/BaseLib/Unaligned.c', 'VariableSmm.efi',
                             crossings)
    narrowed = br.likely_callers('MdePkg/Library/BaseLib/Unaligned.c', 'VariableSmm.efi',
                                 crossings, ('RWVariableHandler',))
    check('every crossing is offered when the offset names no handler', len(both) == 2,
          str(both))
    check('only the handler whose block has a field there survives',
          narrowed == ['RWVariableHandler -> mSmmVariable->SmmSetVariable'], str(narrowed))
    check('a cluster carries the handlers its reports named',
          cluster.field_handlers() == ('RWVariableHandler',),
          str(cluster.field_handlers()))
    check('a cluster of another class narrows nothing',
          flat.field_handlers() == (),
          'empty means do not narrow, so every other class keeps what it had')

    # AsanReportFirmwareClass is declared in NO header, so every caller writes its own
    # prototype and nothing made them agree. FwSanDxe.c's omitted `Detail`, the second
    # parameter, so every argument shifted by one: the reported address landed where a
    # CONST CHAR8 * was expected and the banner walked it as a string, Addr and Size
    # arrived as 0, IsWrite got the return address, and Ip -- the dedup key and the ip in
    # the crashes.csv row -- was never passed. It executed: results/bench-scoreboard.md
    # scores `variable-size-trusted` PASS off a line FwSanReport prints immediately before
    # making that call. Compare every hand-written prototype against the definition rather
    # than trusting them to match.
    params = re.compile(r'AsanReportFirmwareClass\s*\(\s*(?P<params>[^)]*?)\)\s*[;{]', re.S)
    def signature(text):
        """[(type, name)] of the first AsanReportFirmwareClass parameter list in text."""
        hit = params.search(text)
        if not hit:
            return None
        out = []
        for piece in hit.group('params').split(','):
            words = piece.replace('*', ' * ').split()
            words = [w for w in words if w not in ('IN', 'OUT', 'OPTIONAL')]
            if words:
                out.append((' '.join(words[:-1]), words[-1]))
        return out

    want = signature(open(os.path.join(ROOT, 'uefi_asan', 'AsanLib', 'Asan.c')).read())
    check('the definition still takes Detail second',
          want is not None and len(want) >= 2 and want[1][1] == 'Detail',
          str(want))
    callers = [
        os.path.join('eval_source', 'edk2', 'MdeModulePkg', 'Universal', 'FwSanDxe',
                     'FwSanDxe.c'),
        os.path.join('uefi_asan', 'AsanMemoryLib', 'AsanHelper.c'),
        os.path.join('uefi_asan', 'AsanMemoryLibRepStr', 'AsanHelper.c'),
    ]
    seen = 0
    for rel in callers:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        seen += 1
        got = signature(open(path, errors='replace').read())
        check(f'{rel} declares the same parameters as the definition',
              got == want, f'{got} != {want}')
    check('every known caller was compared', seen == len(callers),
          f'{seen} of {len(callers)} -- a caller that moved is a caller nothing checks')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
