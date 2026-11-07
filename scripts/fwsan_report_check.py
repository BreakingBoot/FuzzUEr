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
"""

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASAN = os.path.join(ROOT, 'uefi_asan', 'AsanLib', 'Asan.c')
HELPERS = [os.path.join(ROOT, 'uefi_asan', lib, 'AsanHelper.c')
           for lib in ('AsanMemoryLib', 'AsanMemoryLibRepStr')]
BENCH = os.path.join(ROOT, 'scripts', 'bench_cases.py')

FAILURES = []

STUB = '''
typedef unsigned long long UINT64; typedef unsigned long UINTN;
typedef unsigned int UINT32; typedef unsigned char UINT8;
typedef char CHAR8; typedef unsigned char BOOLEAN; typedef void VOID;
#define IN
#define OUT
#define CONST const
#define STATIC static
#define TRUE 1
#define FALSE 0
#define NULL ((void*)0)
void SerialOutput(const CHAR8 *s);
void Num2Str64bit(UINTN v, CHAR8 *o);
static BOOLEAN asan_inited = TRUE;
static BOOLEAN asan_is_deactivated = FALSE;
'''

DRIVER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char LOG[1 << 20];
static int LOGN;
void SerialOutput(const char *s) { LOGN += snprintf(LOG+LOGN, sizeof LOG - LOGN, "%s", s); }
void Num2Str64bit(unsigned long v, char *o) { snprintf(o, 19, "0x%016lx", v); }
void AsanReportFirmwareClass(const char *, const char *, unsigned long, unsigned long,
                             unsigned long, unsigned long);
static int count(const char *needle) {
    int n = 0; const char *p = LOG;
    while ((p = strstr(p, needle)) != NULL) { n++; p++; }
    return n;
}
int main(int argc, char **argv) {
    (void)argc;
    int ips  = atoi(argv[1]);
    int hits = atoi(argv[2]);
    for (int h = 0; h < hits; h++)
        for (int i = 0; i < ips; i++)
            AsanReportFirmwareClass("double-fetch", "untrusted word read twice in one call",
                                    0xdead, 8, 0, 0x1000 + i);
    printf("banners %d\n",   count("FWSAN: double-fetch -- "));
    printf("reports %d\n",   count("bug_descr=fwsan-double-fetch"));
    printf("notes %d\n",     count("FWSAN: suppressed ("));
    printf("lines %d\n",     count("\n"));
    return 0;
}
'''


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


def build_and_run(src, ips, hits):
    """Compile the real report path against a stub and drive it."""
    tables = src[src.index('#define ASAN_FWSAN_IP_SEEN'):src.index('\nVOID\nAsanReportOutline')]
    unit = (STUB + tables
            + definition(src, 'AsanEmitReport (\n  IN CONST CHAR8  *bug_descr,')
            + definition(src, 'AsanReportFirmwareClass (\n  IN CONST CHAR8  *BugDescr,'))
    with tempfile.TemporaryDirectory() as work:
        cfile = os.path.join(work, 'unit.c')
        dfile = os.path.join(work, 'drive.c')
        exe = os.path.join(work, 'drive')
        open(cfile, 'w').write(unit)
        open(dfile, 'w').write(DRIVER)
        built = subprocess.run(
            ['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-o', exe, cfile, dfile],
            capture_output=True, text=True)
        if built.returncode != 0:
            return None, built.stderr.strip().splitlines()[:4]
        ran = subprocess.run([exe, str(ips), str(hits)], capture_output=True, text=True)
        got = dict(re.findall(r'(\w+) (\d+)', ran.stdout))
        return {k: int(v) for k, v in got.items()}, None


def main():
    print('A firmware-sanitizer detection cannot be announced without being reported')
    src = open(ASAN, encoding='utf-8').read()

    # --- structure: the banner lives in exactly one place ---
    # One class banner in the file, and it has to be the one inside the report function.
    # Counting zero would be wrong -- the banner still has to be emitted, just not before
    # the guards -- so this checks WHERE it is rather than whether it exists.
    #
    # Located inside the extracted DEFINITION, not by offsets into the file: the signature
    # also matches the forward declaration near the top, and a window anchored there spans
    # the wrong region entirely.
    report = definition(src, 'AsanReportFirmwareClass (\n  IN CONST CHAR8  *BugDescr,')
    banners = len(re.findall(r'SerialOutput \("FWSAN: (?!suppressed)', src))
    in_report = len(re.findall(r'SerialOutput \("FWSAN: (?!suppressed)', report))
    check('the class banner is printed only from the report path',
          banners == 1 and in_report == 1,
          f'{banners} banner(s) in Asan.c, {in_report} inside AsanReportFirmwareClass')
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

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
