"""Does the generated harness actually fuzz what it was asked to fuzz?

Two checks already exist and neither asks this. `check_generation.py` compiles the emitted
sources, so it catches a syntax or type error. `build_sweep.sh` links them with the real
toolchain, so it catches a missing declaration behind a warning. A harness can pass both
and still be wrong about the thing that matters: which protocol members it calls, and
whether the fuzzer reaches them.

That has gone wrong three times in ways nothing caught:

  * a member present in the evalset and absent from the harness -- the campaign reports
    clean because that code was never called
  * a dispatch switch with fewer arms than the protocol has members, so the later ones are
    unreachable at any input
  * an argument left as its declaration default, so the member is called with a constant
    forever and the iteration count measures the loop

So this reads the evalset request and the emitted C and compares them.

  python3 scripts/harness_check.py --spec eval_source/evalset_discovered/EfiHiiFont.txt \\
      --harness results/<run>/campaigns/EfiHiiFont/GeneratedHarnesses/<stamp>
  python3 scripts/harness_check.py --sweep results/<run>      # every campaign under it

Exit status is non-zero when a member is missing or unreachable. A member with no fuzzable
argument is reported and does NOT fail: some protocol members genuinely take only values
the harness must not invent -- a function pointer the firmware will call, an address -- and
for those a constant call is the correct behaviour, not a defect.
"""

import argparse
import glob
import os
import re
import sys

MEMBER = re.compile(r'^\s*g\w+Guid\s*:\s*(\w+)\s*$', re.M)
FUZZ_FN = re.compile(r'^Fuzz(\w+)\s*\(', re.M)
CASE = re.compile(r'^\s*case (\d+):', re.M)
CHOICES = re.compile(r'UINTN Choices = (\d+);')
READS = re.compile(r'ReadBytes\(Input,')


SPEC_HEADER = re.compile(r'//\s*from\s+(\S+\.h)')
FIELD = re.compile(r'^\s*([A-Za-z_]\w*)\s+%s\s*;', re.M)


def variadic_members(spec_path, edk2_roots):
    """Members whose declaration takes "..." -- which the generator is right to skip.

    A variadic member cannot be driven from a flat input buffer: the callee reads arguments
    the harness never pushed. EFI_PRINT2_PROTOCOL is the case that matters -- four of its
    ten members are variadic SPrint forms and the other six take a VA_LIST instead, so a
    check that demands all ten reports the generator's correct behaviour as a defect. This
    one did, before this function existed.

    Resolved through the header the spec names: field -> typedef -> parameter list.
    """
    text = read(spec_path)
    named = SPEC_HEADER.search(text)
    if not named:
        return set()
    header = None
    for root in edk2_roots:
        for base, _dirs, files in os.walk(root):
            if named.group(1) in files:
                header = os.path.join(base, named.group(1))
                break
        if header:
            break
    if not header:
        return set()

    body = read(header)
    found = set()
    for member in members_requested(spec_path):
        field = FIELD.search(body.replace('\r\n', '\n'), 0) if False else \
            re.search(r'^\s*([A-Za-z_]\w*)\s+' + re.escape(member) + r'\s*;', body, re.M)
        if not field:
            continue
        typedef = field.group(1)
        at = body.find('*%s)(' % typedef)
        if at < 0:
            continue
        end = body.find(');', at)
        if end > 0 and '...' in body[at:end]:
            found.add(member)
    return found


def read(path):
    try:
        with open(path, errors='replace') as handle:
            return handle.read().replace('\r\n', '\n')
    except OSError:
        return ''


def members_requested(spec_path):
    """The members the evalset asked for, in order."""
    return list(dict.fromkeys(MEMBER.findall(read(spec_path))))


def check(spec_path, harness_dir, edk2_roots=()):
    """One protocol. Returns (problems, notes, stats)."""
    want = members_requested(spec_path)
    harness_c = os.path.join(harness_dir, 'FirnessHarnesses.c')
    main_c = os.path.join(harness_dir, 'FirnessMain.c')
    body, main = read(harness_c), read(main_c)
    problems, notes = [], []

    if not body:
        # Distinct from "the harness is wrong": the generator produced nothing at all, which
        # firness.py already reports when it happens. Flagged here so a sweep summary cannot
        # count the campaign as checked, but named for what it is.
        return ['generator produced no harness (empty %s)'
                % os.path.basename(harness_dir)], [], {}
    if not want:
        return ['no members parsed from %s' % spec_path], [], {}

    have = set(FUZZ_FN.findall(body))
    missing = [m for m in want if m not in have]
    # A variadic member is correctly absent: the callee reads arguments the harness never
    # pushed, so there is nothing a flat input buffer can do with it.
    skipped = variadic_members(spec_path, edk2_roots) & set(missing)
    missing = [m for m in missing if m not in skipped]
    if skipped:
        notes.append('variadic, correctly not generated: %s' % ', '.join(sorted(skipped)))
    if missing:
        problems.append('requested but not generated: %s' % ', '.join(missing))

    # Extra Fuzz functions are not a problem in themselves -- the generator emits helpers
    # for members it reached through a call graph -- but they must still be dispatchable.
    cases = len(set(CASE.findall(main))) if main else 0
    choices = CHOICES.search(main)
    dispatch = int(choices.group(1)) if choices else cases
    reachable = min(cases, dispatch) if cases else dispatch

    generated = [m for m in want if m in have]
    if main and reachable < len(generated):
        problems.append('%d member(s) generated but the dispatch reaches only %d'
                        % (len(generated), reachable))

    # Per-member: does anything read the input before the call?
    for name in generated:
        start = body.find('Fuzz%s(' % name)
        if start < 0:
            continue
        end = body.find('\n}\n', start)
        chunk = body[start:end if end > 0 else len(body)]
        if not READS.search(chunk):
            notes.append('%s takes no fuzzable input -- every call is identical' % name)

    stats = dict(requested=len(want), generated=len(generated), reachable=reachable,
                 reads=len(READS.findall(body)))
    return problems, notes, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--spec', help='an evalset request file')
    parser.add_argument('--harness', help='a GeneratedHarnesses/<stamp> directory')
    parser.add_argument('--sweep', help='a run directory; check every campaign under it')
    parser.add_argument('--evalset', default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'eval_source', 'evalset_discovered'),
        help='where the request files live, for --sweep')
    parser.add_argument('--edk2', default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'eval_source', 'edk2'),
        help='an edk2 tree, so a member can be checked for being variadic before it is '
             'called missing')
    parser.add_argument('--quiet', action='store_true', help='only print problems')
    args = parser.parse_args()

    jobs = []
    if args.sweep:
        for campaign in sorted(glob.glob(os.path.join(args.sweep, 'campaigns', '*'))):
            name = os.path.basename(campaign)
            spec = os.path.join(args.evalset, name + '.txt')
            stamps = sorted(glob.glob(os.path.join(campaign, 'GeneratedHarnesses', '*')))
            if os.path.isfile(spec) and stamps:
                jobs.append((name, spec, stamps[-1]))
    elif args.spec and args.harness:
        jobs.append((os.path.basename(args.spec), args.spec, args.harness))
    else:
        sys.exit('pass --sweep, or both --spec and --harness')

    if not jobs:
        sys.exit('nothing to check: no campaign had both a request file and a harness')

    edk2_roots = [d for d in (args.edk2,) if d and os.path.isdir(d)]
    bad, noted, clean = 0, 0, 0
    for name, spec, harness in jobs:
        problems, notes, stats = check(spec, harness, edk2_roots)
        if problems:
            bad += 1
            print('  FAIL  %s' % name)
            for line in problems:
                print('          %s' % line)
        elif notes:
            noted += 1
            # The header and its notes travel together. Printing the notes while
            # suppressing the header put them under whichever protocol was last printed,
            # so a member of one protocol was reported against another -- and --quiet means
            # "only problems", which a note is not.
            if not args.quiet:
                print('  note  %-32s %d/%d member(s), %d read(s)'
                      % (name, stats.get('generated', 0), stats.get('requested', 0),
                         stats.get('reads', 0)))
                for line in notes:
                    print('          %s' % line)
        else:
            clean += 1
            if not args.quiet:
                print('  ok    %-32s %d member(s) all dispatchable, %d read(s)'
                      % (name, stats.get('generated', 0), stats.get('reads', 0)))

    print()
    print('%d checked: %d ok, %d with notes, %d FAILED' % (len(jobs), clean, noted, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
