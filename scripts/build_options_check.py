#!/usr/bin/env python3
"""Does --extra-build-options turn a caller's entry into a valid DSC line?

The input accepts two shapes: a complete tools_def style assignment, which goes through
untouched, and a bare flag list, which gets attached to CLANGSAN's CC_FLAGS. Telling them
apart looked trivial and was not. The first version asked whether the entry contained an
'=' -- and most compiler flags do, so `-fno-sanitize=pointer-overflow` was written into
the DSC verbatim as though it were an assignment:

    OvmfPkgX64.dsc(1415): error 3000: '-Wno-cast-calling-convention -Wno-error -fno-s...

That failed a firmware build in CI, which is an eight minute round trip to learn something
a table of five strings settles in a second.
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fuzz_edk2 import apply_build_options  # noqa: E402

PREFIX = '*_CLANGSAN_*_CC_FLAGS = '

CASES = [
    # entry,                                              expected line
    ('-Wno-error', PREFIX + '-Wno-error'),
    # The one that broke a build: a flag list whose last element carries an '='.
    ('-Wno-cast-calling-convention -Wno-error -fno-sanitize=pointer-overflow',
     PREFIX + '-Wno-cast-calling-convention -Wno-error -fno-sanitize=pointer-overflow'),
    ('-fno-sanitize=pointer-overflow', PREFIX + '-fno-sanitize=pointer-overflow'),
    ('-mllvm -asan-stack=0', PREFIX + '-mllvm -asan-stack=0'),
    # Genuine assignments, which must NOT be prefixed.
    ('*_CLANGSAN_*_CC_FLAGS = -Wfoo', '*_CLANGSAN_*_CC_FLAGS = -Wfoo'),
    ('*_CLANGSAN_*_DLINK_FLAGS = -z muldefs',
     '*_CLANGSAN_*_DLINK_FLAGS = -z muldefs'),
    ('DEBUG_CLANGSAN_X64_CC_FLAGS = -O1', 'DEBUG_CLANGSAN_X64_CC_FLAGS = -O1'),
]


def main():
    bad = 0
    root = tempfile.mkdtemp(prefix='build-options-')
    try:
        dsc_dir = os.path.join(root, 'OvmfPkg')
        os.makedirs(dsc_dir)
        dsc = os.path.join(dsc_dir, 'OvmfPkgX64.dsc')

        for entry, want in CASES:
            open(dsc, 'w').write('[Defines]\n')
            got = apply_build_options(root, entry, report=lambda _m: None)
            line = got[0].strip() if got else '<nothing>'
            ok = line == want
            bad |= not ok
            print(f"  [{'OK' if ok else 'FAIL'}] {entry[:56]:<58} -> {line[:58]}")
            if not ok:
                print(f"         wanted: {want}")
            # Whatever it produced must sit under a [BuildOptions] header, or the DSC
            # parser will read it as part of whatever section came before.
            body = open(dsc).read()
            if got and '[BuildOptions]' not in body:
                print('  [FAIL] the appended lines are not under a [BuildOptions] header')
                bad = 1

        # Several entries, one per line, is the documented shape.
        open(dsc, 'w').write('[Defines]\n')
        many = apply_build_options(root, '-Wno-error\n*_CLANGSAN_*_DLINK_FLAGS = -z x\n',
                                   report=lambda _m: None)
        ok = len(many) == 2
        bad |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] two entries on two lines -> {len(many)} line(s)")

        # Nothing asked for must change nothing.
        open(dsc, 'w').write('[Defines]\n')
        before = open(dsc).read()
        none = apply_build_options(root, '', report=lambda _m: None)
        ok = none == [] and open(dsc).read() == before
        bad |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] empty input is a no-op")

        # A tree without that DSC must be reported, not crashed on.
        shutil.rmtree(dsc_dir)
        said = []
        missing = apply_build_options(root, '-Wno-error', report=said.append)
        ok = missing == [] and any('not in this tree' in m for m in said)
        bad |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] a missing DSC is reported, not fatal")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return bad


if __name__ == '__main__':
    sys.exit(main())
