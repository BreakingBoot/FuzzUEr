#!/usr/bin/env python3
"""Assert the dxe harness timing is wired end to end.

The dxe timing exists because the application harness is a boot option, and BDS signals
gEfiEndOfDxeEventGroupGuid before it launches one -- so every SMI handler that latches on
EndOfDxe is unreachable from it. See eval1's SmmSpi (whole dispatch), FaultTolerantWriteSmm
(write path), VariableSmm (three command codes) and Tcg2Smm (two).

Wiring it is five separate places, and four of them fail SILENTLY in the way that is
hardest to read: the campaign builds, boots, and reports that the guest never reached the
harness. That is the same symptom as a missing protocol, a bad depex and a hung boot. So
each one is asserted here rather than discovered in a 45-minute campaign.

Run: python3 scripts/dxe_timing_check.py
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIRNESS = os.path.join(HERE, 'firness.py')
MAKE_ESP = os.path.join(HERE, 'make_esp.sh')

FAILED = 0
PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def body(path, name):
    """The source of one function, from its def to the next top-level def."""
    text = open(path, encoding='utf-8').read()
    start = text.find(f'\ndef {name}(')
    if start < 0:
        return ''
    nxt = text.find('\ndef ', start + 1)
    return text[start:nxt if nxt > 0 else len(text)]


def main():
    print('the dxe harness timing is wired end to end')
    src = open(FIRNESS, encoding='utf-8').read()

    # 1. The rebuild exists and does the three things that make it a rebuild and not a
    #    no-op: place the harness, build the platform, restage the .fd.
    rebuild = body(FIRNESS, 'rebuild_ovmf_with_harness')
    check('rebuild_ovmf_with_harness exists', bool(rebuild))
    check('it places the harness in the FV',
          'fv_harness.place(' in rebuild,
          'without place() the DSC and FDF are untouched, the harness is not in the '
          'volume, and the boot runs to BDS and finds nothing')
    # Scoped to the -p argument, not the whole body: the docstring names Firness.dsc on
    # purpose, to say what this function replaces. A whole-body grep failed on that.
    built = re.findall(r'-p\s+(\S+\.dsc)', rebuild)
    check('it builds OvmfPkgX64, not the standalone Firness.dsc',
          built == ['OvmfPkg/OvmfPkgX64.dsc'],
          f'the -p arguments in this function are {built}; building Firness.dsc '
          f'produces a UEFI application, and a DXE_DRIVER has to be linked into the '
          f'platform to be dispatched')
    check('it restages OVMF_CODE.fd over the one the fuzzer boots',
          'QEMU_OVMF_CODE' in rebuild and 'shutil.copyfile' in rebuild,
          'the .fd in /workspace/qemu_fw was copied in when the image was built and '
          'holds a DXEFV with no harness in it -- without the copy the rebuild is '
          'invisible to the campaign')
    check('it restages OVMF_VARS.fd too',
          'QEMU_OVMF_VARS' in rebuild,
          'a VARS built against a different FD_SIZE_IN_KB does not match the CODE')
    check('it does NOT clear Build/',
          'rm -rf' not in rebuild,
          'clearing Build/ turns an incremental relink into a full platform build on '
          'every campaign; that is compile_ovmf\'s business, where bear needs it')
    check('it uses the same defines as the firmware the campaign boots',
          'FIRNESS_ANALYSIS_DEFINES' in rebuild,
          'a different ASAN_SCOPE or FD_SIZE_IN_KB links a firmware that is not the one '
          'the image was measured on -- it builds and boots, so nothing says so')
    # EVERY exit, not just one. A mutation that turned a single `return log, False` into
    # a `raise` left the others in place and this passed when it was written as "is there
    # at least one such return".
    returns = re.findall(r'^\s+return\s+(.*)$', rebuild, re.M)
    pairs = [r for r in returns if re.match(r"(log|'')\s*,\s*(True|False)", r.strip())]
    check('every exit from the rebuild returns (log, ok)',
          bool(returns) and len(pairs) == len(returns),
          f'{len(returns)} return(s), {len(pairs)} of them a (log, ok) pair: '
          f'{[r for r in returns if r not in pairs]}')
    check('the rebuild never raises',
          not re.search(r'^\s+raise\b', rebuild, re.M),
          'compile_harness returns a log string and its caller inspects it; a raise here '
          'is an unhandled traceback in the middle of a campaign, with the generated '
          'harness already on disk and nothing saying the build is what failed')

    # 2. compile_harness dispatches to it.
    compile_harness = body(FIRNESS, 'compile_harness')
    check('compile_harness takes the dxe path',
          "HARNESS_TIMING == 'dxe'" in compile_harness
          and 'rebuild_ovmf_with_harness(' in compile_harness,
          'otherwise the dxe timing generates a DXE_DRIVER and then builds it as the '
          'old standalone application anyway')
    check('the dxe path returns before the Firness.dsc build',
          compile_harness.index("HARNESS_TIMING == 'dxe'")
          < compile_harness.index('build -a X64 -b DEBUG -p Firness/Firness.dsc'),
          'a dispatch placed after the old build runs both')

    # 3. The artefact that proves the harness built is the .fd, not Firness.efi.
    check('the post-compile check looks at the .fd under the dxe timing',
          "built_artefact = QEMU_OVMF_CODE if HARNESS_TIMING == 'dxe' else HARNESS_IMAGE"
          in src,
          'Firness.efi is never written under the dxe timing, so checking for it fails '
          'every single run -- and the message blames the harness build, which worked')
    check('the fuzz-stage gate looks at the .fd too',
          "needed = QEMU_OVMF_CODE if HARNESS_TIMING == 'dxe' else HARNESS_IMAGE" in src,
          'a second gate on Firness.efi refuses to fuzz a campaign that built fine')
    check('the staleness warning looks at the .fd too',
          "harness = QEMU_OVMF_CODE if HARNESS_TIMING == 'dxe' else HARNESS_IMAGE" in src,
          'this warning exists to catch fuzzing a harness built for another protocol; '
          'pointed at a file that never exists it returns silently and catches nothing')

    # 4. The ESP. There is no application to put on it.
    fuzzer = body(FIRNESS, 'run_qemu_fuzzer')
    check('the ESP is built empty under the dxe timing',
          "'--empty' if HARNESS_TIMING == 'dxe'" in fuzzer,
          'passing the missing Firness.efi makes make_esp.sh exit 2 with "no such '
          'file", three stages after the build succeeded')
    esp = open(MAKE_ESP, encoding='utf-8').read()
    check('make_esp.sh accepts --empty', '--empty' in esp)
    check('make_esp.sh still asserts BOOTX64 landed in the normal case',
          "grep -qi 'BOOTX64'" in esp)
    check('make_esp.sh asserts BOOTX64 is ABSENT under --empty',
          re.search(r'--empty was asked for but BOOTX64', esp) is not None,
          'an --empty that picked up a stale BOOTX64 from a reused raw file boots an '
          'old harness and looks exactly like a dxe harness that worked')

    # 5. The timing is rejected where it cannot work.
    check('dxe is rejected on a non-qemu backend',
          "HARNESS_TIMING == 'dxe' and args.backend != 'qemu'" in src,
          'Simics boots its own checkpoint, so the relinked .fd is never read: the '
          'campaign reports zero iterations and nothing says why')
    check('an unknown timing is rejected',
          "HARNESS_TIMING not in ('application', 'dxe')" in src,
          'a typo in the workflow env silently falls back to application timing and the '
          'latched handlers stay unreachable -- the run looks like a clean negative')
    check('the generator is told the timing',
          '--harness-timing' in src,
          'without it the generator emits UEFI_APPLICATION and the driver is never '
          'dispatched')

    # 6. make_esp.sh --empty actually works, if the tools are here.
    tools = all(subprocess.run(['sh', '-c', f'command -v {t}'],
                               capture_output=True).returncode == 0
                for t in ('mkfs.vfat', 'mmd', 'mcopy', 'mdir'))
    if not tools:
        print('  [skip] make_esp.sh --empty not run: dosfstools/mtools are not installed')
    else:
        with tempfile.TemporaryDirectory() as work:
            out = os.path.join(work, 'esp.img')
            made = subprocess.run(['bash', MAKE_ESP, '--empty', out, '16'],
                                  capture_output=True, text=True)
            check('make_esp.sh --empty builds an image',
                  made.returncode == 0 and os.path.isfile(out),
                  f'{made.stdout}{made.stderr}')
            if os.path.isfile(out):
                listed = subprocess.run(['mdir', '-i', out, '::/EFI/BOOT'],
                                        capture_output=True, text=True)
                check('the --empty image has an EFI/BOOT directory and no BOOTX64',
                      listed.returncode == 0
                      and 'BOOTX64' not in listed.stdout.upper(),
                      f'{listed.stdout}{listed.stderr}')
            missing = subprocess.run(
                ['bash', MAKE_ESP, os.path.join(work, 'nope.efi'),
                 os.path.join(work, 'b.img'), '16'], capture_output=True, text=True)
            # Defended twice on purpose: deleting the `[ -f "$EFI" ]` guard still fails,
            # because `stat -c %s` on a missing file breaks the size arithmetic under
            # `set -eu`. So this does not pin the guard, it pins the BEHAVIOUR -- which is
            # the thing that matters when --empty is added right beside it.
            check('a missing application is still an error',
                  missing.returncode != 0,
                  'the --empty branch must not swallow a genuinely missing harness')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
