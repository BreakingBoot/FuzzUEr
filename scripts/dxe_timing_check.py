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


def pcd_tuple(path, name):
    """The PCD strings from a module-level tuple, ignoring the comments between them.

    Each entry carries a long comment, and those comments contain apostrophes, so a
    single-quoted-string regex over the whole tuple matches comment fragments as well.
    Taking only the strings that look like a PCD assignment avoids parsing the file.
    """
    try:
        text = open(path, encoding='utf-8').read()
    except OSError:
        return ()
    start = text.find(f'\n{name} = (')
    if start < 0:
        return ()
    end = text.find('\n)', start)
    if end < 0:
        return ()
    return tuple(re.findall(r"'(g[A-Za-z0-9]+TokenSpaceGuid\.[^']+=[^']+)'",
                            text[start:end]))


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
    # The PCDs. This is the assertion run 42690509737 was missing: the relink built a
    # firmware without them, so the first ASSERT inside SMM CpuDeadLooped the vCPU, the
    # snapshot restore could not recover it, and a campaign that had done 246665
    # iterations on the pipeline's own firmware did 50.
    firness_pcds = pcd_tuple(FIRNESS, 'FIRMWARE_PCDS')
    shared_pcds = pcd_tuple(os.path.join(HERE, 'fuzz_edk2.py'), 'SHARED_PCDS')
    # The arguments are built from the tuple, so there is no literal PCD name in this
    # function to grep for. What has to hold is that every entry becomes a --pcd argument
    # AND that the result is interpolated into the build command -- a joined-but-unused
    # variable is exactly the shape of the defect this check exists for.
    joined = re.search(r"(\w+)\s*=\s*' '\.join\(\s*f'--pcd \{\w+\}'"
                       r"\s+for\s+\w+\s+in\s+FIRMWARE_PCDS\s*\)", rebuild)
    cmd = re.search(r"\n    cmd = \((.*?)\n    [a-z]", rebuild, re.S)
    check('the relink turns every firmware PCD into a --pcd argument',
          bool(firness_pcds) and joined is not None,
          'rebuild_ovmf_with_harness has to join FIRMWARE_PCDS into --pcd arguments; a '
          'firmware relinked without them deadloops in SMM on its first ASSERT and the '
          'campaign spends the rest of its budget timing out against a dead machine')
    check('and passes them to the build that links the platform',
          bool(joined) and bool(cmd) and '{%s}' % joined.group(1) in cmd.group(1)
          and 'OvmfPkg/OvmfPkgX64.dsc' in cmd.group(1),
          'the joined arguments are never interpolated into the build command line, so '
          'they have no effect at all')
    check('firness.py and fuzz_edk2.py pin the SAME PCDs',
          bool(shared_pcds) and firness_pcds == shared_pcds,
          f'FIRMWARE_PCDS is {firness_pcds} and SHARED_PCDS is {shared_pcds}; '
          f'ci.Dockerfile ships only firness.py into the campaign image so the list has '
          f'to be duplicated, which means it can drift -- the relinked firmware would '
          f'then differ from the one the pipeline measured and nothing would say so')
    # Both builds, not just the relink. compile_ovmf builds the tree that the relink then
    # links incrementally, so a PCD that appears only on the relink's command line has to
    # propagate through AutoGen into modules that are already compiled.
    analysis = body(FIRNESS, 'compile_ovmf')
    check('the analysis build pins them too',
          'FIRMWARE_PCDS' in analysis and '--pcd' in analysis
          and re.search(r"\{pcds\}", analysis) is not None,
          'compile_ovmf builds the tree rebuild_ovmf_with_harness relinks; if the two '
          'disagree about the PCDs the relink depends on edk2 propagating a changed '
          'FixedAtBuild value into every already-built module')
    mask = [p for p in firness_pcds if 'PcdDebugPropertyMask' in p]
    check('the mask it pins has the deadloop bit clear',
          len(mask) == 1 and not int(mask[0].split('=')[1], 16) & 0x20,
          f'PcdDebugPropertyMask is {mask}; bit 0x20 is '
          f'DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED, and an ASSERT that CpuDeadLoops '
          f'inside SMM wedges every core with interrupts off')
    check('and keeps the ASSERT bit set, so the finding survives',
          len(mask) == 1 and int(mask[0].split('=')[1], 16) & 0x01,
          'bit 0x01 is DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED; clearing it would silence '
          'the "ASSERT <file>(<line>)" line that guest_asserts() reads back, trading a '
          'located sev4 finding for nothing')
    check('it uses the same defines as the firmware the campaign boots',
          'firmware_defines(' in rebuild,
          'a different ASAN_SCOPE, FD_SIZE_IN_KB or SMM_REQUIRE links a firmware that is '
          'not the one the image was measured on -- and the defines have to come from '
          'the one function that decides them, not a second copy of the default')
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

    # 6. The action can actually be asked for it, and the value reaches the containers.
    action = os.path.join(os.path.dirname(HERE), 'action.yml')
    if not os.path.isfile(action):
        check('action.yml exists', False, action)
    else:
        text = open(action, encoding='utf-8').read()
        check('action.yml exposes harness-timing',
              re.search(r'^  harness-timing:', text, re.M) is not None,
              'without an input the only way to ask for it is step-env inheritance, '
              'which silently reverts to application timing')
        check('action.yml defaults it to application',
              re.search(r"^  harness-timing:(?:.|\n)*?default: 'application'", text,
                        re.M) is not None,
              'defaulting to dxe would relink the platform on every existing campaign')
        check('action.yml wires it into the environment',
              'FIRNESS_HARNESS_TIMING: ${{ inputs.harness-timing }}' in text,
              'an input nothing reads is worse than no input: the run accepts dxe and '
              'fuzzes with application timing')
        batch = os.path.join(HERE, 'fuzz_batch.py')
        forwarded = open(batch, encoding='utf-8').read() if os.path.isfile(batch) else ''
        check('fuzz_batch forwards FIRNESS_* into the campaign containers',
              "k.startswith('FIRNESS_')" in forwarded,
              'the value reaches the action and stops at the container boundary')

    # 7. make_esp.sh --empty actually works, if the tools are here.
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

    # 6b. The defines. A relink that configures the platform differently from the
    # firmware the image carries is the failure mode this function's own comment calls
    # worse than a build failure -- and on edk2-stable202608 it was not even a quiet one:
    # every module lost its link step.
    defines_fn = body(FIRNESS, 'firmware_defines')
    # The READ and the RETURN, not the name. The name also appears in this function's
    # docstring, so grepping for it passes a version that ignores the variable entirely.
    reads = re.search(r"os\.environ\.get\('FIRNESS_ANALYSIS_DEFINES'\)",
                      defines_fn) is not None
    # The exported string has to be the BASE, with this function's additions appended --
    # not returned early, because the relink needs FD_SIZE_IN_KB on top of it, and not
    # ignored, because only the pipeline knows what actually built the .fd.
    prefers = re.search(r"defines = os\.environ\.get\('FIRNESS_ANALYSIS_DEFINES'\)\s*or",
                        defines_fn) is not None
    check('there is one place that decides the firmware defines',
          bool(defines_fn) and reads and prefers,
          f'reads the exported string: {reads}, prefers it: {prefers}. Both of the '
          f'campaign\'s builds have to agree with each other and with the pipeline\'s, '
          f'and only the pipeline knows the string that actually built the .fd')
    check('it asks for the 8MB flash layout when a harness is linked in',
          re.search(r"if with_harness and 'FD_SIZE_IN_KB' not in defines",
                    defines_fn) is not None
          and 'FD_SIZE_IN_KB=8192' in defines_fn,
          'at 4MB FVMAIN_SIZE is 0x348000 and the pipeline\'s own instrumented build '
          'lands at 68% of it, so a firmware with the harness LINKED IN does not fit -- '
          'and this is a property of that build, not of the campaign, because the '
          'pipeline has no harness to fit')
    check('and the relink asks for it',
          'with_harness=True' in rebuild,
          'the one build that carries the harness is the one that needs the bigger '
          'layout')
    check('the resize says something when it changes nothing',
          'resize changed nothing' in body(FIRNESS, 'grow_fv_for_harness'),
          "'' from grow_dxe_fv means both \"already big enough\" and \"a layout it does "
          "not understand\"; printing neither is how run 42743770936 reported a GenFv "
          "error and nothing about the attempt to fix it")
    check('it adds SMM_REQUIRE for an SMI campaign',
          re.search(r"if smi and 'SMM_REQUIRE' not in defines:\s*\n"
                    r"\s*defines \+= ' -D SMM_REQUIRE=TRUE'", defines_fn) is not None,
          'the dxe timing only exists on the SMI path, so its relink builds a platform '
          'that must have an SMM core; without this it builds one that does not while '
          'the image\'s firmware does')
    check('the relink asks for the SMI defines',
          re.search(r'firmware_defines\(\s*smi=True', rebuild) is not None,
          'passing smi=False here would reintroduce exactly the mismatch')
    check('and the analysis build uses the same function',
          'firmware_defines(' in body(FIRNESS, 'compile_ovmf'),
          'compile_ovmf builds the tree the relink links incrementally; disagreeing '
          'about SMM_REQUIRE makes that a reconfiguration, not a link')
    check('the pipeline exports the string that actually built the firmware',
          "os.environ.setdefault('FIRNESS_ANALYSIS_DEFINES'" in sweep_src
          if (sweep_src := open(os.path.join(HERE, 'fuzz_edk2.py'),
                                encoding='utf-8').read()) else False,
          'the pipeline resizes volumes and retries, so only the string its successful '
          'build used is known to match the .fd the image carries')

    # 6b2. The volume. The port sizes the FVs for a firmware with no harness in it, so
    # linking one in is exactly the case that does not fit -- run 42737814549 compiled the
    # harness and then stopped 1.3 MB short at GenFv.
    grow = body(FIRNESS, 'grow_fv_for_harness')
    check('the relink can enlarge a volume the harness does not fit in',
          bool(grow) and 'grow_dxe_fv' in grow,
          'the pipeline already grows DXEFV from GenFv\'s own number when its build does '
          'not fit; a relink that adds a module to that volume needs the same and cannot '
          'carry a constant that is right for only one configuration')
    check('and it reuses the pipeline\'s resize rather than copying it',
          'from fuzz_edk2 import grow_dxe_fv' in grow,
          'COPY ./scripts ships fuzz_edk2.py into the campaign image, so a second '
          'implementation of an FDF rewrite would be two things to keep right')
    check('a failed import of it still says what to do',
          'ImportError' in grow and 'by hand' in grow,
          'the resize is the one thing here that can fail for an environment reason, and '
          '"too small" with no number is not actionable')
    check('the relink retries the build once after growing',
          re.search(r'for attempt in \(0, 1\)', rebuild) is not None
          and 'grow_fv_for_harness(' in rebuild,
          'growing the volume and not rebuilding leaves the same failure reported')
    check('and does not retry a failure it cannot fix',
          re.search(r'if not short or attempt:\s*\n\s*break', rebuild) is not None,
          'a second attempt at an unrelated failure doubles a 3-minute build for '
          'nothing, and hides which attempt the log belongs to')

    # 6c. The failure report. This one cost a 1055s run with nothing to show.
    check('the relink saves its whole build log',
          'dxe-relink.log' in rebuild,
          'the summary below it is a guess; the log is not, and without it a failed '
          'relink leaves nothing to diagnose')
    check('and its summary excludes make\'s ignored-error noise',
          'Error \\d+ \\(ignored\\)' in rebuild or 'ignored' in rebuild,
          'edk2 marks the per-module copy as ignorable, so ONE real failure prints one '
          '"make: [...] Error 1 (ignored)" per module -- a filter on the word "error" '
          'fills with those and drops the cause')
    check('and it always prints the tail of the build',
          'the last lines of the build' in rebuild,
          'edk2 puts "- Failed -" and its summary at the end, and a matched line from '
          'the middle of a 20k-line log is not a substitute for it')

    # 7. The dxe timing has to be reachable on an ARBITRARY edk2, not only through the
    # action. The sweep driver is the other entry point, and the two guards below are the
    # ones whose absence produces a whole sweep of "the boot never reached the harness".
    sweep = os.path.join(HERE, 'fuzz_edk2.py')
    sweep_src = open(sweep, encoding='utf-8').read() if os.path.isfile(sweep) else ''
    check('fuzz_edk2.py takes --harness-timing',
          "'--harness-timing'" in sweep_src
          and re.search(r"choices=\('application', 'dxe'\)", sweep_src) is not None,
          'the sweep is the only way to fuzz an arbitrary ref, so without this the dxe '
          'timing exists for consumers of the action and for nothing else')
    check('and forwards it as FIRNESS_HARNESS_TIMING',
          "os.environ['FIRNESS_HARNESS_TIMING']" in sweep_src,
          'fuzz_batch forwards FIRNESS_* into the campaign containers and firness.py '
          'reads the timing from there; an argument that reaches neither is inert')
    check('and refuses dxe without --smi',
          re.search(r"args\.harness_timing == 'dxe' and not args\.smi", sweep_src)
          is not None,
          'the timing only reaches the generator on the --smi path, so dxe without it '
          'builds a UEFI_APPLICATION, places THAT in the firmware volume and boots an '
          'empty ESP -- it builds, and then nothing runs the harness')
    check('firness.py refuses the same combination',
          re.search(r"HARNESS_TIMING == 'dxe' and not args\.smi", src) is not None,
          'the sweep is not the only caller; a campaign driven directly has to fail the '
          'same way rather than produce a harness nothing dispatches')

    # 8. The workflows. An input nothing passes is the same as no input.
    root = os.path.dirname(HERE)
    flows = os.path.join(root, '.github', 'workflows')

    def flow(name):
        path = os.path.join(flows, name)
        return open(path, encoding='utf-8').read() if os.path.isfile(path) else ''

    sweep_flow = flow('fuzz-edk2.yml')
    check('the weekly sweep passes --harness-timing through',
          '--harness-timing "$TIMING"' in sweep_flow,
          'fuzz-edk2.yml is the scheduled mainline run; an argument the driver accepts '
          'and the workflow never sends changes nothing on a timer')
    check('the sweep has a second cron for the SMI pass',
          sweep_flow.count("- cron:") >= 2 and "'0 3 * * 3'" in sweep_flow,
          'a single cron cannot carry --smi without rebuilding the firmware every '
          'protocol target is measured against, so the SMI pass needs its own schedule')
    # Both halves: the variable has to be DEFINED from github.event.schedule and then
    # READ by the shell. Grepping for the name alone passes when the definition has been
    # renamed, because the shell body still mentions it.
    defined = re.search(r'EVENT_SCHEDULE:\s*\$\{\{\s*github\.event\.schedule\s*\}\}',
                        sweep_flow) is not None
    used = re.search(r'"\$\{EVENT_SCHEDULE:-\}"\s*=\s*\'0 3 \* \* 3\'', sweep_flow) \
        is not None
    check('and selects that pass by the cron expression',
          defined and used,
          f'defined from github.event.schedule: {defined}, compared in the shell: '
          f'{used}. A scheduled run carries no inputs at all, so the cron expression is '
          f'the only thing that can say which pass this is')
    check('the sweep refuses dxe without smi before it starts a 24h job',
          re.search(r'TIMING"?\s*=\s*.dxe.*\n.*::error::', sweep_flow) is not None
          or ('harness_timing=dxe needs smi=true' in sweep_flow),
          'the driver rejects it, but only after a checkout and a bootstrap; the cheap '
          'place to say so is before any of that')

    smi_flow = flow('upstream-smi.yml')
    check('an upstream SMI gate exists and is push-triggerable',
          "branches: ['ci-smi-**']" in smi_flow,
          'nothing here can dispatch a workflow without a token, so a gate with no push '
          'prefix cannot be run at all -- which is how both of fuzz-edk2.yml\'s first '
          'two runs failed unnoticed')
    check('it asks for smi and the dxe timing',
          'smi: true' in smi_flow and 'harness-timing: dxe' in smi_flow,
          'without both it is stable-e2e.yml with extra steps')
    check('it asserts the FV narration, not just that stages passed',
          'harness placed in the DXE FV' in smi_flow
          and 'restaged OVMF_CODE.fd' in smi_flow,
          'every stage passes when the dxe path does not run; the narration is the only '
          'thing that distinguishes a dxe campaign from an application one')
    # The ORDERING, not the mention. Both names also appear in the error text, so a gate
    # that computes the positions and never compares them greps the same.
    # Three parts, because each can be broken without touching the others: both
    # positions have to be taken from the right strings, and then compared. Asserting
    # only the comparison passes a gate that compares two constants.
    from_latch = re.search(r"latch\s*=\s*debugcon\.find\('SmmEndOfDxeHandler'\)",
                           smi_flow) is not None
    from_first = re.search(r"first\s*=\s*debugcon\.find\('SmmCore: dispatch'\)",
                           smi_flow) is not None
    ordered = re.search(r'0 <= latch < first', smi_flow) is not None
    no_boot_option = re.search(r"if 'BOOTX64\.EFI' in debugcon:", smi_flow) is not None
    check('it asserts the latch had not shut',
          from_latch and from_first and ordered and no_boot_option,
          f'latch from the narration: {from_latch}, first dispatch from it: '
          f'{from_first}, compared: {ordered}, boot option rejected: {no_boot_option}. '
          f'Reaching the harness is not the claim -- reaching it BEFORE EndOfDxe is, and '
          f'that is an ordering in debugcon.log plus the absence of a boot option')
    smoke = flow('action-smoke.yml')
    check('the smoke workflow excludes the new prefix',
          "'!ci-smi-**'" in smoke,
          'action-smoke.yml triggers on ci-**, so without the exclusion every push to '
          'ci-smi-* also starts a second firmware build')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
