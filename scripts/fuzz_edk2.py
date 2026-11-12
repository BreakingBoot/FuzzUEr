"""Fuzz an arbitrary edk2 version, unattended, from a ref to a bug report.

    python3 scripts/fuzz_edk2.py --ref edk2-stable202502

Every stage answers a question that, unanswered, makes the run's result meaningless rather
than merely absent. They are run in order and each one says PASS or FAIL with what it saw:

  fetch        is the ref real and checked out
  submodules   edk2 vendors its dependencies; three separate build failures name none of them
  port         the sanitizer integration applied, and how much of it merged cleanly
  vendor       defects the vendor branch ships repaired and named -- a branch can leave a
               library class unresolvable for OvmfPkg and still ship, and that fails
               AutoGen before a line compiles
  build        the firmware built
  instrumented modules actually carry __asan_load/__asan_store -- "applied" is not "instrumented",
               and the difference is invisible from the build log
  discover     protocols from headers and SMI handlers from registration call sites, so a
               branch that adds its own gets them fuzzed without anyone editing a list
  image        a campaign image holding THIS tree. Campaigns generate and build the harness
               from the tree inside the image, so without this every version is fuzzed
               against whichever edk2 the image happened to ship
  detects      the sanitizer reports a deliberate error in this build's own firmware
  fuzz         the campaigns
  triage       cluster, separate the harness and the PCI hole from the firmware, name a driver

A stage that fails stops the run, because everything after it would report a number that
looks like a result and is not one.

A stage can also come back WARN: it did its job, but not for everything it was asked
about -- a sweep where four campaigns of 243 lost their boot to a timeout. That does not
stop the run, because the campaigns that did fuzz are what the run exists to report on,
and throwing away their triage to punish the gap leaves nothing at all.

The exit code says which of the three happened, because a caller cannot tell them apart
from a bare non-zero and the difference decides whether a human needs to look:

  0   every stage passed
  2   degraded -- at least one WARN, no FAIL. The report stands; read it.
  1   a stage FAILED, so the run stopped and the numbers after it do not exist

2 rather than 1 for degraded is not cosmetic. Degraded used to exit 1, and no full-size
sweep has ever come back without one: of the four recorded 243-to-245 target sweeps,
three ended WARN and one FAILED. The weekly workflow was therefore red on every run it
ever completed, including the two that fuzzed all four refs end to end -- so the signal
that something needed looking at was permanently on, and the table it exists to produce
went unread.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def results_base():
    """The directory `--out` defaults into, one `fuzz-<slug>` per ref.

    The repository from a shell: that is where the hand-written write-ups and every
    older campaign already live, and nothing there deletes them.

    NOT the repository in CI, where the repository IS the workspace actions/checkout
    owns. checkout@v4 runs `git clean -ffdx`, -x removes IGNORED files too, and
    .gitignore ignores `results/*` -- so the next job to land on a self-hosted runner
    deletes the results of the one before it. Measured 2026-11-11: run 42999334016, the
    only SMI sweep that has ever completed, finished at 14:47 UTC and a Checks job that
    started 42 seconds later wiped results/fuzz-master. The 90-day artifact was the only
    copy left of it.

    So in CI this is $HOME/fuzzuer-sweep/$GITHUB_RUN_ID -- outside the workspace, where
    nothing cleans, and keyed by the run so two runs on one runner cannot land on each
    other. It is the same shape eval1_edk2/.github/workflows/fuzzuer.yml and the weekly
    in cglosner/edk2 use, and the output of those is all still on disk.
    """
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    if os.environ.get('GITHUB_ACTIONS') == 'true' and run_id:
        return os.path.join(os.path.expanduser('~'), 'fuzzuer-sweep', run_id)
    return os.path.join(REPO, 'results')


# A stage can end three ways, not two. PASS and FAIL are obvious; WARN is "this did its
# job, but not for everything it was asked about" -- a sweep where 239 of 243 campaigns
# fuzzed and four lost their boot to a timeout. Treating that as FAIL stopped the run, so
# triage never ran and the weekly sweep produced campaign directories and no report at
# all, which is the one output it exists for. A degraded run still exits non-zero, so CI
# still shows it as needing a look.
WARN = 'warn'


def state_of(ok):
    if ok is WARN:
        return 'WARN'
    if ok is False:
        return 'FAIL'
    if ok is None:
        return 'SKIP'
    return 'PASS'


class Stage:
    def __init__(self, name):
        self.name = name
        self.ok = None
        self.detail = ''
        self.seconds = 0.0


class Run:
    def __init__(self, ref, out):
        self.ref = ref
        self.out = out
        self.stages = []

    def stage(self, name):
        s = Stage(name)
        self.stages.append(s)
        return s

    def report(self):
        print()
        print(f'  === {self.ref} ===')
        for s in self.stages:
            print(f'    [{state_of(s.ok)}] {s.name:<14}{s.detail}  ({s.seconds:.0f}s)')
        failed = [s for s in self.stages if s.ok is False]
        degraded = [s for s in self.stages if s.ok == WARN]
        if failed:
            print(f'  FAILED at {failed[0].name}')
        elif degraded:
            print(f'  DEGRADED at {degraded[0].name} -- the run finished and its report '
                  f'stands, but not every target was covered')
        else:
            print('  OK')
        # 1 for a failure, 2 for degraded, and the caller is expected to tell them apart:
        # see the exit-code table at the top of this file. Both used to be 1, which made
        # "a few campaigns of 243 timed out" indistinguishable from "the build broke".
        if failed:
            return 1
        return 2 if degraded else 0

    def save(self):
        os.makedirs(self.out, exist_ok=True)
        # Before run.json, because the containers that boot QEMU run as root and leave their
        # captures owned by root. In CI the job's cleanup runs as the runner user and then
        # cannot delete its own output, so the scratch grows by one detect_capture per run
        # with nothing able to reclaim it.
        if getattr(self, 'base_image', ''):
            reown(self.out, self.base_image)
        with open(os.path.join(self.out, 'run.json'), 'w') as handle:
            json.dump({'ref': self.ref,
                       'stages': [{'name': s.name, 'ok': s.ok, 'detail': s.detail,
                                   'seconds': round(s.seconds, 1)} for s in self.stages]},
                      handle, indent=2)


def sh(cmd, cwd=None, timeout=None, env=None):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(cmd, shell=isinstance(cmd, str), cwd=cwd, env=merged,
                          capture_output=True, text=True, timeout=timeout)


def submodules_off_commit(tree):
    """Submodule paths whose checkout is NOT the commit the superproject records.

    `git submodule status` marks those with a leading '+'. A leading '-' means not
    initialised, which is a different thing and not a problem by itself: an uninitialised
    submodule leaves the superproject clean, and a tree can carry one whose URL has died
    without that affecting a build which does not use it.
    """
    got = sh(['git', '-C', tree, 'submodule', 'status'], timeout=300)
    off = []
    for line in got.stdout.splitlines():
        if line[:1] == '+':
            parts = line.split()
            if len(parts) >= 2:
                off.append(parts[1])
    return off


def repair_submodules(tree, report=print):
    """Finish the checkout that an aborted `submodule update` left half done.

    `git submodule update` clones every submodule first and checks each one out at the
    commit the superproject records afterwards. When ONE submodule cannot be cloned the
    whole operation aborts -- and the abort lands before that checkout pass, so every
    submodule that cloned perfectly well is left sitting at its default branch tip instead
    of the recorded commit. The superproject then reads as MODIFIED, and the port stage
    refuses it saying only "has uncommitted changes" plus a list of paths: it names neither
    submodules nor the one submodule that actually failed, so the cause ends up three
    stages away from the message that reports it.

    Measured on an edk2 whose UnitTestFrameworkPkg/Library/SubhookLib/subhook still points
    at https://github.com/Zeex/subhook, which no longer resolves. `submodule update --init
    --depth=1` exits 1, leaves 10 of the other 11 submodules off their recorded commit, and
    the stage called it `PASS submodules 10/11 populated` because the exit code was thrown
    away.

    Re-running the update for exactly those paths completes the skipped checkout. It needs
    no deeper fetch: the objects are already in each submodule and they stay shallow
    afterwards, both measured, so this costs nothing on the network. An earlier version of
    this ran `fetch --unshallow` first on the theory that a shallow clone could not contain
    the recorded commit -- that theory was wrong, and it would have refetched the whole of
    OpenSSL on every repair.

    Returns the paths still wrong afterwards, so the caller can fail honestly rather than
    leaving a later stage to fail for a reason it cannot explain.
    """
    off = submodules_off_commit(tree)
    if not off:
        return []
    report(f'  {len(off)} submodule(s) cloned but were never checked out at the commit '
           f'this tree records, which is what an aborted submodule update leaves behind; '
           f'finishing them')
    sh(['git', '-C', tree, 'submodule', 'update', '--init', '--force', '--'] + off,
       timeout=3600)
    still = submodules_off_commit(tree)
    if still:
        report(f'  {len(still)} still wrong: {", ".join(still[:3])}')
    else:
        report(f'  all {len(off)} now at their recorded commit(s)')
    return still

def apply_build_options(tree, raw, dsc_rel='OvmfPkg/OvmfPkgX64.dsc', report=print):
    """Append caller-supplied [BuildOptions] lines to the platform DSC being built.

    This exists because FuzzUEr builds with clang and edk2 is built upstream with GCC,
    and clang has warnings GCC does not. Upstream code that compiles cleanly under GCC5
    then fails here under -Werror, and the tree is not at fault:
    UefiPayloadPkg/PchSmiDispatchSmm/PchSmiDispatchSmm.c:411 trips
    -Wcast-calling-convention, which GCC does not implement at all, and the same file
    builds fine with the toolchain edk2 actually ships.

    Suppressing such a warning in SAN_FLAGS for every tree was the alternative, and this
    was preferred: the warning is real -- cdecl and ms_abi genuinely differ in argument
    registers on x86-64 -- so a blanket suppression could hide a crash source, and in a
    FUZZER that would surface later as a false finding. Per-caller keeps the shipped
    toolchain strict and puts the relaxation next to the tree that needs it.

    An entry containing '=' is taken as a complete tools_def style line. Anything else is
    taken as compiler flags and attached to CLANGSAN's CC_FLAGS, which is what a caller
    almost always means.

    Appended AFTER the port has run. The port rewrites this DSC -- and dedup_sections
    inside it finds the file's duplicated body by matching the longest repeated run of
    section HEADERS, so adding a header before it runs re-aligns that search and drops
    the wrong copy. A repeated [BuildOptions] section is legal in a DSC, so appending one
    at the end here is safe once the port is done.
    """
    entries = [e.strip() for e in re.split(r'[\r\n]+', raw or '') if e.strip()]
    if not entries:
        return []
    lines = []
    for entry in entries:
        # "Contains '='" is NOT the test, though it was the first one here and it was
        # wrong: most compiler flags contain one. `-fno-sanitize=pointer-overflow` was
        # written out verbatim as though it were a complete tools_def assignment, and the
        # DSC parser rejected the result with `error 3000`. What distinguishes the two is
        # the LEFT of the first '=': a tools_def key is a single token, while a flag list
        # has spaces in it or starts with a dash.
        head = entry.split('=', 1)[0].strip() if '=' in entry else ''
        if head and ' ' not in head and not head.startswith('-'):
            lines.append('  ' + entry)
        else:
            lines.append('  *_CLANGSAN_*_CC_FLAGS = ' + entry)
    dsc = os.path.join(tree, dsc_rel)
    if not os.path.isfile(dsc):
        report(f'  cannot add build options: {dsc_rel} is not in this tree')
        return []
    with open(dsc, 'a', encoding='utf-8', errors='ignore') as handle:
        handle.write('\n\n# Added by fuzz_edk2.py --extra-build-options\n'
                     '[BuildOptions]\n' + '\n'.join(lines) + '\n')
    for line in lines:
        report(f'  build option:{line.rstrip()}')
    return lines


def sync_committed_conf(tree, report=print):
    """Refresh a tree's COMMITTED Conf/ from the templates the port just edited.

    edksetup.sh copies BaseTools/Conf/<name>.template to Conf/<name>.txt ONLY IF that
    file does not already exist. A tree that commits a generated Conf/ therefore keeps a
    tools_def predating the port, and any build pointed at CONF_PATH=<tree>/Conf fails
    with

        build: : warning: Tool chain [CLANGSAN] is not defined
         : error 4000: Not available
            [CLANGSAN] not defined. No toolchain available for build!

    This is not a rare shape: the EVAL-1 challenge tree commits Conf/tools_def.txt,
    Conf/target.txt and Conf/.AutoGenIdFile.txt, and its tools_def.txt mentions CLANGSAN
    zero times. The firmware build survives it because that path does not use the tree's
    Conf; the campaign image's analysis build does, and dies there -- three stages after
    the real cause, with a working firmware already built.

    The file is REPLACED, not merged. The first version of this appended just the lines
    mentioning CLANGSAN or SAN_FLAGS, which cannot work: those lines reference other
    macros by DEF(), so a tree whose committed file predates them got

        Conf/tools_def.txt(2245): error 5000: Macro or Environment has not been defined
            CLANG38_IA32_ASLCC

    Copying a dependent subset out of a file with internal references is the wrong model.
    Replacing is also exactly what edksetup.sh would have done had the file been absent,
    so this restores the intended semantics rather than inventing a merge. The previous
    file is kept beside it as <name>.txt.preport, because a tree that bothered to commit
    one may have customised it and that must not vanish silently.
    """
    done = {}
    for name in ('tools_def', 'build_rule'):
        live = os.path.join(tree, 'Conf', f'{name}.txt')
        template = os.path.join(tree, 'BaseTools', 'Conf', f'{name}.template')
        if not os.path.isfile(live) or not os.path.isfile(template):
            continue
        try:
            have = open(live, encoding='utf-8', errors='ignore').read()
            want = open(template, encoding='utf-8', errors='ignore').read()
        except OSError as exc:
            report(f'  cannot refresh Conf/{name}.txt: {exc}')
            continue
        if have == want:
            continue
        # Only when it actually lacks what the port added -- a tree whose committed Conf
        # already knows the toolchain is left alone.
        if 'CLANGSAN' in have:
            continue
        try:
            shutil.copyfile(live, live + '.preport')
            shutil.copyfile(template, live)
        except OSError as exc:
            report(f'  cannot refresh Conf/{name}.txt: {exc}')
            continue
        done[name] = True
        report(f'  Conf/{name}.txt is committed in this tree and predates the port, and '
               f'edksetup.sh will not refresh a file that exists; replaced it from the '
               f'ported template (previous kept as {name}.txt.preport)')
    return done

def reown(path, image):
    """Give a directory a container wrote back to the user running this.

    The detect probe and the benchmark run as root -- they boot QEMU and poke at firmware
    images -- and everything they leave under the results directory is then root owned. From
    a shell that is untidy; in CI it is a leak, because the job's own cleanup runs as the
    runner user and cannot remove its own run's output. The scratch then grows by a
    detect_capture every run and nothing on the runner can reclaim it.

    Done from inside a container because that is the only side of the mount with the
    privilege to do it. Failure is not fatal: the artifacts are already written and readable,
    this only decides who may delete them.
    """
    if not os.path.isdir(path):
        return
    # The pipeline's own image, not a new one: it is already on the runner, so this adds
    # no pull and cannot fail for want of a registry.
    sh(['docker', 'run', '--rm', '-v', f'{os.path.abspath(path)}:/fix',
        '--entrypoint', 'sh', image, '-c',
        f'chown -R {os.getuid()}:{os.getgid()} /fix'], timeout=300)


def docker(container, script, timeout=None):
    return sh(['docker', 'exec', container, 'bash', '-lc', script], timeout=timeout)


# The child currently running under sh_log, so a signal can take it down too.
_child = None


def _stop_child(signum, _frame):
    """Take the fuzzing batch with us.

    Killing this script used to leave its child running: the batch kept launching
    campaigns, and a second run then shared the output directory with the first -- 40
    containers for a --jobs 20 run, two batches interleaving results into the same
    directories. A cancelled CI job would do exactly the same and leave the runner
    fuzzing.
    """
    if _child is not None and _child.poll() is None:
        _child.terminate()
        try:
            _child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _child.kill()
    sys.exit(128 + signum)


def sh_log(argv, path, timeout=None):
    """Run, echoing as it goes and keeping a copy.

    The fuzzing stage is hours long. Captured wholesale it produces nothing until it
    finishes, which under CI is indistinguishable from a hang, and the log is the only
    place "reached the harness after 41s of boot" is ever written.
    """
    global _child
    with open(path, 'w') as handle:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        _child = proc
        try:
            for line in proc.stdout:
                sys.stdout.write('    | ' + line)
                handle.write(line)
        finally:
            proc.stdout.close()
        try:
            return proc.wait(timeout=timeout)
        finally:
            _child = None


# The campaign image for one version: the base image with this tree in place of whatever
# edk2 it ships, and this build's firmware. BaseTools ships as C source and the campaign
# builds the harness with GenFw; without it every campaign stops at "Unable to find the
# real GenFw".
IMAGE_DOCKERFILE = """FROM {base}
# bash, not the default /bin/sh. edk2's edksetup.sh is a bash script, and on an older tree it
# uses the bash-only "function Name()" form -- upstream made it POSIX later. Sourced under
# dash that is a SYNTAX error, and a syntax error in a sourced script aborts the whole shell
# at once: the step died with code 2 and printed nothing, not even the failure handler two
# lines below it, so the build looked like it had vanished. Conf was left holding only
# ReadMe.txt and `build` never reached PATH, which is the visible half of the same thing.
SHELL ["/bin/bash", "-c"]
RUN rm -rf /workspace/tmp/edk2
COPY ./edk2 /workspace/tmp/edk2
COPY ./qemu_fw /workspace/qemu_fw
# The checkout's own generator and runner, not whichever copy the base image was built
# with. The base had a firness.py predating the QEMU backend, so every campaign compiled
# its harness and then stopped at "only the tsffs/simics runner is implemented here" --
# a message about this repository's code, from a container built before it was written.
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./harness_generator /workspace/harness_generator
COPY ./HarnessHelpers /workspace/HarnessHelpers
# --cores, and -j1 if that still loses: BaseTools generates VfrCompile's parser with antlr
# without declaring every dependency, so a wide -j reads half-written headers. Same race
# as the firmware build stage, and it fails here as an opaque "The command ... returned a
# non-zero code" from docker build -- which is why --cores is small by default rather than
# nproc. The LLVM and QEMU builds in bootstrap_runner.sh stay wide on purpose: ninja
# declares its dependencies, so those scale instead of racing.
RUN {{ make -C /workspace/tmp/edk2/BaseTools -j{cores} \\
     || make -C /workspace/tmp/edk2/BaseTools -j1 ; }} >/tmp/basetools.log 2>&1 \\
    && test -x /workspace/tmp/edk2/BaseTools/Source/C/bin/GenFw \\
    && test -x /workspace/tmp/edk2/BaseTools/Source/C/bin/VfrCompile
# The compilation database firness analyses, built once here instead of once per campaign.
# It carries the SMM choice too, and has to: SMI handler registrations live in
# DXE_SMM_DRIVER modules, so a database built without SMM_REQUIRE contains none of them. The
# C++ analyser then writes a null smi-function-guid-map.json and the generator dies in
# load_smi_data with "'NoneType' object has no attribute 'items'" -- after a container, a
# full analysis and ten minutes. That is why --smi needs --smm all the way down, not just in
# the firmware the campaign boots.
# It describes the tree, not the protocol, so every campaign was paying for the same
# instrumented build of the whole of OVMF under bear -- minutes each, times as many
# protocols as the version has.
#
# The defines are the firmware build's, exactly -- and so are the PCDs, which they were
# not. THIS is the firmware a campaign boots (see the copy into qemu_fw below), and it was
# built without the --pcd overrides the firmware stage passes. One of those is
# PcdResetOnMemoryTypeInformationChange=FALSE, which OvmfPkgX64.dsc forces only inside
# "!if $(SMM_REQUIRE) == FALSE" -- so an SMM image built here kept MdeModulePkg's default
# of TRUE, BDS wrote the changed Memory Type Information in EfiBootManagerBoot and
# warm-reset, and the campaign ended before the harness. The fix for that was written for
# the firmware stage and never reached the build that actually boots.
#
# Measured: swapping this image's OVMF for the detect probe's (same ESP, same harness, same
# q35,smm=on, same fork) took the boot from stopping after "[Bds]UnregisterKeyNotify" to
# opening BOOTX64.EFI and fuzzing 35 iterations over 2389 edges.
#
# The .debug files this leaves behind are what turns an address in a sanitizer report back
# into a function and a line, and that only holds while they are the same build as the
# image that is running.
RUN cd /workspace/tmp/edk2 \\
    && export WORKSPACE=/workspace/tmp/edk2 \\
       EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools \\
       CONF_PATH=/workspace/tmp/edk2/Conf \\
       CLANGSAN_BIN=/workspace/llvm-15.0.7/build/bin/ \\
    && . ./edksetup.sh >/dev/null 2>&1 \\
    && bear --output /workspace/tmp/compile_commands.json -- \\
       build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc \\
       -D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FIRNESS_QEMU_CRASH=TRUE{bench}{smm} \\
       -D NETWORK_IP6_ENABLE=TRUE -D NETWORK_HTTP_BOOT_ENABLE=TRUE \\
       -D FD_SIZE_IN_KB=8192 {pcds}-n {cores} >/tmp/anabuild.log 2>&1 \\
       || {{ echo '=== the analysis build failed; its last 60 lines: ==='; \\
             tail -60 /tmp/anabuild.log; exit 1; }} \\
    && python3 -c "import json,sys; d=json.load(open('/workspace/tmp/compile_commands.json')); print(len(d),'compile commands'); sys.exit(0 if d else 1)"
# The firmware the fuzzer boots has to be the build those .debug files describe, and it
# was not. qemu_fw copied in above is the build stage's, built at
# /workspace/tmp/edk2-master; the analysis build just now produced a second image of the
# same source at /workspace/tmp/edk2. Two paths mean two sets of __FILE__ strings, so the
# two images are not byte-identical -- and a compiler-inserted check reports nothing but a
# return address, which was then turned into a file and a line against binaries that were
# not the ones running. That is how a report from SmbiosDxe came back pointing at
# UefiDriverModel.c. Take the firmware from the build whose debug images are here and the
# two cannot drift apart again.
RUN cp /workspace/tmp/edk2/Build/OvmfX64/DEBUG_CLANGSAN/FV/OVMF_CODE.fd \\
       /workspace/tmp/edk2/Build/OvmfX64/DEBUG_CLANGSAN/FV/OVMF_VARS.fd \\
       /workspace/qemu_fw/ \\
    && cp /workspace/tmp/edk2/Build/OvmfX64/DEBUG_CLANGSAN/X64/AsanSelfTest.efi \\
       /workspace/qemu_fw/
"""


def run_stage(run, name, fn):
    s = run.stage(name)
    start = time.time()
    try:
        s.ok, s.detail = fn()
    except subprocess.TimeoutExpired:
        s.ok, s.detail = False, 'timed out'
    except Exception as error:                      # a stage must not take the run with it
        s.ok, s.detail = False, f'{type(error).__name__}: {error}'
    s.seconds = time.time() - start
    # None is "deliberately not run", not a failure: printing FAIL for a stage the caller
    # asked to skip is how --skip-fuzz reads as a broken version.
    print(f'  [{state_of(s.ok)}] {name:<14}{s.detail}')
    return s.ok


NETWORK_DEFINES = (
    # OvmfPkgX64 defaults NETWORK_TLS_ENABLE, NETWORK_IP6_ENABLE and
    # NETWORK_HTTP_BOOT_ENABLE to FALSE, so twelve protocols the evalset asks for are never
    # installed: the six of the IPv6 stack and the four HTTP ones. They were costing a boot
    # and a budget each to discover their opening LocateProtocol fails. iSCSI is already
    # TRUE upstream.
    # TLS is deliberately NOT here. Enabling it pulls OpenSSL's TLS sources, which need
    # errno/strcmp/strcpy/strchr from the full OpensslLib and a TLS-capable BaseCryptLib --
    # and the ASan port overrides BaseCryptLib with a variant that does not carry those
    # shims, so the link fails with a page of undefined references. Recovering EfiTls and
    # EfiTlsConfiguration means reworking the port's crypto choice, not setting a flag.
    ' -D NETWORK_IP6_ENABLE=TRUE'
    ' -D NETWORK_HTTP_BOOT_ENABLE=TRUE'
)

DXE_FV_PCDS = 'PcdOvmfDxeMemFvBase|gUefiOvmfPkgTokenSpaceGuid.PcdOvmfDxeMemFvSize'

# The --pcd overrides every build in a run shares. Kept in one place because the firmware
# build and the analysis build in IMAGE_DOCKERFILE maintain separate command lines, and
# that is exactly how PcdResetOnMemoryTypeInformationChange came to be set on the build
# nobody boots -- see the note on IMAGE_DOCKERFILE. A PCD one build sets and the other does
# not is a difference between the firmware that was validated and the firmware that runs.
SHARED_PCDS = (
    # A fuzzer cannot survive a guest reset, and with SMM the firmware takes one.
    # OvmfPkgX64.dsc forces this PCD FALSE only inside "!if $(SMM_REQUIRE) == FALSE", so an
    # SMM build keeps MdeModulePkg's default of TRUE: BDS sees the Memory Type Information
    # differ, writes it and warm-resets so the new map takes effect --
    #   Memory Type Information settings change.
    #   ...Warm Reset!!!
    # libafl_qemu then dies on "Unhandled QEMU shutdown cause: GuestReset" and the campaign
    # ends before the harness, which is why ONLY SMM campaigns failed. Without SMM the
    # variable store is opened read-only, the write cannot happen, and the question never
    # arises. Passed for every build: without SMM the DSC already says FALSE, so this only
    # ever agrees with it.
    'gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange=FALSE',

    # 0x0F is OvmfPkgX64.dsc's own 0x2F with DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED (0x20)
    # cleared, and nothing else changed: DEBUG_ASSERT, DEBUG_PRINT, DEBUG_CODE and
    # CLEAR_MEMORY all stay on, so the "ASSERT <file>(<line>): <expr>" line still reaches
    # the debug console and freed pool is still poisoned. Only the CpuDeadLoop that
    # followed it is gone, which DebugLib documents as a PCD choice -- with neither the
    # breakpoint nor the deadloop bit set, DebugAssert prints and returns.
    #
    # A dead loop forfeits the whole remaining budget, and inside SMM it forfeits the
    # machine. Measured on eval1 run 42154605158: the corpus grew 0 -> 20 over 20 fast
    # iterations, then input 21 reached VarCheckPolicyLibMmiHandler with a 1-byte comm
    # buffer, that handler returned EFI_INVALID_PARAMETER, SmiManage hit its "Unexpected
    # status code returned" ASSERT (PiSmmCore/Smi.c:193) and CpuDeadLoop()ed with
    # interrupts off. Iterations 22, 23 and 24 produced no guest output at all -- the
    # snapshot restore does not recover a vCPU wedged in SMM -- so the campaign spent the
    # rest of its 300s timing out against a dead machine and stopped at 24 iterations.
    #
    # The ASSERT is still a finding, and a better one than the timeout was: it names its
    # own file and line. guest_asserts() in bug_report.py reads those lines back out of the
    # capture, so clearing the bit keeps the finding and buys back the budget.
    'gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask=0x0F',
)


def shared_pcds():
    """SHARED_PCDS as build(1) arguments."""
    return ' '.join(f'--pcd {pcd}' for pcd in SHARED_PCDS)


# The dependency file build(1) writes for every compile names the module it belongs to:
#   -MF .../Build/OvmfX64/DEBUG_CLANGSAN/X64/OvmfPkg/RWVariable/RWVariable/OUTPUT/RWVariable.obj.deps
# so <Pkg>/<path>/<inf stem> comes straight out of the command line, per module, which is
# the granularity the DSC scopes BuildOptions by. A source directory is not: OvmfPkg/Spi
# builds DxeSpi (instrumented) and SmmSpi (not) out of one directory.
OBJ_DEPS = re.compile(r'-MF\s+\S*?/Build/[^/]+/[^/]+/[^/]+/'
                      r'((?:[A-Za-z0-9]+Pkg)/.*?)/OUTPUT/([^/\s]+)\.obj\.deps')


def own_code_instrumented(text, tree=''):
    """Per module, was the module's OWN source compiled with -fsanitize=address.

    The instrumented stage counts images whose .debug carries __asan_load/__asan_store,
    and for an SMM image that number is a fiction. A library instance is built once with
    the global flags and BuildOptions cannot be scoped to one, so every module links
    instrumented copies of BaseLib and BaseMemoryLib whatever its own flags were. The
    symbols are therefore present in an SMM driver's image while none of that driver's own
    code is checked: measured on eval1 run 42171026991, 288/290 images by symbols against
    0 of 17 SMM modules by their own sources.

    That matters because the gate exists to stop exactly this -- "a sweep over
    uninstrumented firmware reports clean and means nothing" -- and every injected bug in
    that tree is in one of those 17.

    AutoGen objects are excluded: they are generated, nobody is looking for a bug in them,
    and a module whose only instrumented object was AutoGen would otherwise count as
    covered.

    Returns (instrumented, total, [(module, module_type), ...] for the ones with none).
    """
    seen = {}
    for line in text.splitlines():
        if 'clang' not in line:
            continue
        found = OBJ_DEPS.search(line)
        if not found:
            continue
        module, obj = found.group(1), found.group(2)
        if obj.startswith('AutoGen'):
            continue
        hit, total = seen.get(module, (0, 0))
        seen[module] = (hit + (1 if 'fsanitize=address' in line else 0), total + 1)
    dark = []
    for module, (hit, total) in sorted(seen.items()):
        if total and not hit:
            dark.append((module, module_type(tree, module)))
    return sum(1 for hit, _ in seen.values() if hit), len(seen), dark


def module_type(tree, module):
    """MODULE_TYPE out of the module's own INF, or '' -- the key IS the INF's path."""
    if not tree:
        return ''
    inf = os.path.join(tree, f'{module}.inf')
    try:
        with open(inf, errors='ignore') as handle:
            found = re.search(r'^\s*MODULE_TYPE\s*=\s*(\S+)', handle.read(), re.M)
    except OSError:
        return ''
    return found.group(1) if found else ''


def build_error(text):
    """The line that actually explains a failed build.

    Picking the first line containing 'error' reported the compiler COMMAND LINE, because
    it carries -Werror: a firmware volume that overflowed by 1.6 MB was reported as
    '"/workspace/llvm-15.0.7/build/bin/clang" -MMD -MF ...', which says nothing. GenFv's
    own complaint, and build.py's numbered errors, come first now, and a GenFv line is
    paired with the line under it, where the sizes are.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(r'GenFv: ERROR', line):
            detail = lines[index + 1].strip() if index + 1 < len(lines) else ''
            return (line.strip() + ' -- ' + detail).strip(' -')
    for pattern in (r'^\s*:?\s*error \d+:', r'error \d+:', r': (fatal )?error:'):
        for line in lines:
            if re.search(pattern, line) and not line.lstrip().startswith('"'):
                return line.strip()
    for line in lines:
        if 'error' in line.lower() and len(line) < 200 \
                and not line.lstrip().startswith('"'):
            return line.strip()
    return ''


def grow_dxe_fv(tree, required, block=0x10000, headroom=0x80000):
    """Make DXEFV big enough for `required` bytes, and the volume holding it match.

    The port sizes the volumes for the configuration it was written against. Turning SMM
    on adds PiSmmCpuDxeSmm, PiSmmCore, VariableSmm and the rest, all instrumented, and
    GenFv stops with 'the required fv image size 0x25ab378 exceeds the set fv image size
    0x2400000' -- 1.6 MB short. Rather than carry a constant that is wrong for the next
    configuration, take GenFv's own number: it says exactly what it needed.

    DXEFV is the last region in [FD.MEMFD], so growing it grows the FD by the same amount;
    NumBlocks has to follow or GenFd rejects the arithmetic. Returns a description, or ''
    when the layout is not the one this understands -- in which case nothing is touched,
    because a half-edited FDF fails somewhere that looks unrelated.
    """
    for rel in ('OvmfPkg/OvmfPkgX64.fdf', 'OvmfPkg/Include/Fdf/MemFd.fdf.inc'):
        path = os.path.join(tree, rel)
        if not os.path.isfile(path):
            continue
        lines = open(path, newline='').read().split('\n')
        where = next((i for i, l in enumerate(lines) if DXE_FV_PCDS in l), -1)
        if where < 1:
            continue
        region = re.match(r'^(0x[0-9A-Fa-f]+)\|(0x[0-9A-Fa-f]+)\s*$',
                          lines[where - 1].strip())
        if not region:
            return ''
        base, old = int(region.group(1), 16), int(region.group(2), 16)
        # Only safe while nothing sits above it; otherwise growing it would run into the
        # next region and GenFds would report an overlap somewhere else entirely.
        for line in lines:
            other = re.match(r'^(0x[0-9A-Fa-f]+)\|(0x[0-9A-Fa-f]+)\s*$', line.strip())
            if other and int(other.group(1), 16) > base:
                return ''
        # Only this FD's own header lines. Every numeric Size in the file matched at
        # first, which happens to be harmless in the layout this was written against --
        # MEMFD is the only block with literal sizes there -- and would silently resize an
        # unrelated FD in any layout that is not. The block runs from its section header,
        # or the start of an include that has none, to the next one.
        start = 0
        for index in range(where, -1, -1):
            if lines[index].lstrip().startswith('['):
                start = index
                break
        stop = len(lines)
        for index in range(where + 1, len(lines)):
            if lines[index].lstrip().startswith('['):
                stop = index
                break
        inside = range(start, stop)
        for index in inside:
            found = re.match(r'^\s*BlockSize\s*=\s*0x([0-9A-Fa-f]+)\s*$', lines[index])
            if found:
                block = int(found.group(1), 16)
                break

        new = ((required + headroom + block - 1) // block) * block
        if new <= old:
            return ''
        lines[where - 1] = f'0x{base:X}|0x{new:X}'
        grown = new - old
        for index in inside:
            size = re.match(r'^(\s*Size\s*=\s*)0x([0-9A-Fa-f]+)\s*$', lines[index])
            if size:
                lines[index] = f'{size.group(1)}0x{int(size.group(2), 16) + grown:X}'
                continue
            blocks = re.match(r'^(\s*NumBlocks\s*=\s*)0x([0-9A-Fa-f]+)\s*$',
                              lines[index])
            if blocks:
                lines[index] = (f'{blocks.group(1)}'
                                f'0x{int(blocks.group(2), 16) + grown // block:X}')
        open(path, 'w', newline='').write('\n'.join(lines))
        return (f'{rel}: DXEFV 0x{old:X} -> 0x{new:X} for a volume needing '
                f'0x{required:X}')
    return ''


SMI_TARGET = 'DiscoveredSmi'


def pick_targets(evalset, limit, smi, explicit=()):
    """Which discovered targets to fuzz: all of them, the first `limit`, or named ones.

    Returns [] for "every target discovered", which is what passing no -p to fuzz_batch
    means. The precedence is a property rather than a line in the stage body, because
    getting it backwards -- a bounded gate quietly overriding a caller's --targets -- is
    invisible in a log that says "fuzzing 2 target(s)" either way.

    For a gate that runs the SAME pipeline on several edk2 releases without spending a
    full campaign budget on each of them. Naming protocols literally cannot work there:
    the discovered set differs between releases -- 261 on edk2-stable202305 against 254
    on edk2-stable202608 -- so a fixed name is a target that silently does not exist on
    some of them, and a run that fuzzed nothing reports exactly like a clean one.

    Sorted, so two runs of one ref choose the same targets and a difference between them
    is a regression rather than a different draw. Under --smi the handler list goes first:
    it is the target that mode exists to fuzz, and taking the alphabetical head without it
    would fuzz protocols while reporting an SMI run.
    """
    if explicit:
        return list(explicit)
    if limit <= 0:
        return []
    names = sorted(f[:-len('.txt')] for f in os.listdir(evalset)
                   if f.endswith('.txt') and f[:-len('.txt')] != SMI_TARGET)
    if smi:
        names.insert(0, SMI_TARGET)
    return names[:limit]


def main():
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop_child)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ref', required=True, help='edk2 tag, branch or SHA to fuzz')
    parser.add_argument('--source', default=os.path.join(REPO, 'eval_source', 'edk2'),
                        help='an edk2 checkout to take the ref and the port from')
    parser.add_argument('--port-from', default='',
                        help='the tree the sanitizer integration is taken from. Defaults '
                             'to apply_asan.py\'s own default, the fork beside this '
                             'repository. Only set this if the port lives somewhere else '
                             '-- it is NOT the tree being fuzzed, which is --source')
    parser.add_argument('--budget', type=int, default=600, help='seconds per target')
    parser.add_argument('--jobs', type=int, default=8, help='targets fuzzed at once')
    parser.add_argument('--targets', nargs='*', default=None,
                        help='specific targets; default is everything discovered')
    parser.add_argument('--out', default='', help='where the artifacts go')
    parser.add_argument('--work', default='',
                        help='where this run keeps its own scratch: the git worktree of the '
                             'ref and the docker build context for the campaign image. '
                             'Defaults to this repository, which is fine from a shell and '
                             'wrong inside CI -- there the repository is the workspace '
                             'actions/checkout owns, and a pipeline writing into it leaves '
                             'a tree the next job cannot check out')
    parser.add_argument('--builder', default='fwbuild-stack',
                        help='container holding the toolchain')
    parser.add_argument('--port-base', default='',
                        help='the commit the sanitizer port sits on top of')
    parser.add_argument('--boot-timeout', type=int, default=0,
                        help='seconds a campaign may spend booting to the harness before '
                             'it is given up on; the default scales with --jobs, because '
                             'that is what the boot is competing with')
    parser.add_argument('--base-image', default='fuzzuer-ci:latest',
                        help='the image the per-version campaign image is layered on; '
                             'scripts/bootstrap_runner.sh builds the default')
    parser.add_argument('--bench', action='store_true',
                        help='build the SanBench benchmark drivers and the firmware '
                             'sanitizer into the image and fuzz them. Ground truth: '
                             'every member hides a fault behind a condition an input '
                             'has to satisfy, so what a sweep finds among them is a '
                             'measurement of the fuzzer rather than of the firmware')
    parser.add_argument('--cores', type=int, default=0,
                        help='parallel jobs for every firmware build. Default: a quarter of '
                             'the machine, capped at 8. Wide parallelism is where the edk2 '
                             'build becomes unreliable rather than fast -- BaseTools races '
                             'at high -j and the analysis build has been seen hang at '
                             'nproc on a 72-core box -- and the campaigns are what should '
                             'have the cores, not one build. Raise it if you are building '
                             'and not fuzzing')
    parser.add_argument('--extra-defines', action='append', default=[], metavar='FOO=BAR',
                        help='extra -D macros for every firmware build, repeatable and '
                             'space separated. Quoting is respected, so a value with a '
                             'space in it survives. These go LAST on the build command '
                             'line, after every define the pipeline sets itself: edk2 '
                             'keeps command line macros in a dict, so last wins and a '
                             'codebase can override one of ours (FD_SIZE_IN_KB, say) '
                             'rather than only add to it')
    parser.add_argument('--extra-build-options', default='',
                        help='tools_def style [BuildOptions] lines appended to the '
                             'platform DSC, one per line. An entry with no "=" is taken '
                             'as compiler flags for CLANGSAN. Use it when your tree needs '
                             'a relaxation clang demands and GCC does not -- upstream '
                             'UefiPayloadPkg/PchSmiDispatchSmm trips '
                             '-Wcast-calling-convention, which GCC does not have')
    parser.add_argument('--extra-pcds', action='append', default=[],
                        metavar='Space.Pcd=Value',
                        help='extra --pcd overrides for every firmware build, same form '
                             'and same last-wins ordering as --extra-defines. Needed '
                             'because a per-codebase build knob is as often a PCD as a '
                             'macro: the warm reset that blocked every SMM campaign was '
                             'fixed by exactly one of these, and a consumer should not '
                             'have to wait for this script to learn the next one')
    parser.add_argument('--smi', action='store_true',
                        help='also fuzz the SMI handlers the discover stage finds, not just '
                             'the protocols. Implies --smm: the handlers answer an SMM core, '
                             'and without SMM_REQUIRE=TRUE the firmware has none at all, so '
                             'the campaign would spend its budget proving that')
    parser.add_argument('--smm', action='store_true',
                        help='build with SMM_REQUIRE=TRUE, which is what puts an SMM core '
                             'and its handlers in the image. Without it the firmware has no '
                             'SMM at all -- measured, 0 SMM modules -- so an SMI harness has '
                             'nothing to talk to. This also switches the campaign guest to '
                             '"q35,smm=on", which it does NOT run by default whatever an '
                             'earlier version of this text claimed. Costs a larger FV and a '
                             'much slower boot, so it is off by default')
    parser.add_argument('--standalone-mm', action='store_true',
                        help='with --smm, use the StandaloneMM model rather than PiSmmCore, '
                             'which is what installs EFI_MM_COMMUNICATION3_PROTOCOL. Inert '
                             'on its own: OvmfPkgX64.dsc nests the whole StandaloneMM block '
                             'inside !if $(SMM_REQUIRE) == TRUE')
    parser.add_argument('--harness-timing', choices=('application', 'dxe'),
                        default='application',
                        help='when the SMI harness runs. "application" writes it to the '
                             'ESP, which BDS launches AFTER it signals EndOfDxe -- so '
                             'every handler that latches on that event refuses it, and on '
                             'upstream MdeModulePkg alone that is SmmSpi\'s whole '
                             'dispatch, FaultTolerantWriteSmm\'s write path and '
                             'VariableSmm\'s runtime-cache arm. "dxe" builds it into the '
                             'DXE firmware volume as a DXE_DRIVER with a depex, so it '
                             'runs before the latch shuts. Needs --smi, relinks the '
                             'platform per campaign, and the campaign guest is qemu '
                             'either way')
    parser.add_argument('--max-targets', type=int, default=0, metavar='N',
                        help='fuzz at most N of the discovered targets, chosen by name. '
                             '0, the default, fuzzes everything discovered. For a gate '
                             'that has to reach the fuzz and triage stages on several '
                             'versions without spending a full budget on each')
    parser.add_argument('--skip-fuzz', action='store_true',
                        help='qualify a version without spending the fuzzing budget')
    args = parser.parse_args()

    # The boot competes with every other campaign booting at the same time, so a fixed
    # budget is really a different budget at every --jobs. Measured on a 72-core box over
    # 243 campaigns: at --jobs 4 the harness was reached in 108s and 298s; at --jobs 20
    # the median was 495s, the p90 645s and the p99 849s -- against a 900s limit. Four
    # campaigns fell off that edge and reported zero iterations, three of which had fuzzed
    # in the previous run, which reads as a regression and is not one. 90s a job puts the
    # limit at roughly twice the p99 at the parallelism that produced it, and leaves the
    # old 900s floor for small runs. An explicit --boot-timeout still wins.
    boot_timeout_given = bool(args.boot_timeout)
    if not args.boot_timeout:
        args.boot_timeout = max(900, 90 * args.jobs)

    # The benchmark and the sanitizer are gated in the DSC and the FDF, and the same
    # string has to reach the firmware build and the campaign image's analysis build --
    # a benchmark present in one and absent from the other is a campaign fuzzing a
    # protocol the image never installed.
    # The FDF gates are "!ifdef $(SAN_BENCH)", the form upstream uses for CSM_ENABLE, and
    # that form reads a bare -D perfectly well. They were "!ifdef SAN_BENCH", which the DSC
    # parser honours and the FDF parser does not: the drivers compiled -- build.log shows
    # all three -- and DXEFV.inf came back without either FILE_GUID, so the volume never
    # carried them. A campaign then fuzzed a protocol nothing had installed for 22297
    # iterations and reported zero findings, which read as a sanitizer blind to its own
    # benchmark. The exerciser had been saying "no memory protocol -- build with
    # -D SAN_BENCH" the whole time, on a build given exactly that.
    #
    # =TRUE is kept because it is explicit and costs nothing; the gates no longer need it.
    bench_defines = ' -D SAN_BENCH=TRUE -D FW_SAN=TRUE' if args.bench else ''
    # Passthroughs for a build knob this driver does not model. Flattened through shlex
    # rather than str.split so that Foo.Pcd=L"two words" arrives as one token, and the
    # leading -D or --pcd is accepted-and-dropped because that is how anyone who has read
    # a build command will write it.
    def build_knobs(values, flag):
        out_ = []
        for v in values or []:
            for tok in shlex.split(v):
                if tok and tok not in ('-D', '--pcd'):
                    out_.append(tok)
        return out_

    # Both are checked here, before anything is fetched, ported or built. edk2 does reject
    # a malformed macro name itself, but only once build.py is running -- which on this
    # pipeline is several minutes of fetch, submodules, port and BaseTools later.
    extra_defines = ''
    for tok in build_knobs(args.extra_defines, '-D'):
        name = tok.split('=', 1)[0]
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', name):
            sys.exit(f'--extra-defines {tok}: edk2 requires a macro name matching '
                     f'[A-Z][A-Z0-9_]*. build.py would stop at "The macro name must be '
                     f'in the pattern", but only after the tree was already built up to '
                     f'that point.')
        extra_defines += f' -D {tok}'

    # Everything the ANALYSIS build in IMAGE_DOCKERFILE needs that is not a -D macro. The
    # campaign boots that build's OVMF, so a PCD the firmware stage sets and this one does
    # not is a difference between the firmware that was validated and the firmware that
    # runs. Kept beside the extras below for the same reason.
    image_pcds = f'{shared_pcds()} '
    # Filled in below once the caller's extras are parsed, because the firmware build's
    # comment promises them to "every build in the run" and the image build is one.
    image_extra = ''
    extra_pcds = ''
    for tok in build_knobs(args.extra_pcds, '--pcd'):
        if '=' not in tok or '.' not in tok.split('=', 1)[0]:
            sys.exit(f'--extra-pcds {tok}: expected TokenSpaceGuid.PcdName=Value. edk2 '
                     f'takes a name it cannot resolve as "PCD is not in the DSC" or, '
                     f'worse, applies nothing and builds a firmware that merely looks '
                     f'configured, so the form is required up front.')
        extra_pcds += f' --pcd {tok}'
    if extra_defines or extra_pcds:
        print(f'per-codebase build knobs:{extra_defines}{extra_pcds}')
    # The image build gets them too. Its command line is maintained separately from the
    # firmware build's, which is exactly how PcdResetOnMemoryTypeInformationChange ended
    # up set on the build nobody boots: see the note on IMAGE_DOCKERFILE. A caller's knob
    # that reaches one build and not the other produces a campaign whose firmware is not
    # the firmware the run validated.
    image_extra = f'{extra_defines}{extra_pcds} '.lstrip()

    # Small on purpose, and the same number for every build in the run so a failure is
    # reproducible. os.cpu_count() can be None, hence the or 4.
    cores = args.cores if args.cores > 0 else max(1, min(8, (os.cpu_count() or 4) // 4))
    # SMM_REQUIRE is what builds the SMM core and its handlers; STANDALONE_MM_ENABLE only
    # chooses WHICH core, and does nothing by itself because the DSC nests it inside
    # !if $(SMM_REQUIRE) == TRUE. Asking for the model without the foundation is a mistake
    # worth naming rather than silently ignoring.
    # Fuzzing handlers against a firmware with no SMM core is not a degraded run, it is a
    # guaranteed empty one: every handler's Communicate finds no protocol and returns. So
    # this turns SMM on rather than letting the combination look like it was tried.
    if args.smi and not args.smm:
        args.smm = True
        print('--smi implies --smm; building with SMM_REQUIRE=TRUE')
    # The dxe timing is an SMI construction: firness.py only passes the timing to the
    # generator on the --smi path, and the depex it emits is floored on
    # gEfiSmmCommunicationProtocolGuid. Asked for without --smi it would build a
    # UEFI_APPLICATION, place it in the firmware volume and boot an empty ESP -- every
    # target reporting "the boot never reached the harness". firness.py rejects that too;
    # this is the earlier and cheaper place to say so, before a port and a build.
    if args.harness_timing == 'dxe' and not args.smi:
        sys.exit('--harness-timing dxe needs --smi: the dxe harness is a DXE_DRIVER whose '
                 'depex floor is gEfiSmmCommunicationProtocolGuid, emitted only on the '
                 'SMI path. Without --smi the generator would build a UEFI_APPLICATION, '
                 'and placing that in the firmware volume produces a harness nothing '
                 'dispatches and no boot option launches.')
    if args.standalone_mm and not args.smm:
        sys.exit('--standalone-mm needs --smm: OvmfPkgX64.dsc nests the StandaloneMM '
                 'components inside !if $(SMM_REQUIRE) == TRUE, so on its own it builds '
                 'nothing and the run would look like a plain one.')
    smm_defines = (' -D SMM_REQUIRE=TRUE' if args.smm else '') + \
                  (' -D STANDALONE_MM_ENABLE=TRUE' if args.standalone_mm else '')

    # The machine has to offer SMM to firmware built to require it. The campaign fuzzer
    # defaults to a plain "q35" and only takes "q35,smm=on" from this variable, which
    # nothing set: an SMM_REQUIRE image therefore booted on a machine with no SMRAM, got
    # through 56 module constructors in 3600s and never reached the harness -- 0 of 4
    # campaigns, 0 iterations, reported as a boot that needed longer. The same firmware
    # boots to BDS in 369s on a machine that has SMM, which is how the detect probe
    # passed while every campaign failed. fuzz_batch passes FIRNESS_* through to the
    # campaign containers, so setting it here reaches them.
    if args.smm:
        os.environ.setdefault('FIRNESS_QEMU_MACHINE', 'q35,smm=on')

    # The same channel: fuzz_batch forwards every FIRNESS_* into the campaign containers,
    # and firness.py reads the timing from FIRNESS_HARNESS_TIMING. setdefault, not an
    # assignment, so an operator who exported it keeps their value -- and so the default
    # 'application' never overwrites one.
    if args.harness_timing != 'application':
        os.environ['FIRNESS_HARNESS_TIMING'] = args.harness_timing
        print(f'harness timing: {args.harness_timing} -- the harness is linked into the '
              f'DXE firmware volume, so the platform is relinked once per campaign')

    slug = re.sub(r'[^A-Za-z0-9._-]', '-', args.ref)
    # Absolute, because several stages hand this to "docker run -v", and a relative
    # path there is read as a named volume rather than a directory: "includes invalid
    # characters for a local volume name". The default is already absolute, so only an
    # explicit --out could trip it -- and when it did, it failed the run at the detects
    # stage, after the image had already been rebuilt.
    out = os.path.abspath(args.out or os.path.join(results_base(), f'fuzz-{slug}'))
    work = os.path.abspath(args.work) if args.work else REPO
    os.makedirs(work, exist_ok=True)
    # Both of these used to be unconditionally inside REPO. In CI that is the checkout, and
    # a worktree plus a build context left there is what broke the following job: its
    # actions/checkout could neither clean nor re-clone, and the workspace ended up with no
    # .git at all.
    tree = os.path.join(work, 'eval_source', f'edk2-{slug}')
    os.makedirs(os.path.dirname(tree), exist_ok=True)
    run = Run(args.ref, out)
    run.base_image = args.base_image

    # Several stages hand `out` and `work` to "docker run -v". On this host a bind mount
    # from /tmp silently yields an EMPTY directory inside the container, so the detect probe
    # reports "--code, --vars, --selftest given but not on disk" for files that are plainly
    # there, and a campaign writes its results into nowhere. Checked here, once, because the
    # symptom points at the wrong thing every time.
    # Before the probe, not after: the probe runs a container from this image, so a host
    # that simply has not been bootstrapped yet would otherwise be reported as a bind mount
    # failure -- blaming the path, and sending the reader to /tmp, for a missing image.
    if sh(['docker', 'image', 'inspect', args.base_image]).returncode:
        sys.exit(f'{args.base_image} is not present, so nothing can run in a container yet '
                 f'-- run scripts/bootstrap_runner.sh')
    for name, path in (('--out', out), ('--work', work)):
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, '.mount-probe')
        with open(probe, 'w') as handle:
            handle.write('probe')
        seen = sh(['docker', 'run', '--rm', '-v', f'{path}:/probe',
                   '--entrypoint', 'sh', args.base_image, '-c',
                   'test -f /probe/.mount-probe && echo VISIBLE'], timeout=120)
        os.remove(probe)
        if 'VISIBLE' not in seen.stdout:
            sys.exit(f'{name} {path} cannot be bind mounted into a container: a file written '
                     f'there is not visible inside one. On this host that is what any path '
                     f'under /tmp does. Use a path under the repository or the runner, and '
                     f'note the failure it would otherwise cause is reported as missing '
                     f'files rather than as a mount problem.')
    run.evalset = ''
    run.target_count = 0
    image_tag = f'fuzzuer-{slug.lower()}:latest'
    os.makedirs(out, exist_ok=True)
    print(f'=== fuzzing edk2 {args.ref} -> {out} ===')

    def ready():
        """Say what is missing before spending an hour finding out."""
        gone = []
        for image in (args.base_image,):
            if sh(['docker', 'image', 'inspect', image]).returncode:
                gone.append(f'image {image}')
        up = sh(['docker', 'ps', '-q', '--filter', f'name=^{args.builder}$'])
        if not up.stdout.strip():
            gone.append(f'container {args.builder}')
        if gone:
            return False, (f'{", ".join(gone)} missing -- run '
                           f'scripts/bootstrap_runner.sh')
        return True, f'{args.base_image} and {args.builder} are up'

    def fetch():
        if os.path.isdir(tree):
            sh(['git', '-C', args.source, 'worktree', 'remove', '--force', tree])
            shutil.rmtree(tree, ignore_errors=True)
        # A registration can outlive its directory, and then "worktree add" refuses the
        # path while nothing on disk explains why. That is the normal state in CI:
        # actions/checkout cleans the workspace between runs, which deletes the worktree
        # and leaves the record in .git/modules/<sub>/worktrees -- git calls it "prunable".
        # The removal above only runs when the directory is still there, so without this a
        # second run in the same workspace always failed at fetch with a bare
        # "fatal: '<path>'" and a stage that had worked by hand every time.
        sh(['git', '-C', args.source, 'worktree', 'prune'])
        got = sh(['git', '-C', args.source, 'rev-parse', '--verify', f'{args.ref}^{{commit}}'])
        if got.returncode:
            # Whichever remote this checkout actually has. Fetching from a hardcoded
            # "tianocore" works for the edk2 mirror this started with and fails for every
            # vendor tree -- NVIDIA's clone calls its remote "origin" -- so a ref that is
            # not already local would have failed with "no such remote" rather than
            # anything about the ref.
            remotes = sh(['git', '-C', args.source, 'remote']).stdout.split()
            ordered = [r for r in ('tianocore', 'origin') if r in remotes]
            ordered += [r for r in remotes if r not in ordered]
            fetched = None
            for remote in ordered:
                fetched = sh(['git', '-C', args.source, 'fetch', '--depth=1', remote,
                              args.ref], timeout=1800)
                if not fetched.returncode:
                    break
            if fetched is None:
                return False, f'{args.source} has no git remote to fetch {args.ref} from'
            if fetched.returncode:
                return False, (f'no such ref, and fetch from {", ".join(ordered)} failed: '
                               f'{fetched.stderr.strip()[:80]}')
        made = sh(['git', '-C', args.source, 'worktree', 'add', '--detach', tree, args.ref],
                  timeout=1800)
        if made.returncode:
            return False, made.stderr.strip()[:100]
        sha = sh(['git', '-C', tree, 'rev-parse', '--short', 'HEAD']).stdout.strip()
        return True, f'{args.ref} at {sha}'

    def submodules():
        mods = os.path.join(tree, '.gitmodules')
        if not os.path.isfile(mods):
            return True, 'none declared'
        paths = re.findall(r'path\s*=\s*(\S+)', open(mods).read())
        # The exit code is READ. It used to be discarded, and that is how a git
        # invocation which exited 1 -- aborting partway through, leaving 10 of 11
        # submodules off their recorded commit -- was reported as `PASS 10/11 populated`,
        # with the port stage three steps later as the first sign of trouble.
        did = sh(['git', '-C', tree, 'submodule', 'update', '--init', '--depth=1'],
                 timeout=3600)
        if did.returncode:
            blame = [l for l in (did.stderr or '').splitlines()
                     if 'Failed to clone' in l or 'aborting' in l]
            print(f'  git submodule update exited {did.returncode}'
                  + (f': {blame[-1][:120]}' if blame else ''))
        # Shallow because it is much cheaper, then the checkout finished for anything the
        # abort skipped. See repair_submodules for what that failure actually looks like.
        still_wrong = repair_submodules(tree)
        # isdir first: listdir on a path that is not there raises, and the stage then
        # fails with a FileNotFoundError naming a directory rather than saying which
        # submodule did not come down.
        empty = [p for p in paths
                 if os.path.isdir(os.path.join(tree, p))
                 and not os.listdir(os.path.join(tree, p))]
        # only the ones the build actually reaches matter; the rest are noise
        needed = [p for p in empty if any(k in p for k in
                  ('brotli', 'mipisyst', 'openssl', 'mbedtls'))]
        if needed:
            return False, f'{len(needed)} required submodule(s) empty: {needed[0]}'
        # Said here rather than letting the port stage refuse the tree with a message that
        # names neither submodules nor depth.
        if still_wrong:
            return False, (f'{len(still_wrong)} submodule(s) are not at the commit this '
                           f'tree records, even after a full fetch '
                           f'({", ".join(still_wrong[:3])}) -- the tree is dirty and the '
                           f'port stage will refuse it')
        return True, f'{len(paths) - len(empty)}/{len(paths)} populated'

    def port():
        # The tool lives with the sanitizer, in uefi_asan, because it is how you apply
        # that sanitizer to any edk2 rather than something this pipeline does privately.
        # Anyone with a checkout can run it the same way: apply_asan.py --to <tree>.
        apply = os.path.join(REPO, 'uefi_asan', 'apply_asan.py')
        if not os.path.isfile(apply):
            return False, f'{apply} is missing; is the uefi_asan submodule checked out?'
        argv = [sys.executable, apply, '--to', tree]
        # --from is where the sanitizer integration is TAKEN FROM, not the tree being
        # fuzzed. Deriving it from --source is right only while --source is the fork that
        # carries the port, and wrong the moment it is a vendor tree: pointing it at
        # NVIDIA/edk2 asked apply_asan to lift the port out of a tree that does not have
        # one, and the run died with "165 clean, 3 failed -- the port did not land" while
        # the same tree ports with zero failures when --from names the fork. Left unset,
        # apply_asan uses its own default, which IS the fork.
        if args.port_from:
            argv += ['--from', args.port_from]
        if args.port_base:
            argv += ['--base', args.port_base]
        done = sh(argv, timeout=1800)
        text = done.stdout + done.stderr
        log = text
        # A tree with no upstream history cannot 3-way merge. apply_asan rebases the port
        # onto the target by applying each modified file against the version at the PORT
        # BASE, and `git apply -3` needs that pre-image blob in the TARGET repository's
        # object store. A squashed vendor import does not have it -- nor does anything
        # else whose history was not inherited from the tree the port sits on -- and the
        # failure reads per file as "repository lacks the necessary blob to perform 3-way
        # merge", which says nothing about history or about where the blob could come
        # from. Measured on an edk2 imported as 7 squashed commits: 28 files merged
        # cleanly and the 2 that did not were the OVMF platform description and its FDF,
        # so the run stopped at port and the firmware was never built.
        #
        # The port base is a commit in the tree the port is TAKEN FROM, which is on this
        # filesystem, so this is a local fetch: no network, and it costs the blobs of one
        # commit rather than a whole history.
        if 'lacks the necessary blob' in text:
            base = re.search(r'port base\s+([0-9a-f]{7,40})', text)
            src = os.path.abspath(args.port_from
                                  or os.path.join(REPO, 'eval_source', 'edk2'))
            if not base:
                print('  the port base blobs are missing and port.log does not name the '
                      'base, so there is nothing to fetch')
            # Asked of git, not guessed from the filesystem. A SUBMODULE's `.git` is a
            # 44 byte text file holding `gitdir: ...`, not a directory, and the port
            # source normally IS a submodule -- so `os.path.isdir(src/'.git')` is False
            # for exactly the common case and this fetch silently never ran. The shell
            # side of this repository already knew: action-smoke.yml and checks.yml both
            # test `-e "$sub/.git"`, not `-d`.
            elif sh(['git', '-C', src, 'rev-parse', '--git-dir'], timeout=60).returncode:
                print(f'  the port base blobs are missing and {src} is not a git '
                      f'checkout to fetch them from')
            else:
                # Resolved to a FULL object name first. `git fetch <url> <sha>` takes
                # only a complete 40 character name, and apply_asan prints the base
                # abbreviated to 12 -- so fetching what it printed fails with "couldn't
                # find remote ref 1eeca0750af5", which reads as though the commit were
                # missing from the source rather than merely abbreviated. Measured both
                # ways: the 12 character form fails, the 40 character form fetches it.
                seen = sh(['git', '-C', src, 'rev-parse',
                           base.group(1) + '^{commit}'], timeout=60)
                sha = seen.stdout.strip()
                if seen.returncode or not sha:
                    print(f'  port base {base.group(1)[:12]} is not in {src} either, so '
                          f'there is nowhere to fetch it from')
                    sha = ''
                if sha:
                    print(f'  this tree lacks the blobs for port base {sha[:12]}, which '
                          f'is what a squashed or unrelated history means; fetching them '
                          f'from {src}')
                    got = sh(['git', '-C', tree, 'fetch', '--no-tags', '--quiet', src,
                              sha], timeout=1800)
                else:
                    got = None
                if got is None:
                    pass
                elif got.returncode:
                    why = (got.stderr or '').strip().splitlines()
                    print(f'  that fetch failed, so the port fails the same way: '
                          f'{why[-1][:120] if why else "no output"}')
                else:
                    # The tree has to go back to clean first. The failed attempt applied
                    # 28 of its 30 files before stopping, and apply_asan refuses to port
                    # onto a tree with uncommitted changes -- so the retry did not retry
                    # anything, it just failed differently, with
                    # "M CryptoPkg/Library/BaseCryptLib/PeiCryptLib.inf".
                    #
                    # Safe because this IS a throwaway worktree of the ref, made by this
                    # run: nothing of the caller's is in it, and the port's own output is
                    # exactly what has to go. Deliberately WITHOUT
                    # --recurse-submodules, and `clean -fd` rather than -ffd, so the
                    # submodules survive -- they were just repaired, and re-cloning
                    # OpenSSL costs minutes. Measured: clean afterwards, all 10 still
                    # populated, the port's 94 copied files gone.
                    sh(['git', '-C', tree, 'reset', '--hard', '--quiet'], timeout=600)
                    sh(['git', '-C', tree, 'clean', '-fdq'], timeout=600)
                    # The counts below must come from the RETRY, not from the attempt that
                    # already failed: both texts contain a "merged cleanly" line and
                    # re.search takes the first, so parsing the concatenation would report
                    # the failure even when the retry applied everything.
                    retried = sh(argv, timeout=1800)
                    text = retried.stdout + retried.stderr
                    log += ('\n=== retried after fetching the port base ===\n' + text)
                    done = retried
        # Kept, not discarded. The detail line below carries parsed counts, so a tool that
        # fell over before printing any left "? clean, -1 failed" and nothing anywhere
        # said why -- three CI runs failed here before the reason (a shallow reference
        # checkout with no port base) could be read at all.
        # The whole transcript, both attempts if there were two, while the counts above
        # are parsed from the attempt that decided the outcome.
        open(os.path.join(out, 'port.log'), 'w').write(log)
        clean = re.search(r'merged cleanly\s+(\d+)', text)
        fixed = re.search(r'conflicts resolved\s+(\d+)', text)
        left = re.search(r'conflicts REMAINING\s+(\d+)', text)
        failed = re.search(r'could not apply\s+(\d+)', text)
        nfail = int(failed.group(1)) if failed else -1
        nleft = int(left.group(1)) if left else -1
        detail = (f'{clean.group(1) if clean else "?"} clean, '
                  f'{fixed.group(1) if fixed else "?"} resolved, {nleft} unresolved, '
                  f'{nfail} failed')
        if nfail == -1 and nleft == -1:
            # No counts at all means it did not get as far as applying anything, so the
            # counts are not the story -- what it said is.
            said = [line.strip() for line in text.splitlines() if line.strip()]
            why = said[-1][:100] if said else f'it printed nothing'
            return False, (f'apply_asan reported no counts (exit {done.returncode}): '
                           f'{why} -- see port.log')
        if nfail != 0 or nleft != 0:
            return False, detail + ' -- the port did not land'
        # a marker left anywhere makes the build fail somewhere else entirely
        stray = sh(f"grep -rl '^<<<<<<< ' {tree} 2>/dev/null | head -3").stdout.strip()
        if stray:
            return False, f'conflict markers left in {stray.splitlines()[0]}'
        # After the port, deliberately: see apply_build_options on why the order matters.
        added = apply_build_options(tree, args.extra_build_options)
        # Also after the port: it is the port that puts CLANGSAN in the template, and this
        # copies what it added into a Conf/ the tree committed. See sync_committed_conf.
        sync_committed_conf(tree)
        return True, detail

    def vendor():
        """Repair defects the vendor tree ships, and say which ones were there.

        A vendor branch can add a library class, declare it, provide an instance, resolve
        it for the platforms it cares about, and leave OvmfPkg unresolvable -- their OVMF
        does not have to build for their product to ship. That is not something the
        sanitizer port can fix and not something to discover halfway through a build log,
        so it is repaired here, named, and reported.

        Each entry only ever adds a resolution the tree itself already provides, and only
        where the class really is unresolved, so an upstream tree comes back untouched.
        """
        fixups = [
            # NVIDIA/edk2, main-edk2-stable202508 and neighbours. VariableRuntimeDxe --
            # which every OvmfPkg DSC builds -- consumes VarSetCallbacksLib. It is
            # declared in MdeModulePkg.dec and resolved in MdeModulePkg.dsc and
            # UefiPayloadPkg.dsc; no OvmfPkg DSC resolves it, so OVMF X64 fails AutoGen
            # with "error 4000: VarSetCallbacksLib not found" before a line is compiled.
            # Reported at <pending>; the Null instance is theirs, not ours.
            dict(cls='VarSetCallbacksLib',
                 instance='MdeModulePkg/Library/VarSetCallbacksLibNull/'
                          'VarSetCallbacksLibNull.inf',
                 why='NVIDIA consumes it in VariableRuntimeDxe and resolves it nowhere '
                     'OvmfPkg can see'),
        ]

        dscs = [os.path.join(tree, 'OvmfPkg', name) for name in
                ('OvmfPkgX64.dsc', 'OvmfPkgIa32X64.dsc', 'OvmfPkgIa32.dsc')]
        dscs = [d for d in dscs if os.path.isfile(d)]
        if not dscs:
            return False, 'no OvmfPkg DSC in this tree'

        applied = []
        for fix in fixups:
            # Consumed by something, and shipped with an instance: without both, adding
            # a resolution would be inventing a dependency rather than repairing one.
            consumers = sh(f"grep -rl '^[[:space:]]*{fix['cls']}[[:space:]]*$' "
                           f"{tree} --include=*.inf 2>/dev/null | head -1").stdout.strip()
            if not consumers or not os.path.isfile(os.path.join(tree, fix['instance'])):
                continue

            for dsc in dscs:
                text = open(dsc, newline='').read()
                if fix['cls'] in text:
                    continue
                # Into the platform's own [LibraryClasses], which is the common
                # fall-back every module type inherits. Appending after the header keeps
                # it clear of the architecture-specific overrides further down.
                nl = '\r\n' if '\r\n' in text else '\n'
                marker = '[LibraryClasses]' + nl
                if marker not in text:
                    return False, f'{os.path.basename(dsc)} has no [LibraryClasses]'
                line = f"  {fix['cls']}|{fix['instance']}{nl}"
                text = text.replace(marker, marker + line, 1)
                with open(dsc, 'w', newline='') as handle:
                    handle.write(text)
                applied.append(f"{fix['cls']} -> {os.path.basename(dsc)}")

        if not applied:
            return True, 'nothing to repair'
        return True, f"{len(applied)} vendor defect(s): {'; '.join(applied)}"

    def in_builder():
        """Where this tree lives inside the toolchain container."""
        return f'/workspace/tmp/edk2-{slug}'

    def sync():
        # the toolchain container cannot see the host tree; ship it once
        dest = in_builder()
        docker(args.builder, f'rm -rf {dest} && mkdir -p {dest}')
        tar = subprocess.Popen(['tar', '-cf', '-', '--exclude=.git', '-C', tree, '.'],
                               stdout=subprocess.PIPE)
        take = subprocess.Popen(['docker', 'exec', '-i', args.builder, 'tar', '-xf', '-',
                                 '-C', dest], stdin=tar.stdout)
        tar.stdout.close()
        take.communicate()
        got = docker(args.builder, f'ls {dest}/OvmfPkg/OvmfPkgX64.dsc >/dev/null && echo ok')
        return ('ok' in got.stdout), 'tree staged in the builder'

    def build_firmware(defines, logname):
        dest = in_builder()
        # edksetup copies the templates into Conf/ only when they are absent, so a Conf/
        # left by an earlier run is used as-is. A previous port that left conflict markers
        # in tools_def.template therefore keeps failing the build long after the port is
        # fixed, and the error names a line number in a generated file rather than a merge.
        docker(args.builder, f'rm -rf {dest}/Conf && mkdir -p {dest}/Conf')
        script = (f'export WORKSPACE={dest} EDK_TOOLS_PATH={dest}/BaseTools '
                  f'CONF_PATH={dest}/Conf '
                  f'CLANGSAN_BIN=/workspace/llvm-15.0.7/build/bin/ '
                  f'PYTHON_COMMAND=$(command -v python3); cd {dest} && '
                  f'source edksetup.sh >/dev/null 2>&1 && '
                  # BaseTools generates VfrCompile's parser with antlr and does not
                  # declare every dependency, so a wide -j races: on edk2-stable202602
                  # at -j72 the compiler read a half-written Pccts header and stopped at
                  # "AParser.h:300: expected initializer before 'if'", while the same
                  # tree at -j8 builds it cleanly. A failure here also has to be fatal --
                  # it used to be followed by ';', so a missing VfrCompile surfaced much
                  # later as clang being handed a .c file that was never generated.
                  f'{{ make -C BaseTools -j8 || make -C BaseTools -j1 ; }} '
                  f'>/tmp/bt-{slug}.log 2>&1; '
                  f'test -x BaseTools/Source/C/bin/VfrCompile -a '
                  f'-x BaseTools/Source/C/bin/GenFw || '
                  f'{{ echo "BASETOOLS-FAILED"; tail -30 /tmp/bt-{slug}.log; exit 1; }}; '
                  f'build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc '
                  f'{defines}{NETWORK_DEFINES} -D FD_SIZE_IN_KB=8192 '
                  # See SHARED_PCDS for why each of these is here. The analysis build
                  # in IMAGE_DOCKERFILE takes the same list, from the same constant.
                  f'{shared_pcds()} '
                  # Last, so --extra-defines/--extra-pcds can override any of the above
                  # and not merely add to it. Every build in the run gets them, including
                  # the detect probe, because a knob a codebase needs to build at all is
                  # not optional for one of the builds.
                  f'{extra_defines}{extra_pcds} '
                  f'-n {cores}')
        done = docker(args.builder, script, timeout=7200)
        text = done.stdout + done.stderr
        open(os.path.join(out, logname), 'w').write(text)
        if 'BASETOOLS-FAILED' in text:
            why = [l for l in text.splitlines() if 'error' in l.lower()][:1]
            return False, ('BaseTools did not build: '
                           + (why[0][:90] if why else 'see the log'))
        if '- Done -' not in text:
            return False, (build_error(text)[:160] or 'build did not finish')
        return True, text

    def build_fitting(defines, logname):
        """build_firmware, growing DXEFV once if the volume overflowed.

        A volume that overflowed is the one build failure the pipeline can fix by itself,
        and it has to: the port sizes the volumes for its own configuration, so turning
        SMM on made every build fail at GenFv with the volume 1.6 MB short. GenFv states
        what it needed, so there is nothing to guess at.

        Shared, because the retry used to live in the campaign build alone while the
        DETECT PROBE -- which is the LARGER image, carrying SanBenchSmm, SanBenchDrive and
        FwSanDxe on top of the same SMM configuration -- called build_firmware directly
        and had none of it. Measured on run 43226389330: the campaign image built at
        70% full and the probe then failed with 'the required fv image size 0x26933e0
        exceeds the set fv image size', so the SMM benchmark could not be scored at all
        and the stage reported a build failure rather than a volume that needed 2 MB.
        Returns (ok, text_or_reason).
        """
        ok_, text = build_firmware(defines, logname)
        if ok_:
            return True, text
        short = re.search(r'required fv image size 0x([0-9A-Fa-f]+) exceeds the set '
                          r'fv image size 0x([0-9A-Fa-f]+)', text)
        if not short:
            return False, text
        grew = grow_dxe_fv(tree, int(short.group(1), 16))
        if not grew:
            return False, (f'the firmware volume needs 0x{short.group(1)} and is '
                           f'0x{short.group(2)}, and this [FD.MEMFD] layout is '
                           f'not one the resize understands -- enlarge DXEFV by '
                           f'hand')
        print(f'  the firmware volume was too small; {grew}')
        ok_sync, _ = sync()
        if not ok_sync:
            return False, text
        return build_firmware(defines, logname)

    def build():
        defines = ('-D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FIRNESS_QEMU_CRASH=TRUE'
                   + bench_defines + smm_defines)
        ok_, text = build_fitting(defines, 'build.log')
        if not ok_:
            return False, text
        # The campaign's own builds have to be this configuration, not a guess at it.
        # firness.py builds twice inside the campaign container -- the analysis build, and
        # under the dxe harness timing a relink of the platform whose .fd the fuzzer then
        # boots -- and both read FIRNESS_ANALYSIS_DEFINES. Nothing set it, so both used a
        # hardcoded default with no SMM_REQUIRE in it while this build had one: on
        # edk2-stable202608 the relink then lost every module at its link step (run
        # 42723218264). This is the string that actually worked, after any volume resize,
        # so it is the only safe thing to hand them. setdefault, so an operator who
        # exported their own keeps it.
        os.environ.setdefault('FIRNESS_ANALYSIS_DEFINES', defines.strip())
        fill = re.search(r'FVMAIN_COMPACT \[(\d+)%Full\]', text)
        return True, f'firmware built{", FV " + fill.group(1) + "% full" if fill else ""}'

    def instrumented():
        # "applied" is not "instrumented". The symbols an instrumented module carries are
        # __asan_load/__asan_store/__asan_gen_; __asan_report lives in the runtime, and
        # grepping for it reports 0 of 272 on a fully instrumented build.
        dest = in_builder()
        got = docker(args.builder,
                     f'n=0; t=0; for f in $(find {dest}/Build/OvmfX64 -name "*.debug" '
                     f'2>/dev/null); do t=$((t+1)); '
                     f'nm "$f" 2>/dev/null | grep -qE "__asan_(load|store|gen_)" '
                     f'&& n=$((n+1)); done; echo "$n/$t"', timeout=1800)
        ratio = got.stdout.strip().splitlines()[-1] if got.stdout.strip() else '0/0'
        hit, total = (ratio.split('/') + ['0'])[:2]
        if not total.isdigit() or int(total) == 0:
            return False, 'no built modules to check'
        if int(hit) == 0:
            return False, f'{ratio} -- nothing instrumented'
        # A floor, not just "something was instrumented". Getting full scope to boot took
        # four separate fixes and the healthy value here is near-total -- every run in
        # results/ sits between 218/220 and 276/276, i.e. 99% or better. A partial collapse
        # is the dangerous shape: the firmware still boots, the campaigns still run, and a
        # sweep over uninstrumented modules reports a clean result that means nothing.
        # 90% leaves room for the handful of modules the scope deliberately excludes
        # without admitting the case where most of the image lost its checks.
        share = int(hit) / int(total)
        if share < 0.90:
            return False, (f'{ratio} = {share:.0%} instrumented, under the 90% floor. A '
                           f'sweep over uninstrumented firmware reports clean and means '
                           f'nothing, so this stops the run')
        # The symbol count alone overstates SMM, badly. Say what the modules' own code
        # carries, and name the SMM ones, because a campaign that drives an SMI handler
        # whose driver is not instrumented reports clean for a reason that has nothing to
        # do with the firmware being correct.
        detail = f'{ratio} images carry ASan symbols'
        log = os.path.join(out, 'build.log')
        if os.path.isfile(log):
            own, total, dark = own_code_instrumented(open(log, errors='replace').read(),
                                                    tree)
            detail += f'; {own}/{total} modules have their own code instrumented'
            smm = [m for m, kind in dark if 'SMM' in (kind or '').upper()]
            if smm:
                shown = ', '.join(m.split('/')[-1] for m in smm[:6])
                detail += (f'. NONE of the {len(smm)} SMM module(s) are -- {shown}'
                           f'{" ..." if len(smm) > 6 else ""} -- so a defect in an SMI '
                           f'handler\'s own code raises no report; only the instrumented '
                           f'libraries it links can')
        return True, detail

    def discover():
        evalset = os.path.join(REPO, 'eval_source', f'evalset-{slug}')
        shutil.rmtree(evalset, ignore_errors=True)
        # Scope the scan to the packages that actually produced modules for this
        # firmware. The build output is the ground truth for that -- no DSC parsing and
        # no list to keep current. Without it the tree's ArmPkg and EmbeddedPkg headers
        # contribute targets an OVMF X64 image cannot install, and each one spends a
        # container, an analysis and a build to discover it does not link.
        built = docker(args.builder,
                       f'ls {in_builder()}/Build/OvmfX64/DEBUG_CLANGSAN/X64 2>/dev/null')
        packages = sorted(d for d in built.stdout.split() if d.endswith('Pkg'))
        argv = [sys.executable, os.path.join(HERE, 'gen_protocol_inputs.py'),
                '-s', tree, '-o', evalset, '-m', '1']
        # Only when the drivers are actually in the image. Discovery reads headers,
        # so without this the benchmark protocols are found on every run and each
        # one spends a boot budget waiting for a protocol nothing installed.
        if args.bench:
            argv.append('--bench')
        if packages:
            argv += ['--packages'] + packages
        sh(argv, timeout=3600)
        smi = os.path.join(evalset, 'DiscoveredSmi.txt')
        sh([sys.executable, os.path.join(HERE, 'discover_smi.py'),
            '-s', tree, '-o', smi], timeout=3600)
        # DiscoveredSmi.txt shares this directory with the protocol request files but is
        # not one: it is the handler list written just above. Counting it made the planned
        # campaign count one too many, and the batch fuzzed it as a protocol -- a
        # container, a full analysis and a build spent to die in the generator with "no
        # target functions were resolved". fuzz_batch.py skips it by name for the same
        # reason, unless it is running in --smi mode, which is what the file is for.
        protos = len([f for f in os.listdir(evalset)
                      if f.endswith('.txt') and f != os.path.basename(smi)]) \
            if os.path.isdir(evalset) else 0
        handlers = len([l for l in open(smi).read().split('\n') if l.strip()]) \
            if os.path.isfile(smi) else 0
        if protos == 0:
            return False, 'no protocols discovered'
        run.evalset = evalset
        # Under --smi the handler list is one more target: fuzz_batch stops excluding
        # DiscoveredSmi.txt by name and firness.py --smi generates every handler in it into
        # a single harness, dispatched by the selector byte. Counting it matters because the
        # fuzz stage sizes its own timeout from this number.
        run.target_count = protos + (1 if args.smi and handlers else 0)
        scope = f' from {len(packages)} package(s)' if packages else ''
        if args.smi:
            if not handlers:
                return False, ('--smi was asked for and discovery found no SMI handlers in '
                               'this tree, so there is nothing to fuzz')
            # The SMI harness DOES generate. This note used to say the opposite --
            # that the campaign image bakes its compilation database once from a build
            # with no SMM modules, so the analyser sees no handler registration, the map
            # comes back null and the generator dies in load_smi_data. That was true
            # until 0d47e191 made the image's analysis build carry the SMM defines, and
            # it has been wrong ever since while still being printed on every run.
            #
            # Verified on the EVAL-1 tree, analyser plus generator, no boot needed:
            # smi-function-guid-map.json came back a dict of 10 entries and the run
            # reported "Generated Harness" and "Compiled Harness". A null map still shows
            # up on a PROTOCOL run, which is expected and harmless -- nothing asked for
            # the SMI analysis there -- and mistaking one for the other is what kept the
            # stale note alive.
            #
            # The note that used to sit here said no campaign on an SMM_REQUIRE image had
            # ever reached a harness and that this target would therefore find nothing.
            # That stopped being true on run 42154605158: the boot reached the harness in
            # 58s, 11 targets dispatched, the corpus grew 0 -> 20 over 2606 edges, and the
            # campaign ended early only because its 21st input ASSERTed inside SMM and
            # CpuDeadLoop()ed the guest -- which SHARED_PCDS now prevents. Leaving the note
            # in place would tell the next reader to disregard a result that is real.
            return True, (f'{protos} protocols{scope}, {handlers} SMI handlers found in '
                          f'source; the SMI harness generates and campaigns on this image '
                          f'do reach it')
        # Said plainly, because the count on its own reads as though they were targets:
        # without --smi these are discovered and then left alone.
        return True, (f'{protos} protocols{scope}, {handlers} SMI handlers '
                      f'(not fuzzed; pass --smi)')

    def stage_image():
        """A campaign image whose harness tree is the version under test.

        Campaigns run firness.py -s /workspace/tmp, so both the analysis and the harness
        build come from the tree baked into the image. Fuzzing every version against the
        image's own edk2 measures one tree over and over and files each result under
        whichever ref the matrix happened to name.
        """
        dest = in_builder()
        stage = os.path.join(work, 'imgstage', slug)
        shutil.rmtree(stage, ignore_errors=True)
        os.makedirs(os.path.join(stage, 'qemu_fw'))
        os.makedirs(os.path.join(stage, 'edk2'))
        # source only: the campaign rebuilds the harness, and Build/ is most of the tree
        sh(f'tar -cf - --exclude=.git --exclude=Build -C {tree} . | '
           f'tar -xf - -C {stage}/edk2', timeout=1800)
        hunt = docker(args.builder,
                      f'find {dest}/Build \\( -name OVMF_CODE.fd -o -name OVMF_VARS.fd '
                      f'-o -name AsanSelfTest.efi \\) 2>/dev/null | sort')
        wanted = {}
        for line in hunt.stdout.split():
            wanted.setdefault(os.path.basename(line), line)
        for name in ('OVMF_CODE.fd', 'OVMF_VARS.fd', 'AsanSelfTest.efi'):
            if name not in wanted:
                return False, f'{name} is not in the build output'
            got = sh(['docker', 'cp', f'{args.builder}:{wanted[name]}',
                      os.path.join(stage, 'qemu_fw', name)], timeout=900)
            if got.returncode:
                return False, f'could not take {name} out of the builder'
        for src_dir, name in ((os.path.join(REPO, 'scripts'), 'scripts'),
                             (os.path.join(REPO, 'firness', 'harness_generator'),
                              'harness_generator'),
                             (os.path.join(REPO, 'firness', 'HarnessHelpers'),
                              'HarnessHelpers')):
            if not os.path.isdir(src_dir):
                return False, f'{name} is missing from the checkout'
            shutil.copytree(src_dir, os.path.join(stage, name),
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        open(os.path.join(stage, 'Dockerfile'), 'w').write(
            IMAGE_DOCKERFILE.format(base=args.base_image, bench=bench_defines,
                                    pcds=image_pcds + image_extra,
                                    smm=smm_defines, cores=cores))
        # Not -q. Quiet mode prints the image id and throws the build away, so a failed
        # image build left only its last line -- truncated to 110 characters in run.json --
        # and nothing to diagnose from. The image build runs a full harness build inside the
        # container, which is exactly the kind of failure that needs its output.
        built = sh(['docker', 'build', '-t', image_tag,
                    '-f', os.path.join(stage, 'Dockerfile'), stage], timeout=5400)
        open(os.path.join(out, 'image.log'), 'w').write(built.stdout + built.stderr)
        if built.returncode:
            tail = (built.stdout + built.stderr).strip().splitlines()
            return False, ((tail[-1][:110] if tail else 'docker build failed')
                           + ' -- full output in image.log')
        return True, f'{image_tag} carries this tree'

    def detects():
        """Firmware whose shadow is unmapped, and a runtime that never reports, look
        exactly like firmware with no bugs in it. Nothing downstream means anything until
        a deliberate error has been seen caught.

        This needs a second build of the same tree. Under ASAN_FUZZER=qemu the runtime
        reports a finding by executing LibAFL's custom instruction, which outside LibAFL
        is simply an invalid opcode: the sanitizer arms at ReadyToBoot, the first finding
        raises #UD, and the guest dies in CpuDxe's exception handler before BDS ever
        launches the self test. The same tree with the same instrumentation, reporting to
        the serial port instead, answers the question the check is really asking -- is the
        shadow mapped and does the runtime report.

        It reuses the build directory, which by this point has already been copied into
        the campaign image, so overwriting it costs nothing.
        """
        # ASAN_FUZZER defaults to qemu inside the DSC, so omitting it changes
        # nothing; the DSC's own comment names -D ASAN_FUZZER=none for this.
        #
        # bench_defines belongs here too, and leaving it out made the scoreboard
        # unscorable. This build REPLACES the firmware the benchmark is then booted
        # against, so without SAN_BENCH the SanBenchDxe driver is not in it -- while
        # SanBenchDrive.efi survives in the shared Build tree from the campaign build and
        # is still found. The application therefore boots, finds no protocol to call, and
        # every one of the twelve classes reports UNBUILT: "0 of 0 scorable classes
        # detected", which reads as a benchmark with nothing in it rather than as a probe
        # built without the drivers.
        #
        # The probe asks for them unconditionally rather than following --bench. The
        # scoreboard is the most capable ground truth here -- eleven classes, four of them
        # visible only to a firmware-specific check -- and it was reachable only by
        # passing a flag that action.yml defaults to false and that no workflow sets, so
        # it had never run in CI. Three workflows upload a bench_cases.log that nothing
        # wrote. Both modules are gated by SAN_BENCH/FW_SAN in the DSC and the FDF alike,
        # and this build replaces only the probe firmware, never the campaign image, so
        # asking for them here cannot put a positive control in front of the fuzzer.
        probe_defines = ' -D SAN_BENCH=TRUE -D FW_SAN=TRUE'
        ok_, text = build_fitting('-D ASAN_SCOPE=full -D ASAN_FUZZER=none'
                                  + probe_defines + smm_defines,
                                  'detect-build.log')
        if not ok_:
            return False, f'the check build failed: {text}'
        dest = in_builder()
        probe = os.path.join(out, 'detect_fw')
        shutil.rmtree(probe, ignore_errors=True)
        os.makedirs(probe)
        hunt = docker(args.builder,
                      f'find {dest}/Build \\( -name OVMF_CODE.fd -o -name OVMF_VARS.fd '
                      f'-o -name AsanSelfTest.efi -o -name SanBenchDrive.efi '
                      f'\\) 2>/dev/null | sort')
        found = {}
        for line in hunt.stdout.split():
            found.setdefault(os.path.basename(line), line)
        for name in ('OVMF_CODE.fd', 'OVMF_VARS.fd', 'AsanSelfTest.efi'):
            if name not in found:
                return False, f'the check build produced no {name}'
            sh(['docker', 'cp', f'{args.builder}:{found[name]}',
                os.path.join(probe, name)], timeout=900)
        # Optional, unlike the three above: the benchmark drivers only exist when the build
        # was given -D SAN_BENCH, and a run without them is not a failure. Finding it and
        # not copying it is how the scoreboard below would have reported "drivers absent"
        # on every run, including the ones that had them.
        if 'SanBenchDrive.efi' in found:
            sh(['docker', 'cp', f'{args.builder}:{found["SanBenchDrive.efi"]}',
                os.path.join(probe, 'SanBenchDrive.efi')], timeout=900)
        began = time.monotonic()
        done = sh(['docker', 'run', '--rm', '-v', f'{REPO}:/repo:ro',
                   '-v', f'{probe}:/fw:ro', '-v', f'{os.path.abspath(out)}:/out',
                   '--entrypoint', 'bash', args.base_image, '-lc',
                   'python3 /repo/scripts/detect_check.py '
                   '--code /fw/OVMF_CODE.fd --vars /fw/OVMF_VARS.fd '
                   '--selftest /fw/AsanSelfTest.efi --skip-network '
                   # The probe builds the same defines as the campaign, so when SMM is in
                   # the image the probe's machine has to offer it too -- and it needs
                   # longer: SMM init plus the UBSan narration this build prints to serial
                   # pushed the boot past the 90s default, which the probe then reported as
                   # "the self test never ran" even though the log shows it reaching BDS.
                   + ('--smm --timeout 300 ' if args.smm else '') +
                   '--keep /out/detect_capture'], timeout=1800)
        run.probe_boot = time.monotonic() - began
        text = done.stdout + done.stderr
        open(os.path.join(out, 'detect_check.log'), 'w').write(text)
        said = [l for l in text.splitlines() if 'asan detection classes' in l]
        if not said:
            return False, 'detect_check reached no verdict -- see detect_check.log'
        if '[PASS]' not in said[0]:
            return False, said[0].split(']', 1)[-1].strip()[:110]
        detail = said[0].split('classes', 1)[-1].strip()[:90]

        # AsanSelfTest covers five heap classes. The SanBench drivers cover eleven,
        # including the four only a firmware-specific check can see, and until now the
        # scoreboard that reads them -- scripts/bench_cases.py -- was run by hand and by
        # nothing else, which makes it the most capable ground truth here and the least
        # likely to be consulted. Run it on the same serial-reporting firmware this stage
        # already built, one boot per class, and fail the stage on a class that regressed.
        bench_app = os.path.join(probe, 'SanBenchDrive.efi')
        if not os.path.isfile(bench_app):
            # Reachable only if the probe build dropped a module it was asked for, which
            # is worth saying out loud -- returning a pass here is what let the benchmark
            # go unscored for as long as it did.
            return WARN, detail + ' -- the probe carries no SanBenchDrive.efi to score'
        scored = sh(['docker', 'run', '--rm', '-v', f'{REPO}:/repo:ro',
                     '-v', f'{probe}:/fw:ro', '-v', f'{os.path.abspath(out)}:/out',
                     '--entrypoint', 'bash', args.base_image, '-lc',
                     'python3 /repo/scripts/bench_cases.py --code /fw/OVMF_CODE.fd '
                     '--vars /fw/OVMF_VARS.fd --app /fw/SanBenchDrive.efi '
                     '--out /out/bench_cases --roms /workspace/qemu_fw --jobs 2'
                     # Exactly when the probe firmware was built with SMM_REQUIRE, which
                     # is the same condition. bench_cases.py needs it to boot the image at
                     # all -- q35,smm=on plus the SMM varstore globals, and an
                     # SMM_REQUIRE image does not come up without them -- and the smm-*
                     # rows are what measure a report raised by an SMM driver's OWN code.
                     # Without this they come back exempt: the board stays honest and
                     # green, and the thing those rows exist to demonstrate is never
                     # demonstrated. Conditional, because passing it to a non-SMM image
                     # would make the varstore SMM-writable only, which is untested here.
                     + (' --smm' if args.smm else '')],
                    timeout=2400)
        bench_text = scored.stdout + scored.stderr
        open(os.path.join(out, 'bench_cases.log'), 'w').write(bench_text)
        verdict = [l for l in bench_text.splitlines() if 'scorable classes detected' in l]
        if not verdict:
            return WARN, detail + ' -- the benchmark reached no verdict, see bench_cases.log'
        found = re.search(r'(\d+) of (\d+)', verdict[0])
        if found and found.group(1) != found.group(2):
            missed = [l.split()[0] for l in bench_text.splitlines()
                      if ' MISS ' in l or ' WRONG ' in l]
            return False, (f'{detail}; benchmark {verdict[0].strip()} -- '
                           f'{", ".join(missed[:6])} regressed')
        return True, f'{detail}; benchmark {verdict[0].strip()}'

    def scale_boot_timeout():
        """Carry the probe's measured boot into the campaigns' limit.

        The 90s-a-job model was fitted over 243 campaigns of NON-SMM firmware, where a
        solo boot fits in about 90s -- which is why the detect probe's own default was 90s
        too. Building with SMM boots far more code: the probe had to be given 300s, and
        every campaign then spent its whole budget without reaching the harness, 0 of 4,
        because the campaign limit had not learned the same lesson.

        So keep the fitted model and scale it by how much slower this configuration's boot
        actually is. The probe is one solo boot of the very firmware the campaigns boot,
        so it is the right measurement and it has already been taken by the time this
        runs. Capped, because a campaign that will never reach the harness should fail in
        an hour rather than hold a slot all day -- and the cap is announced, not silent.
        """
        measured = getattr(run, 'probe_boot', 0)
        if boot_timeout_given or measured <= 0:
            return
        slower = max(1.0, measured / 90.0)
        want = max(900, int(90 * args.jobs * slower))
        # 7200, not 3600. The first cap was a guess and it truncated the model's own
        # answer: an SMM boot measures 371s solo and the model asked for 6669s, so 3600s
        # cut it off within sight of the harness -- 4680 serial lines, the console already
        # in text mode, the same point a plain QEMU boot reaches in under 420s. The
        # campaign runs under icount, which is an order of magnitude slower, and that is
        # what the measurement is for. Still capped, so firmware that will never arrive
        # fails in two hours rather than never.
        capped = min(want, 7200)
        if capped <= args.boot_timeout:
            return
        print(f'  the probe booted this firmware in {measured:.0f}s, {slower:.1f}x the '
              f'90s the boot limit assumes; raising it from {args.boot_timeout}s to '
              f'{capped}s'
              + (f' (capped from {want}s)' if capped < want else ''))
        args.boot_timeout = capped

    def fuzz():
        scale_boot_timeout()
        # Said before the budget is spent, not after. An SMM_REQUIRE image needs the
        # secure pflash variable store to be WRITABLE -- that is where SMM-protected
        # variables live -- and the campaign used to open it read-only, which stopped the
        # boot in early DXE at 56 module constructors while firness reported a boot that
        # needed longer. It was not: 1620s and 3600s failed identically, and the detect
        # probe booted the same firmware to BDS in 365s with the store writable.
        #
        # The fuzzer now opens it writable on an SMM machine. What remains is a real
        # caveat rather than a blocker, so it is stated rather than hidden.
        if args.smm:
            print('  NOTE: this image requires SMM, so the campaign guest runs '
                  '"q35,smm=on" and opens the variable store for WRITING -- an '
                  'SMM_REQUIRE image writes to the secure pflash while its variable '
                  'drivers come up, and read-only stopped the boot in early DXE at 56 '
                  'module constructors. The cost is that a variable written during '
                  'fuzzing is not rolled back between iterations, because the snapshot '
                  'restores RAM and not block devices: watch edges_stability.')
        if args.skip_fuzz:
            return None, 'not run: --skip-fuzz'
        campaigns = os.path.join(out, 'campaigns')
        # Start from an empty directory. fuzz_batch skips a protocol that already has a
        # log.json, so a second run of the same ref would report the first run's
        # campaigns as its own. The campaign containers write as root through the bind
        # mount, which is why this cannot simply be shutil.rmtree.
        if os.path.isdir(campaigns):
            sh(['docker', 'run', '--rm', '-v', f'{os.path.abspath(out)}:/out',
                '--entrypoint', 'sh', args.base_image, '-c',
                'rm -rf /out/campaigns'], timeout=600)
            shutil.rmtree(campaigns, ignore_errors=True)
            if os.path.isdir(campaigns):
                return False, f'could not clear {campaigns} from the last run'
        # A run that was killed leaves its containers behind, and fuzz_batch rightly
        # refuses to reuse a name that is still running -- so every later run of the same
        # ref launches nothing at all. The name carries a hash of the output directory,
        # which this run has just emptied, so anything still holding one is orphaned.
        tag = hashlib.sha1(os.path.abspath(campaigns).encode()).hexdigest()[:6]
        prefix = os.environ.get('FIRNESS_CONTAINER_PREFIX', 'fuzz')
        stale = sh(['docker', 'ps', '-aq', '--filter', f'name={prefix}-.*-{tag}$'])
        ids = stale.stdout.split()
        if ids:
            sh(['docker', 'rm', '-f'] + ids, timeout=600)
            print(f'    removed {len(ids)} container(s) left by an earlier run')
        # A protocol this firmware never installs costs a whole boot and a whole budget to
        # discover that its opening LocateProtocol fails. protocol_presence.py has taken
        # that census for a long time and nothing passed it here, so every sweep fuzzed
        # them: AndroidBootImg and AndroidFastbootTransport are EmbeddedPkg drivers that
        # OvmfPkgX64 does not build, and they reported thousands of executions each.
        presence = os.path.join(out, 'presence.csv')
        capture = os.path.join(out, 'detect_capture', 'debug.log')
        if os.path.isfile(capture):
            took = sh([sys.executable, os.path.join(HERE, 'protocol_presence.py'),
                       '--capture', capture, '--root', os.path.join(REPO, 'eval_source'),
                       '--evalset', run.evalset, '--out', presence], timeout=600)
            if took.returncode or not os.path.isfile(presence):
                presence = ''
        else:
            presence = ''

        argv = [sys.executable, os.path.join(HERE, 'fuzz_batch.py'),
                '-r', REPO, '-o', campaigns, '-j', str(args.jobs),
                '-t', str(args.budget), '--backend', 'qemu',
                '--image', image_tag, '--tree', tree, '--evalset', run.evalset,
                # A target whose boot never reaches the harness otherwise holds a slot for
                # the 2700s default. Across a matrix of a couple of hundred that is most
                # of the run spent waiting for firmware that has already failed.
                '--boot-timeout', str(args.boot_timeout),
                # the cache holds an analysis of whichever tree it was taken from; this
                # run is about a specific ref, so analyse that
                '--no-anacache']
        if args.smi:
            argv.append('--smi')
        if presence:
            argv += ['--presence', presence]
        chosen = pick_targets(run.evalset, args.max_targets, args.smi, args.targets)
        if chosen and not args.targets:
            print(f'  fuzzing {len(chosen)} of {run.target_count} discovered target(s): '
                  f'{", ".join(chosen)}')
        if chosen:
            argv += ['-p'] + chosen
        # a campaign is its budget plus a boot and a harness build; the queue runs
        # args.jobs of them at once
        planned = len(chosen) if chosen else run.target_count
        rounds = max(1, -(-planned // max(1, args.jobs)))
        # The boot allowance is a floor, not a wall: firness.py keeps waiting past it while
        # the guest is still writing to serial or the debug port, up to FIRNESS_BOOT_EXTEND
        # times the allowance. This timeout has to allow for that or it kills the campaign
        # mid-extension and the log says "timed out" where it means "the boot was still
        # going" -- the opposite of what the extension exists to report.
        extend = max(1, int(os.environ.get('FIRNESS_BOOT_EXTEND', '3')))
        code = sh_log(argv, os.path.join(out, 'fuzz.log'),
                      timeout=rounds * (args.budget + args.boot_timeout * extend + 900)
                      + 1800)
        made = [d for d in sorted(os.listdir(campaigns))
                if os.path.isfile(os.path.join(campaigns, d, 'log.json'))] \
            if os.path.isdir(campaigns) else []
        if not made:
            return False, 'no campaign produced a log.json'
        # A campaign can produce a log and have fuzzed nothing: the boot has a budget of
        # its own, and a firmware that never reaches the harness spends all of it and
        # then reports zero. Counting logs alone makes that run green, which is the one
        # thing this script exists not to do.
        #
        # A protocol this platform never calls is not a failure. FuzzUEr models a
        # protocol from the call sites the analysis recorded, so one that is declared in
        # a header but that no module in this build ever calls yields an empty call
        # database and nothing to harness -- EmbeddedGpio and EfiSpiConfiguration are
        # platform protocols, EdkiiNonDiscoverableDevice and EdkiiSdMmcOverride belong to
        # drivers OvmfPkgX64 does not carry. Discovery reads headers and cannot know that
        # in advance, so name them here rather than reporting red for four protocols that
        # were never present to fuzz.
        #
        NO_CALL_SITES = 'no target functions were resolved'
        #
        # Reaching the harness is not the same as fuzzing it. A member that blocks or
        # never returns makes every input time out, and a timeout is recorded as an
        # objective -- so the campaign reports a handful of iterations, every one of them
        # a solution, and no edges at all. On an edk2 master sweep that was 19 of 239
        # campaigns, and every one of them was counted as a success: EfiBdsArch fuzzing
        # Entry, which by specification never returns; EfiMetronomeArch fuzzing
        # WaitForTick with a fuzzed tick count; EfiCpuIo2 reading physical addresses
        # nothing is mapped at. Together they spend a budget and a boot each -- some seven
        # hours of the run -- to produce nothing, and say the same thing as a campaign
        # that worked.
        #
        # Zero edges is what separates them. A campaign that executed the target even once
        # records coverage; one that never got through the call records none.
        #
        LINE = re.compile(r'Fuzzed (\d+) iteration\(s\), (\d+) edge\(s\), (\d+) solution\(s\)')
        fuzzed, iterations, absent, silent, stuck = 0, 0, [], [], []
        for name in (sorted(os.listdir(campaigns)) if os.path.isdir(campaigns) else []):
            log = os.path.join(campaigns, name, 'run.log')
            if not os.path.isfile(log):
                continue
            text = open(log, errors='ignore').read()
            runs = [(int(a), int(b), int(c)) for a, b, c in LINE.findall(text)]
            count, edges, solutions = max(runs, default=(0, 0, 0), key=lambda r: r[0])
            if not runs:
                count = max((int(n) for n in re.findall(r'Fuzzed (\d+) iteration', text)),
                            default=0)
            iterations += count
            if count and edges:
                fuzzed += 1
            elif count and solutions >= count:
                stuck.append(name)
            elif count:
                fuzzed += 1
            elif NO_CALL_SITES in text:
                absent.append(name)
            else:
                silent.append(name)
        # How good the coverage signal was, not just how much of it there was. The
        # fuzzer reports edges_stability every 30s into each campaign's qemu/run.txt and
        # nothing here ever read it -- so a sweep where three quarters of every observed
        # edge was jitter reported exactly what a clean one reports. That is how the
        # master sweep of 2026-09-17 came to be quoted as 3.4M iterations finding
        # nothing, when it ran at a median stability of 24.5% with the determinism
        # control switched off entirely. A run whose feedback is mostly noise has not
        # searched the space it appears to have searched, and it must say so itself.
        stability = []
        for name in (sorted(os.listdir(campaigns)) if os.path.isdir(campaigns) else []):
            beats = os.path.join(campaigns, name, 'qemu', 'run.txt')
            if not os.path.isfile(beats):
                continue
            seen = re.findall(r'edges_stability: ([\d.]+)%',
                              open(beats, errors='ignore').read())
            if seen:
                stability.append(float(seen[-1]))
        detail = (f'{fuzzed}/{planned} campaign(s) fuzzed the harness '
                  f'({iterations} iteration(s))')
        if stability:
            stability.sort()
            median = stability[len(stability) // 2]
            shaky = sum(1 for v in stability if v < 90.0)
            detail += f', edge stability median {median:.0f}%'
            if shaky:
                detail += f' ({shaky} campaign(s) under 90%)'
        if absent:
            detail += f', {len(absent)} not called anywhere in this build'
        if stuck:
            shown = ', '.join(stuck[:5]) + ('...' if len(stuck) > 5 else '')
            detail += (f', {len(stuck)} reached the harness but never came back out of '
                       f'the call ({shown})')
        if not fuzzed:
            return False, (detail + ' -- every boot spent its budget without reaching '
                           'the harness; each run.log says how far it got')

        # Did the guest ever see its testcase? Everything above counts iterations and
        # edges, and all of it moves whether or not the bytes arrived: the length alone
        # drives how many steps a sequence takes. A campaign fuzzing a constant input
        # reports the findings a constant input reaches and no check objected -- 474
        # byte-identical heap overflows from one planted constant, with a corpus that
        # never left the seed count. So this is asserted, not assumed.
        starved = []
        sys.path.insert(0, os.path.join(REPO, 'scripts'))
        try:
            from input_check import scan, verdict as input_verdict
            for name in (sorted(os.listdir(campaigns)) if os.path.isdir(campaigns) else []):
                where = os.path.join(campaigns, name)
                if not os.path.isdir(where):
                    continue
                state, _why = input_verdict(*scan(where))
                if state in ('DEAD', 'LENGTH ONLY'):
                    starved.append(f'{name}:{state.lower().replace(" ", "-")}')
        except Exception as error:                      # never fail the run over a check
            detail += f', input delivery unchecked ({error})'
        if starved:
            shown = ', '.join(starved[:6]) + ('...' if len(starved) > 6 else '')
            return WARN, (detail + f' -- {len(starved)} campaign(s) never received a '
                          f'testcase, so their coverage and findings are functions of the '
                          f'input length alone: {shown}')
        if silent:
            shown = ', '.join(silent[:6]) + ('...' if len(silent) > 6 else '')
            # Degraded, not failed. The campaigns that did fuzz are exactly what the run
            # exists to produce, and discarding their triage because one boot in two
            # hundred ran out of time throws away the report to punish the gap.
            return WARN, detail + f' -- {len(silent)} produced nothing: {shown}'
        if code != 0:
            return WARN, detail + f' -- the batch exited {code}'
        # Below this the coverage feedback is mostly jitter, the corpus grows on noise
        # and the search never leaves the neighbourhood of the first call. The campaigns
        # ran and their findings stand; what cannot stand is reading the iteration count
        # as though the space had been explored. 90% is where a target that is merely
        # awkward stops and one that is not being searched begins.
        if stability and stability[len(stability) // 2] < 90.0:
            return WARN, (detail + ' -- the coverage signal is mostly noise; treat the '
                          'iteration count as a lower bound on nothing')
        return True, detail

    def triage():
        if args.skip_fuzz:
            return None, 'not run: --skip-fuzz'
        campaigns = os.path.join(out, 'campaigns')
        # In the image, not on the host. A CPU exception is reported as a module and an
        # offset, and turning that into a function and a line needs the .debug images of
        # the build that was running -- which live in the image, beside the firmware the
        # campaigns booted. The firmware build happens inside the builder container, so
        # the host's copy of the tree has no Build directory at all and every fault came
        # out as "no source -- symbolise the offset". Same reason the detects stage runs
        # in a container rather than here.
        known = os.path.join(HERE, 'known-bugs.json')
        inner = ['python3', '/workspace/scripts/bug_report.py',
                 '-r', '/campaigns',
                 '--json', '/out/bugs.json',
                 '--markdown', '/out/bugs.md',
                 '--title', f'edk2 {args.ref}',
                 '--build', '/workspace/tmp/edk2']
        if os.path.isfile(known):
            inner += ['--known', '/workspace/scripts/known-bugs.json']
        argv = ['docker', 'run', '--rm',
                '-v', f'{os.path.abspath(campaigns)}:/campaigns:ro',
                '-v', f'{os.path.abspath(out)}:/out',
                '--entrypoint', 'python3', image_tag] + inner[1:]
        code = sh_log(argv, os.path.join(out, 'triage.log'), timeout=3600)
        report = os.path.join(out, 'bugs.json')
        if code != 0 or not os.path.isfile(report):
            return False, 'triage produced no report -- see triage.log'
        found = json.load(open(report))
        # Zero candidates is a real answer, not a failure: it says this version, fuzzed
        # this long, showed nothing the filters did not explain.
        return True, (f'{len(found["candidates"])} candidate(s) from '
                      f'{found["clusters"]} cluster(s)')

    ok = True
    for name, fn in (('ready', ready),
                     ('fetch', fetch), ('submodules', submodules), ('port', port),
                     ('vendor', vendor),
                     ('sync', sync), ('build', build), ('instrumented', instrumented),
                     ('discover', discover), ('image', stage_image),
                     ('detects', detects), ('fuzz', fuzz), ('triage', triage)):
        if run_stage(run, name, fn) is False:
            ok = False
            break

    run.save()
    return run.report()


if __name__ == '__main__':
    sys.exit(main())
