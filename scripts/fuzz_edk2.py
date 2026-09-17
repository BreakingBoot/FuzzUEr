"""Fuzz an arbitrary edk2 version, unattended, from a ref to a bug report.

    python3 scripts/fuzz_edk2.py --ref edk2-stable202502

Every stage answers a question that, unanswered, makes the run's result meaningless rather
than merely absent. They are run in order and each one says PASS or FAIL with what it saw:

  fetch        is the ref real and checked out
  submodules   edk2 vendors its dependencies; three separate build failures name none of them
  port         the sanitizer integration applied, and how much of it merged cleanly
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
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


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
            state = 'PASS' if s.ok else ('FAIL' if s.ok is False else 'SKIP')
            print(f'    [{state}] {s.name:<14}{s.detail}  ({s.seconds:.0f}s)')
        failed = [s for s in self.stages if s.ok is False]
        print(f'  {"FAILED at " + failed[0].name if failed else "OK"}')
        return 1 if failed else 0

    def save(self):
        os.makedirs(self.out, exist_ok=True)
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
# -j8, and -j1 if that still loses: BaseTools generates VfrCompile's parser with antlr
# without declaring every dependency, so a wide -j reads half-written headers. Same race
# as the firmware build stage, and it fails here as an opaque "The command ... returned a
# non-zero code" from docker build.
RUN {{ make -C /workspace/tmp/edk2/BaseTools -j8 \\
     || make -C /workspace/tmp/edk2/BaseTools -j1 ; }} >/tmp/basetools.log 2>&1 \\
    && test -x /workspace/tmp/edk2/BaseTools/Source/C/bin/GenFw \\
    && test -x /workspace/tmp/edk2/BaseTools/Source/C/bin/VfrCompile
# The compilation database firness analyses, built once here instead of once per campaign.
# It describes the tree, not the protocol, so every campaign was paying for the same
# instrumented build of the whole of OVMF under bear -- minutes each, times as many
# protocols as the version has.
#
# The defines are the firmware build's, exactly. The .debug files this leaves behind are
# what turns an address in a sanitizer report back into a function and a line, and that
# only holds while they are the same build as the image that is running.
RUN cd /workspace/tmp/edk2 \\
    && export WORKSPACE=/workspace/tmp/edk2 \\
       EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools \\
       CONF_PATH=/workspace/tmp/edk2/Conf \\
       CLANGSAN_BIN=/workspace/llvm-15.0.7/build/bin/ \\
    && . ./edksetup.sh >/dev/null 2>&1 \\
    && bear --output /workspace/tmp/compile_commands.json -- \\
       build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc \\
       -D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FIRNESS_QEMU_CRASH=TRUE \\
       -D FD_SIZE_IN_KB=8192 -n "$(nproc)" >/tmp/anabuild.log 2>&1 \\
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
    state = 'PASS' if s.ok else ('FAIL' if s.ok is False else 'SKIP')
    print(f'  [{state}] {name:<14}{s.detail}')
    return s.ok


def main():
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop_child)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ref', required=True, help='edk2 tag, branch or SHA to fuzz')
    parser.add_argument('--source', default=os.path.join(REPO, 'eval_source', 'edk2'),
                        help='an edk2 checkout to take the ref and the port from')
    parser.add_argument('--budget', type=int, default=600, help='seconds per target')
    parser.add_argument('--jobs', type=int, default=8, help='targets fuzzed at once')
    parser.add_argument('--targets', nargs='*', default=None,
                        help='specific targets; default is everything discovered')
    parser.add_argument('--out', default='', help='where the artifacts go')
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
    if not args.boot_timeout:
        args.boot_timeout = max(900, 90 * args.jobs)

    slug = re.sub(r'[^A-Za-z0-9._-]', '-', args.ref)
    # Absolute, because several stages hand this to "docker run -v", and a relative
    # path there is read as a named volume rather than a directory: "includes invalid
    # characters for a local volume name". The default is already absolute, so only an
    # explicit --out could trip it -- and when it did, it failed the run at the detects
    # stage, after the image had already been rebuilt.
    out = os.path.abspath(args.out or os.path.join(REPO, 'results', f'fuzz-{slug}'))
    tree = os.path.join(REPO, 'eval_source', f'edk2-{slug}')
    run = Run(args.ref, out)
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
        got = sh(['git', '-C', args.source, 'rev-parse', '--verify', f'{args.ref}^{{commit}}'])
        if got.returncode:
            fetched = sh(['git', '-C', args.source, 'fetch', '--depth=1', 'tianocore',
                          args.ref], timeout=1800)
            if fetched.returncode:
                return False, f'no such ref, and fetch failed: {fetched.stderr.strip()[:80]}'
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
        sh(['git', '-C', tree, 'submodule', 'update', '--init', '--depth=1'], timeout=3600)
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
        return True, f'{len(paths) - len(empty)}/{len(paths)} populated'

    def port():
        # The tool lives with the sanitizer, in uefi_asan, because it is how you apply
        # that sanitizer to any edk2 rather than something this pipeline does privately.
        # Anyone with a checkout can run it the same way: apply_asan.py --to <tree>.
        apply = os.path.join(REPO, 'uefi_asan', 'apply_asan.py')
        if not os.path.isfile(apply):
            return False, f'{apply} is missing; is the uefi_asan submodule checked out?'
        argv = [sys.executable, apply, '--to', tree]
        if args.source:
            argv += ['--from', args.source]
        if args.port_base:
            argv += ['--base', args.port_base]
        done = sh(argv, timeout=1800)
        text = done.stdout + done.stderr
        clean = re.search(r'merged cleanly\s+(\d+)', text)
        fixed = re.search(r'conflicts resolved\s+(\d+)', text)
        left = re.search(r'conflicts REMAINING\s+(\d+)', text)
        failed = re.search(r'could not apply\s+(\d+)', text)
        nfail = int(failed.group(1)) if failed else -1
        nleft = int(left.group(1)) if left else -1
        detail = (f'{clean.group(1) if clean else "?"} clean, '
                  f'{fixed.group(1) if fixed else "?"} resolved, {nleft} unresolved, '
                  f'{nfail} failed')
        if nfail != 0 or nleft != 0:
            return False, detail + ' -- the port did not land'
        # a marker left anywhere makes the build fail somewhere else entirely
        stray = sh(f"grep -rl '^<<<<<<< ' {tree} 2>/dev/null | head -3").stdout.strip()
        if stray:
            return False, f'conflict markers left in {stray.splitlines()[0]}'
        return True, detail

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
                  f'{defines} -D FD_SIZE_IN_KB=8192 -n "$(nproc)"')
        done = docker(args.builder, script, timeout=7200)
        text = done.stdout + done.stderr
        open(os.path.join(out, logname), 'w').write(text)
        if 'BASETOOLS-FAILED' in text:
            why = [l for l in text.splitlines() if 'error' in l.lower()][:1]
            return False, ('BaseTools did not build: '
                           + (why[0][:90] if why else 'see the log'))
        if '- Done -' not in text:
            why = [l for l in text.splitlines() if 'error' in l.lower()][:1]
            return False, (why[0][:110] if why else 'build did not finish')
        return True, text

    def build():
        ok_, text = build_firmware(
            '-D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FIRNESS_QEMU_CRASH=TRUE',
            'build.log')
        if not ok_:
            return False, text
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
        return True, f'{ratio} modules carry ASan checks'

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
        run.target_count = protos
        scope = f' from {len(packages)} package(s)' if packages else ''
        return True, f'{protos} protocols{scope}, {handlers} SMI handlers'

    def stage_image():
        """A campaign image whose harness tree is the version under test.

        Campaigns run firness.py -s /workspace/tmp, so both the analysis and the harness
        build come from the tree baked into the image. Fuzzing every version against the
        image's own edk2 measures one tree over and over and files each result under
        whichever ref the matrix happened to name.
        """
        dest = in_builder()
        stage = os.path.join(REPO, 'imgstage', slug)
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
            IMAGE_DOCKERFILE.format(base=args.base_image))
        built = sh(['docker', 'build', '-q', '-t', image_tag,
                    '-f', os.path.join(stage, 'Dockerfile'), stage], timeout=5400)
        if built.returncode:
            tail = (built.stdout + built.stderr).strip().splitlines()
            return False, (tail[-1][:110] if tail else 'docker build failed')
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
        ok_, text = build_firmware('-D ASAN_SCOPE=full -D ASAN_FUZZER=none',
                                   'detect-build.log')
        if not ok_:
            return False, f'the check build failed: {text}'
        dest = in_builder()
        probe = os.path.join(out, 'detect_fw')
        shutil.rmtree(probe, ignore_errors=True)
        os.makedirs(probe)
        hunt = docker(args.builder,
                      f'find {dest}/Build \\( -name OVMF_CODE.fd -o -name OVMF_VARS.fd '
                      f'-o -name AsanSelfTest.efi \\) 2>/dev/null | sort')
        found = {}
        for line in hunt.stdout.split():
            found.setdefault(os.path.basename(line), line)
        for name in ('OVMF_CODE.fd', 'OVMF_VARS.fd', 'AsanSelfTest.efi'):
            if name not in found:
                return False, f'the check build produced no {name}'
            sh(['docker', 'cp', f'{args.builder}:{found[name]}',
                os.path.join(probe, name)], timeout=900)
        done = sh(['docker', 'run', '--rm', '-v', f'{REPO}:/repo:ro',
                   '-v', f'{probe}:/fw:ro',
                   '--entrypoint', 'bash', args.base_image, '-lc',
                   'python3 /repo/scripts/detect_check.py '
                   '--code /fw/OVMF_CODE.fd --vars /fw/OVMF_VARS.fd '
                   '--selftest /fw/AsanSelfTest.efi --skip-network'], timeout=1800)
        text = done.stdout + done.stderr
        open(os.path.join(out, 'detect_check.log'), 'w').write(text)
        said = [l for l in text.splitlines() if 'asan detection classes' in l]
        if not said:
            return False, 'detect_check reached no verdict -- see detect_check.log'
        if '[PASS]' not in said[0]:
            return False, said[0].split(']', 1)[-1].strip()[:110]
        return True, said[0].split('classes', 1)[-1].strip()[:90]

    def fuzz():
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
        if args.targets:
            argv += ['-p'] + list(args.targets)
        # a campaign is its budget plus a boot and a harness build; the queue runs
        # args.jobs of them at once
        planned = len(args.targets) if args.targets else run.target_count
        rounds = max(1, -(-planned // max(1, args.jobs)))
        code = sh_log(argv, os.path.join(out, 'fuzz.log'),
                      timeout=rounds * (args.budget + args.boot_timeout + 900) + 1800)
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
        detail = (f'{fuzzed}/{planned} campaign(s) fuzzed the harness '
                  f'({iterations} iteration(s))')
        if absent:
            detail += f', {len(absent)} not called anywhere in this build'
        if stuck:
            shown = ', '.join(stuck[:5]) + ('...' if len(stuck) > 5 else '')
            detail += (f', {len(stuck)} reached the harness but never came back out of '
                       f'the call ({shown})')
        if not fuzzed:
            return False, (detail + ' -- every boot spent its budget without reaching '
                           'the harness; each run.log says how far it got')
        if silent:
            shown = ', '.join(silent[:6]) + ('...' if len(silent) > 6 else '')
            return False, detail + f' -- {len(silent)} produced nothing: {shown}'
        return True, detail + ('' if code == 0 else f' -- the batch exited {code}')

    def triage():
        if args.skip_fuzz:
            return None, 'not run: --skip-fuzz'
        campaigns = os.path.join(out, 'campaigns')
        argv = [sys.executable, os.path.join(HERE, 'bug_report.py'),
                '-r', campaigns,
                '--json', os.path.join(out, 'bugs.json'),
                '--markdown', os.path.join(out, 'bugs.md'),
                '--title', f'edk2 {args.ref}',
                '--build', tree]
        known = os.path.join(HERE, 'known-bugs.json')
        if os.path.isfile(known):
            argv += ['--known', known]
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
