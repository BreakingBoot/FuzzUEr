import os
import re
import sys
import json
import shutil
import argparse
import subprocess


# run only the harness generator against a cached firness analysis and report what
# happened. the clang analysis costs ~10 minutes per protocol and does not change when
# the generator changes, so caching it turns a fix-test cycle from hours into seconds.
# use scripts/gen_protocol_inputs.py to build the input set and cache the analysis with
# firness -o <cache>/<name> once per protocol.
GENERATOR = '/workspace/harness_generator/main.py'
# the compiler and the directory holding FirnessHelpers.h. inside the container these are
# clang and the copied helpers; run natively they have to be pointed at the repo
COMPILER = 'clang'
HELPERS = ''


# a missing file means the analysis has not been cached yet, which is not a result and
# must not be reported as one. an empty database is NOT a skip: firness writes a bare
# "null" when it saw no call sites, and the generator still builds a harness from the
# declarations when the requested methods are among them
def analysis_state(cache_dir):
    path = os.path.join(cache_dir, 'call-database.json')
    if not os.path.isfile(path):
        return 'INCOMPLETE'
    try:
        with open(path, 'r') as f:
            json.load(f)
    except (OSError, ValueError):
        return 'INCOMPLETE'
    return 'READY'


# entries of one section of a dsc/inf, ignoring the architecture suffix so that
# [LibraryClasses] and [LibraryClasses.common.UEFI_APPLICATION] both count
def section_entries(path, section):
    entries = []
    inside = False
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            header = re.match(r'^\[([^\]]+)\]$', line)
            if header:
                inside = any(part.strip().split('.')[0].lower() == section.lower()
                             for part in header.group(1).split(','))
                continue
            if inside:
                entries.append(line)
    return entries


# the harness builds against its own Firness.dsc, so a library class the inf asks for and
# the dsc does not map is a link failure that a compile of the .c file cannot reveal
def library_gaps(harness_dir, roots):
    inf = os.path.join(harness_dir, 'FirnessHarnesses.inf')
    dsc = os.path.join(harness_dir, 'Firness.dsc')
    if not (os.path.isfile(inf) and os.path.isfile(dsc)):
        return None
    mapped = {}
    for entry in section_entries(dsc, 'LibraryClasses'):
        if '|' in entry:
            name, path = entry.split('|', 1)
            mapped.setdefault(name.strip(), path.strip())
    unmapped = [c for c in section_entries(inf, 'LibraryClasses') if c not in mapped]
    absent = sorted({p for p in mapped.values()
                     if not any(os.path.isfile(os.path.join(r, p)) for r in roots)})
    return unmapped, absent


def run_generator(cache_dir, input_file, edk2_dir, out_dir, smi=False):
    # the generator writes libmap.json back next to the databases, so it needs its own
    # copy of the analysis rather than the shared cache
    work = os.path.join(out_dir, 'analysis')
    shutil.copytree(cache_dir, work, dirs_exist_ok=True)
    cache_dir = work
    cmd = [
        'python3', GENERATOR,
        '-d', os.path.join(cache_dir, 'call-database.json'),
        '-g', os.path.join(cache_dir, 'generator-database.json'),
        '-gd', os.path.join(cache_dir, 'generators.json'),
        '-t', os.path.join(cache_dir, 'types.json'),
        '-a', os.path.join(cache_dir, 'aliases.json'),
        '-m', os.path.join(cache_dir, 'macros.json'),
        '-e', os.path.join(cache_dir, 'enums.json'),
        '-i', input_file,
        '-s', os.path.join(cache_dir, 'cast-map.json'),
        '-in', os.path.join(cache_dir, 'includes.json'),
        '-f', os.path.join(cache_dir, 'functions.json'),
        '--edk2', edk2_dir,
        '-o', out_dir,
    ]
    if smi:
        cmd += ['--smi', '-sm', os.path.join(cache_dir, 'smi-function-guid-map.json')]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


# a syntax-only check on the generated C. this catches the "expected expression" and
# "unknown type name" classes without paying for a full edk2 build
def syntax_check(harness_dir, edk2_dir):
    # all three sources, not just the generated harness: FirnessMain.c is what includes
    # the backend header, so compiling only FirnessHarnesses.c hides a missing helper
    sources = [os.path.join(harness_dir, name) for name
               in ('FirnessHarnesses.c', 'FirnessMain.c', 'FirnessHelpers.c')]
    if not os.path.isfile(sources[0]):
        return None
    sources = [p for p in sources if os.path.isfile(p)]
    # the packages the generated inf declares, so the search path matches what the real
    # build sees. hardcoding a list here made an OvmfPkg header look like a missing file
    packages = ['MdePkg', 'MdeModulePkg', 'NetworkPkg', 'ShellPkg', 'UefiCpuPkg', 'SecurityPkg']
    inf = os.path.join(harness_dir, 'FirnessHarnesses.inf')
    if os.path.isfile(inf):
        for entry in section_entries(inf, 'Packages'):
            pkg = entry.split('/')[0]
            if pkg and pkg not in packages:
                packages.append(pkg)
    includes = []
    for pkg in packages:
        includes += ['-I', os.path.join(edk2_dir, pkg, 'Include')]
    includes += ['-I', os.path.join(edk2_dir, 'MdePkg', 'Include', 'X64'), '-I', harness_dir]
    # edk2 force-includes AutoGen.h into every module, which is what pulls Base.h and
    # Uefi.h ahead of the module's own headers. without standing in for it here the
    # generated includes fail on UINTN long before reaching any generated code
    # -c rather than -fsyntax-only: running codegen also catches what only shows up
    # once the type is laid out, such as sizeof on an incomplete type
    if HELPERS:
        includes += ['-I', HELPERS]
    if COMPILER.startswith('clang'):
        dialect = ['-target', 'x86_64-pc-linux-gnu', '-Wno-everything']
    else:
        # gcc has no -Wno-everything and no -target; it is x86_64 already
        dialect = ['-w']
    cmd = [COMPILER, '-c', '-o', '/dev/null', '-fshort-wchar',
           '-fno-builtin', '-mno-red-zone'] + dialect + [
           '-DEFIAPI=__attribute__((ms_abi))', '-include', 'Uefi.h'] + includes
    for source in sources:
        p = subprocess.run(cmd + [source], capture_output=True, text=True)
        if p.returncode != 0:
            return p.returncode, p.stderr
    return 0, ''


def classify(err_text):
    for marker in ('error: expected expression', 'error: unknown type name',
                   'error: use of undeclared identifier', 'error: no member named',
                   'error: implicit declaration of function',
                   'error: cannot take the address of an rvalue',
                   'error: expected'):
        if marker in err_text:
            line = [l for l in err_text.splitlines() if marker in l]
            return line[0].strip() if line else marker
    for l in err_text.splitlines():
        if 'error:' in l:
            return l.strip()
    return ''


def main():
    parser = argparse.ArgumentParser(
        description='Run the harness generator against cached analysis and report failures')
    parser.add_argument('-c', '--cache', type=str, required=True, help='Cached analysis root')
    parser.add_argument('-i', '--inputs', type=str, required=True, help='Protocol input directory')
    parser.add_argument('--edk2', type=str, required=True, help='edk2 source root')
    parser.add_argument('-o', '--output', type=str, default='/tmp/genout', help='Scratch output dir')
    parser.add_argument('-p', '--protocol', type=str, help='Only this protocol')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print generator output on failure')
    parser.add_argument('--platforms', type=str, help='edk2-platforms root, for resolving dsc library paths')
    parser.add_argument('--generator', type=str, help='Path to harness_generator/main.py')
    parser.add_argument('--cc', type=str, default='clang', help='Compiler to check the generated C with')
    parser.add_argument('--helpers', type=str, help='Directory holding FirnessHelpers.h')
    args = parser.parse_args()
    global GENERATOR, COMPILER, HELPERS
    if args.generator:
        GENERATOR = args.generator
    COMPILER = args.cc
    HELPERS = args.helpers or ''

    names = ([args.protocol] if args.protocol
             else sorted(d for d in os.listdir(args.cache) if os.path.isdir(os.path.join(args.cache, d))))
    tally = {}
    for name in names:
        cache_dir = os.path.join(args.cache, name)
        input_file = os.path.join(args.inputs, name + '.txt')
        if not os.path.isfile(input_file):
            continue
        state = analysis_state(cache_dir)
        if state != 'READY':
            tally.setdefault(state, []).append(name)
            print(f'{name:34} {state}')
            continue

        out_dir = os.path.join(args.output, name)
        shutil.rmtree(out_dir, ignore_errors=True)
        os.makedirs(out_dir, exist_ok=True)
        rc, log = run_generator(cache_dir, input_file, args.edk2, out_dir)
        harness = os.path.join(out_dir, 'Firness')
        # the generator reporting that nothing matched the request is a clean outcome, not
        # a failure: the protocol is simply not exercised anywhere in this firmware image
        if 'no target functions were resolved' in log:
            tally.setdefault('NO_TARGETS', []).append(name)
            print(f'{name:34} NO_TARGETS')
            continue
        if rc != 0 or not os.path.isfile(os.path.join(harness, 'FirnessHarnesses.c')):
            first = classify(log) or next((l.strip() for l in log.splitlines()
                                           if 'Error' in l or 'error' in l), 'generator failed')
            tally.setdefault('GEN_FAIL', []).append((name, first))
            print(f'{name:34} GEN_FAIL     {first[:80]}')
            if args.verbose:
                print(log[-1500:])
            continue

        roots = [args.edk2] + ([args.platforms] if args.platforms else [])
        gaps = library_gaps(harness, roots)
        if gaps and (gaps[0] or gaps[1]):
            tally.setdefault('LIB_GAP', []).append((name, gaps))

        checked = syntax_check(harness, args.edk2)
        if checked is None:
            tally.setdefault('NO_OUTPUT', []).append(name)
            print(f'{name:34} NO_OUTPUT')
        elif checked[0] != 0:
            first = classify(checked[1])
            tally.setdefault('SYNTAX_FAIL', []).append((name, first))
            print(f'{name:34} SYNTAX_FAIL  {first[:80]}')
        else:
            tally.setdefault('OK', []).append(name)
            print(f'{name:34} OK')

    print('\n--- summary ---')
    for key in ('OK', 'SYNTAX_FAIL', 'GEN_FAIL', 'LIB_GAP', 'NO_TARGETS', 'NO_OUTPUT', 'INCOMPLETE'):
        if key in tally:
            print(f'  {key:14} {len(tally[key])}')
    for name, (unmapped, absent) in tally.get('LIB_GAP', []):
        if unmapped:
            print(f'  {name}: unmapped library class(es): {", ".join(unmapped)}')
        if absent:
            print(f'  {name}: dsc points at missing inf(s): {", ".join(absent)}')
    return 0 if not (tally.get('SYNTAX_FAIL') or tally.get('GEN_FAIL')) else 1


if __name__ == '__main__':
    sys.exit(main())
