#!/usr/bin/env python3
"""Name every module the sanitizer does not check, and say why for each one.

The instrumented stage already measures two different things and reports both:

  288/290 images carry ASan symbols        -- per module IMAGE, from nm on the .debug
  314/327 modules have their own code      -- per module, from the compile lines

The first number is the generous one and always will be. Counted on eval1 run
43454245046: the build writes 290 .debug files and not one of them belongs to a library
(`BaseLib.debug`, `AsanLib.debug`, `BaseMemoryLibRepStr.debug` -- none exist), so the
denominator really is module images; but an image is credited for __asan_load symbols
that a LINKED library contributed, and a library instance is built once with the global
flags whatever the module's own BuildOptions said. So 288/290 can read as near-total
while a driver's own statements carry no checks at all.

The second number is the one that answers the question, and the stage printed only the
number. own_code_instrumented() hands back the list of modules behind the shortfall and
the caller named the SMM ones; the other ten to twelve went unmentioned in every run
report ever written. "314/327" reads as near-total coverage while something specific is
uncovered, and the only way to find out what was to re-run a Python snippet over the
build log. This module turns that list into one sentence with a reason per group.

WHAT THE GROUPS MEAN, measured on the two runs this was written against

  PEI/SEC -- 12 of the 13 on eval1 run 43454245046, 10 of the 11 on upstream master
  (/home/gl055/fuzzuer-sweep/43704163314/fuzz-master/build.log). Not an oversight and
  not fixable by a flag. Three separate things have to be true before an instrumented
  access can report anything, and in PEI none of them is:

    * MdeModulePkg/Library/AsanLib/AsanLib.inf declares
      LIBRARY_CLASS = AsanLib|DXE_DRIVER ... DXE_CORE SMM_CORE. PEIM is not in that
      list, so the reporting runtime cannot link into a PEIM at all.
    * AsanLibNull is what does link (its LIBRARY_CLASS does list PEIM), and every
      __asan_load/__asan_store body in uefi_asan/AsanLibNull/AsanNull.c is empty. An
      instrumented PEIM therefore emits calls that do nothing.
    * The shadow does not exist for most of PEI anyway. OvmfPkg/PlatformPei/MemDetect.c
      builds the gAsanInfoGuid HOB that tells the runtime where the shadow is -- and
      PlatformPei is itself a PEIM, so everything dispatched before it has no shadow to
      consult. AsanLib with no HOB deactivates itself.

    AsanLib also declares CONSTRUCTOR = AsanLibConstructor, whose signature is
    (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) -- arguments a PEIM has
    neither of. Instrumenting PEI would add roughly three times the code size to a
    volume with no room for it in exchange for calls into empty functions.

  declared -- a module in a phase that CAN report, excluded by name in
  OvmfPkg/OvmfPkgX64.dsc with a measured reason. There is exactly one, and
  scripts/asan_scope_check.py asserts that this table and that DSC still agree, because
  an exclusion recorded in one place and not the other is the shape this project has
  been burned by twice.

  unknown -- no INF in the tree to read a MODULE_TYPE from. A FILE_GUID override in
  [Components] puts the build output under the GUID instead of the BASE_NAME
  (UefiCpuPkg/CpuMpPei/280251c4-1d09-4035-9062-839acb5f18c1 is CpuMpPei built for a
  uniprocessor guest), so the directory's own INF is tried before giving up.

  unexpected -- dark, in a DXE or SMM phase, and nothing accounts for it. This is the
  group the sentence exists for: a campaign driving an SMI handler whose driver is not
  instrumented reports clean for a reason that has nothing to do with the firmware being
  correct. Both runs this was written against have none.

Standalone, over a build log that is already on disk:

  python3 scripts/asan_scope.py <build.log> [--tree <edk2 checkout>]
"""

import os
import re
import sys

# The module types that run before the shadow exists. PEI_CORE and SEC are here for the
# same reason as PEIM: OvmfPkgX64.dsc switches SAN_FLAGS off for all three in one
# [BuildOptions.common.EDKII.SEC, ...PEI_CORE, ...PEIM] block.
PHASE_TYPES = ('SEC', 'PEI_CORE', 'PEIM')

PHASE_REASON = (
    'PEI/SEC, where AsanLib declares no PEIM flavour, AsanLibNull does and its hooks '
    'are empty, and the gAsanInfoGuid HOB is built by a PEIM -- so an instrumented '
    'access there cannot report'
)

# Modules in a reporting phase that are excluded deliberately, and what was measured.
#
# Keyed the way own_code_instrumented keys its modules: the INF path without the .inf,
# relative to the tree. Not keyed on the basename -- OvmfPkg/Spi builds DxeSpi and
# SmmSpi out of one directory and the whole point of the per-module measurement is that
# those are two different answers.
EXCLUDED = {
    'MdeModulePkg/Universal/Acpi/BootScriptExecutorDxe/BootScriptExecutorDxe': (
        'it runs a hand-relocated copy of its own image at S3 resume with no DXE core '
        'under it, and instrumented the boot faults inside it with no report first'
    ),
}

# Why that one is excluded, at the length that does not belong in a run log.
#
# ScriptExecute.c allocates EfiReservedMemoryType pages, relocates its own PE image into
# them with PeCoffLoaderRelocateImage and publishes the entry point of that COPY for S3
# resume, where there is no DXE core, no boot services and no AsanLibConstructor having
# run over the copy's own data. OvmfPkgX64.dsc records what was measured when it was
# instrumented at ASAN_SCOPE=full: "the boot faults inside this driver with no ASan
# report before it, so it is a crash rather than a finding". It is off the normal DXE
# paths, it installs no protocol any campaign targets, and putting it back needs a boot
# to show it is safe -- which is why this is a named exclusion rather than a silent one.

# 8-4-4-4-12. A [Components] entry with a <Defines> FILE_GUID override builds into a
# directory named after the GUID, so the key own_code_instrumented records has no INF of
# its own and the MODULE_TYPE has to come from the directory's.
GUID_NAME = re.compile(r'^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')


def sibling_inf(module):
    """The INF a FILE_GUID override hides: Pkg/Dir/<guid> is built from Pkg/Dir/Dir.

    Returns '' for anything that is not a GUID-named build directory, so a caller can
    tell "try this instead" from "there is nothing else to try".
    """
    head, tail = os.path.split(module)
    if head and GUID_NAME.match(tail):
        return os.path.join(head, os.path.basename(head))
    return ''


def classify(dark, kind_of=None):
    """Split own_code_instrumented's dark list into why each entry is dark.

    `dark` is [(module, module_type)] exactly as own_code_instrumented returns it, and
    `kind_of` is an optional module -> MODULE_TYPE resolver used ONLY to recover a type
    the caller could not read. It is a callable rather than a tree path so that this
    module does not need a second copy of the INF reader: there is one spelling of
    "what type is this module", it lives beside the measurement, and this decides which
    path to ask about.

    Returns a dict of four lists. Every entry of `dark` lands in exactly one of them,
    which is the property that keeps a group from quietly swallowing the rest.
    """
    groups = {'phase': [], 'declared': [], 'unknown': [], 'unexpected': []}
    for module, kind in dark:
        if module in EXCLUDED:
            groups['declared'].append((module, EXCLUDED[module]))
            continue
        kind = (kind or '').strip()
        if not kind and kind_of:
            alternative = sibling_inf(module)
            if alternative:
                kind = (kind_of(alternative) or '').strip()
        if kind.upper() in PHASE_TYPES:
            groups['phase'].append((module, kind))
        elif not kind:
            groups['unknown'].append((module, kind))
        else:
            groups['unexpected'].append((module, kind))
    return groups


def describe(dark, kind_of=None):
    """One sentence naming every dark module, grouped by reason. '' when none are.

    Nothing is elided. A reader of the run log has to be able to see the list without
    re-deriving it, and the stage already fails below a 90% floor -- so the longest this
    can get is bounded by the point at which the run stops anyway.
    """
    if not dark:
        return ''
    groups = classify(dark, kind_of)
    said = []
    if groups['phase']:
        said.append('%d in %s: %s'
                    % (len(groups['phase']), PHASE_REASON, names(groups['phase'])))
    for module, reason in groups['declared']:
        said.append('%s is excluded by name in OvmfPkgX64.dsc -- %s'
                    % (base(module), reason))
    if groups['unknown']:
        said.append('%d with no INF in the tree to read a MODULE_TYPE from, so this '
                    'cannot say which phase they run in: %s'
                    % (len(groups['unknown']), names(groups['unknown'])))
    # Last, and in capitals, because it is the only group that means something is wrong.
    # A dark DXE or SMM module is the shape the whole stage exists to stop: the firmware
    # boots, the campaigns run, and a sweep over it reports a clean result that means
    # nothing.
    if groups['unexpected']:
        said.append('UNEXPLAINED -- %d module(s) in a phase that CAN report carry no '
                    'checks of their own: %s. A campaign driving one of these reports '
                    'clean for a reason that has nothing to do with the firmware being '
                    'correct'
                    % (len(groups['unexpected']), names(groups['unexpected'])))
    return '%d carry none of their own: ' % len(dark) + '; '.join(said)


def base(module):
    return module.split('/')[-1]


def names(rows):
    """basename (TYPE), for every row -- the type included because it is the reason."""
    return ', '.join('%s (%s)' % (base(module), kind or 'type unknown')
                     for module, kind in rows)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    tree = ''
    logs = []
    index = 0
    while index < len(argv):
        if argv[index] == '--tree' and index + 1 < len(argv):
            tree = argv[index + 1]
            index += 2
            continue
        logs.append(argv[index])
        index += 1
    if not logs:
        sys.exit(__doc__.strip().splitlines()[-1].strip())

    # Imported here, not at the top: fuzz_edk2 imports this module, and a top-level
    # import back into it would be a cycle. The measurement is NOT reimplemented -- a
    # copy here would keep agreeing with itself after the real one changed.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from fuzz_edk2 import own_code_instrumented, module_type

    status = 0
    for log in logs:
        if not os.path.isfile(log):
            print('%s: no such file' % log)
            status = 1
            continue
        text = open(log, errors='replace').read()
        own, total, dark = own_code_instrumented(text, tree)
        print('%s: %d/%d modules have their own code instrumented' % (log, own, total))
        if not dark:
            print('  every module in this build checks its own code')
            continue
        groups = classify(dark, lambda m: module_type(tree, m) if tree else '')
        for group in ('phase', 'declared', 'unknown', 'unexpected'):
            rows = groups[group]
            if not rows:
                continue
            print('  %s (%d)' % (group, len(rows)))
            for module, detail in rows:
                print('    %-70s %s' % (module, detail))
        print('  sentence: ' + describe(dark,
                                        lambda m: module_type(tree, m) if tree else ''))
        if groups['unexpected']:
            status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
