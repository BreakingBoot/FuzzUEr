#!/usr/bin/env python3
"""Assert a report also seen during the boot is not called input driven.

A sanitizer site that fires on a plain boot fires whatever the fuzzer sends: the boot
happened before any input existed. firness.py has said so since the AtBoot column was
added -- "a site that also reported during boot is firmware doing what it does anyway;
the harness starting does not make it a finding" -- and bug_report.py never read it.

Its own test was `cluster.phases == {'boot'}`, which is only true for a site the harness
NEVER reaches. A site in both phases fell through to "candidate", so on run 42749754933
CpuHotplugSmm.efi|global-buffer-overflow|String.c appeared under "Firmware, provoked by an
input" while "Firmware, present on every run" printed None -- and its boot rows were in
the same crashes.csv. With open-issues on, that files an issue for firmware behaving as it
always does.

The AtBoot column had a second defect of its own, covered here too: it was keyed on
(file, line) with no module, and BaseLib is linked into nearly every image. DxeCore's 586
boot reports at Unaligned.c:197 therefore marked PiSmmCore's fuzz report at the same
library line as "also seen at boot", which is two different images and two different
callers.

Run: python3 scripts/boot_phase_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

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


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Report:
    def __init__(self, phase, protocol='DiscoveredSmi', line=10, count=1,
                 message='read of 8 bytes at 0x0000000001000000'):
        self.phase = phase
        self.protocol = protocol
        self.line = line
        self.count = count
        self.message = message
        self.module = 'CpuHotplugSmm.efi'
        # the verdict reads .path for the harness and known-artefact matches
        self.path = 'MdePkg/Library/BaseLib/String.c'
        self.file = 'MdePkg/Library/BaseLib/String.c'
        self.site = 'String.c'
        self.error_type = 'global-buffer-overflow'
        self.asan_msg = '__asan_loadN0x08'


def cluster_of(mod, phases):
    """A cluster carrying one report per phase, keyed as bug_report keys them."""
    cluster = mod.Cluster(('CpuHotplugSmm.efi', 'global-buffer-overflow', 'String.c'))
    for phase in phases:
        cluster.add(Report(phase))
    return cluster


def main():
    print('a report also seen during the boot is not called input driven')
    report = load('bug_report')

    # boot only: never reached by the harness, so it is background and filtered.
    only_boot = cluster_of(report, ['boot'])
    kind, why = report.verdict(only_boot, {only_boot.key}, 8)
    check('boot only stays background', kind == 'background', f'{kind}: {why}')

    # fuzz only: nothing says the firmware does this by itself.
    only_fuzz = cluster_of(report, ['fuzz'])
    kind, why = report.verdict(only_fuzz, set(), 8)
    check('fuzz only is a candidate', kind == 'candidate', f'{kind}: {why}')

    # both: the boot sighting predates every input, so an input did not provoke it.
    both = cluster_of(report, ['boot', 'fuzz'])
    kind, why = report.verdict(both, {both.key}, 8)
    check('boot AND fuzz is not a candidate', kind != 'candidate',
          f'{kind}: {why} -- the boot sighting happened before any input existed, so '
          f'calling it input driven files an issue against firmware behaving as it '
          f'always does')
    check('and it is still reported, not filtered away', kind == 'ubiquitous',
          f'{kind}: a real defect can sit here -- the HII null-pointer overflow did -- '
          f'so it belongs in "present on every run", not in the filtered bucket')
    check('and says why it is not input driven',
          'boot' in why and ('did not provoke' in why or 'not input driven' in why),
          f'the reason given was {why!r}')

    # The AtBoot column, which is the same judgement written into crashes.csv.
    source = open(os.path.join(HERE, 'firness.py'), encoding='utf-8').read()
    keyed = "at_boot = {(getattr(c, 'module', ''), getattr(c, 'site', c.file), c.line)"
    check('the AtBoot column is keyed on the module too', keyed in source,
          'BaseLib is linked into nearly every image, so a (file, line) key lets one '
          'module\'s boot report mark another module\'s fuzz report as "also at boot"')
    check('and the row is tested with the same key',
          "and (getattr(crash, 'module', '')," in source,
          'building the set with the module and testing it without one matches nothing')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
