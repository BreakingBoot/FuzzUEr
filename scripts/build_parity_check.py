#!/usr/bin/env python3
"""Do the two OVMF builds in this pipeline agree on their overrides?

There are two, with separately maintained command lines:

  1. the FIRMWARE build, run in the builder container by the `build` stage, and
  2. the ANALYSIS build inside IMAGE_DOCKERFILE, run under `bear` to produce the
     compilation database.

The second one's OVMF is what gets copied into /workspace/qemu_fw and booted by **every
campaign**. So a `--pcd` the firmware build sets and the image build does not is not a
cosmetic difference: it means the firmware a campaign runs is not the firmware the run
validated, and the stage table says everything passed.

That is not hypothetical. `PcdResetOnMemoryTypeInformationChange=FALSE` was added to the
firmware build -- with a comment reading "Passed for every build" -- and never reached the
image build. An SMM image therefore kept MdeModulePkg's default of TRUE, BDS warm-reset
inside EfiBootManagerBoot, libafl died on GuestReset, and every SMM campaign reported 0
iterations. It cost six wrong theories before the two command lines were compared.

Reads the AST rather than the raw text, so the many comments that now mention that PCD by
name cannot be mistaken for command line arguments.
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.path.join(HERE, 'fuzz_edk2.py')

# TokenSpaceGuid.PcdName= as it appears in a build command line
PCD = re.compile(r'--pcd\s+([A-Za-z0-9]+)\.(Pcd[A-Za-z0-9_]*)\s*=')


def text_of(node):
    """Approximate the runtime text of a string or f-string node.

    Adjacent string literals are folded by the parser, so a command built as a run of
    f-strings arrives as one node. A {placeholder} becomes '{}' -- its value is not known
    statically and is not what this compares.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(part.value)
            else:
                out.append('{}')
        return ''.join(out)
    return ''


def pcds_in(text):
    return {f'{g}.{n}' for g, n in PCD.findall(text)}


def main():
    tree = ast.parse(open(DRIVER, encoding='utf-8').read())

    image_nodes, other_nodes, dockerfile = [], [], None
    for node in ast.walk(tree):
        # the string that feeds IMAGE_DOCKERFILE's {pcds}
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if 'image_pcds' in names:
                image_nodes.append(node.value)
                continue
            if 'IMAGE_DOCKERFILE' in names:
                dockerfile = text_of(node.value)
                continue
    for node in ast.walk(tree):
        if isinstance(node, (ast.Constant, ast.JoinedStr)):
            if any(node is n for n in image_nodes):
                continue
            other_nodes.append(node)

    image_pcds = set()
    for n in image_nodes:
        image_pcds |= pcds_in(text_of(n))

    firmware_pcds = set()
    for n in other_nodes:
        t = text_of(n)
        if t is dockerfile:
            continue
        firmware_pcds |= pcds_in(t)

    bad = 0
    print(f'  firmware build sets: {sorted(firmware_pcds) or "none"}')
    print(f'  image build sets:    {sorted(image_pcds) or "none"}')

    missing = firmware_pcds - image_pcds
    if missing:
        print(f'::error::the image build is missing {len(missing)} PCD override(s) the '
              f'firmware build sets: {", ".join(sorted(missing))}')
        print('::error::a campaign boots the IMAGE build, so this means the firmware under '
              'test is not the firmware that was validated')
        bad = 1
    else:
        print('  [OK]   every PCD the firmware build sets reaches the image build')

    # The plumbing has to exist at all: without the placeholder nothing can be passed.
    if dockerfile is None:
        print('::error::cannot find IMAGE_DOCKERFILE; this check has gone blind')
        bad = 1
    elif '{pcds}' not in dockerfile:
        print('::error::IMAGE_DOCKERFILE has no {pcds} placeholder, so overrides cannot '
              'reach the build a campaign boots')
        bad = 1
    else:
        print('  [OK]   IMAGE_DOCKERFILE takes a {pcds} placeholder')

    # And the image build must be the one whose OVMF is booted, or this check is comparing
    # the wrong pair. That is asserted by the copy into qemu_fw living in the same template.
    if dockerfile and 'qemu_fw' not in dockerfile:
        print('::error::IMAGE_DOCKERFILE no longer copies its build into qemu_fw -- the '
              'premise of this check (that a campaign boots the image build) needs '
              'rechecking')
        bad = 1
    elif dockerfile:
        print('  [OK]   the image build is still the one copied into qemu_fw')

    return bad


if __name__ == '__main__':
    sys.exit(main())
