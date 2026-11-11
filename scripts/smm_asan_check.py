#!/usr/bin/env python3
"""Assert SMM code is instrumented, and that the SMM pool redzone reaches the tail.

Two separate things, both of which were silently wrong.

**SMM was not instrumented at all.** `MdeModulePkg/Include/Dsc/Asan.dsc.inc` set
`*_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address` for `SMM_CORE` and `DXE_SMM_DRIVER`, and
`==` replaces rather than appends, so those module types got no `-fsanitize=address`.
Measured: 0 of 17 SMM modules on eval1 and 0 of 9 on mainline had their own code checked,
while the stage still called 288 of 290 images "instrumented" because every image links
instrumented copies of BaseLib. The block's comment justified it as "SMM keeps its own
shadow and its own runtime", which stopped being true once OvmfPkgX64.dsc resolved AsanLib
for both types -- there is one shadow and it already covers SMRAM.

`-mllvm -asan-stack=0` is the one hard prerequisite and is asserted separately below.
Clang writes stack frame redzones INLINE and unconditionally, which bypasses AsanLib's
`MEM_TO_SHADOW` range guard; an SMM stack is in TSEG, and nothing maintains that shadow.

**The SMM pool redzone was shorter than the gap it had to cover.** `AsanPoisonPoolRedZones`
poisoned `ComputePoolRightRedzoneSize(Size)` bytes after the caller's buffer. That sizes a
redzone, not the slack a bucket allocation leaves: a 16-byte request takes a 16-byte
redzone in a 256-byte bucket, and the 40 bytes between the redzone and `POOL_TAIL` were
described by nothing. `OvmfPkg/Spi/SmmSpi.c` writes 8 bytes at exactly the first byte past
the redzone, before the check that would stop it -- so the overflow this code exists to
catch landed in the hole and ran 261+ times in run 42703964006 reporting nothing. The
numeric assertion below ties the fix to that address rather than to a count.

Run: python3 scripts/smm_asan_check.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FORK = os.path.join(REPO, 'eval_source', 'edk2')

DSC_INC = os.path.join(FORK, 'MdeModulePkg', 'Include', 'Dsc', 'Asan.dsc.inc')
POOL_C = os.path.join(FORK, 'MdeModulePkg', 'Core', 'PiSmmCore', 'Pool.c')
SMM_H = os.path.join(FORK, 'MdeModulePkg', 'Core', 'PiSmmCore', 'PiSmmCore.h')
ASAN_C = (os.path.join(FORK, 'MdeModulePkg', 'Library', 'AsanLib', 'Asan.c'),
          os.path.join(REPO, 'uefi_asan', 'AsanLib', 'Asan.c'))

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


def read(path):
    if not os.path.exists(path):
        return ''
    with open(path, encoding='utf-8', errors='replace', newline='') as handle:
        return handle.read().replace('\r\n', '\n')


def main():
    dsc = read(DSC_INC)
    if not dsc:
        print(f'[FAIL] not found: {DSC_INC}')
        return 1

    print('the SMM instrumentation switch')
    check('ASAN_SMM exists and defaults TRUE',
          re.search(r'^\s*DEFINE\s+ASAN_SMM\s*=\s*TRUE\s*$', dsc, re.M) is not None,
          'defaulting it off means nothing is instrumented and the knob reads as done')

    # The two blocks appear under both arms of the !if, so locate the TRUE arm first.
    arm = re.search(r'!if\s+"\$\(ASAN_SMM\)"\s*==\s*"TRUE"(.*?)!else', dsc, re.S)
    check('the TRUE arm is present', arm is not None)
    enabled = arm.group(1) if arm else ''
    for kind in ('SMM_CORE', 'DXE_SMM_DRIVER'):
        block = re.search(r'\[BuildOptions\.common\.EDKII\.' + kind + r'\]\s*\n'
                          r'\s*\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*(?P<flags>.*)',
                          enabled)
        check(f'{kind} is instrumented when ASAN_SMM is TRUE',
              block is not None and '$(ASAN_SAN_FLAGS)' in block.group('flags'),
              'without $(ASAN_SAN_FLAGS) the module type gets no -fsanitize=address, '
              'and "==" replaces so there is nothing else to fall back on')
        check(f'{kind} restates -mllvm -asan-stack=0',
              block is not None and '-asan-stack=0' in block.group('flags'),
              'clang emits frame redzones inline, bypassing the MEM_TO_SHADOW guard; an '
              'SMM stack is in TSEG and nothing maintains that shadow')

    other = dsc[dsc.index('!else', dsc.index('"$(ASAN_SMM)"')):] if arm else ''
    off = other[:other.index('!endif')] if '!endif' in other else ''
    for kind in ('SMM_CORE', 'DXE_SMM_DRIVER'):
        check(f'{kind} goes back to uninstrumented when ASAN_SMM is FALSE',
              re.search(r'\[BuildOptions\.common\.EDKII\.' + kind + r'\]\s*\n'
                        r'\s*\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*-Wno-frame-address', off)
              is not None,
              'a knob that does not restore the old behaviour is not a knob')

    # Not a check on the prose -- the TRUE arm quotes the old claim in order to explain
    # why it is false. What must not come back is an UNCONDITIONAL disable, i.e. the SMM
    # blocks sitting outside the !if/!else at all.
    structured = (enabled.count('[BuildOptions.common.EDKII.SMM_CORE]') == 1
                  and off.count('[BuildOptions.common.EDKII.SMM_CORE]') == 1
                  and dsc.count('[BuildOptions.common.EDKII.SMM_CORE]') == 2)
    check('the SMM blocks exist only inside the knob',
          structured,
          'a third copy outside the !if/!else would win or lose by file order, and the '
          'knob would stop meaning anything')

    print('\nthe gate that actually wins')
    # The .inc is included by OvmfPkgX64.dsc, and _ExpandBuildOption keys options by the
    # literal "*_CLANGSAN_X64_SAN_FLAGS" string per module type, so the LATER statement
    # wins. A correct .inc with an unconditional disable here instruments nothing, and the
    # build log looks identical.
    plat = read(os.path.join(FORK, 'OvmfPkg', 'OvmfPkgX64.dsc'))
    check('the platform DSC is readable', bool(plat))
    # Scoped to the SMM section: the file also holds 15 per-module opt-in SAN_FLAGS
    # lines, and counting those says nothing about SMM.
    header = ('[BuildOptions.common.EDKII.DXE_SMM_DRIVER, '
              'BuildOptions.common.EDKII.SMM_CORE]')
    blocks = []
    for match in re.finditer(re.escape(header), plat):
        rest = plat[match.end():]
        nxt = re.search(r'\n\[', rest)
        blocks.append(rest[:nxt.start()] if nxt else rest)
    check('the SMM BuildOptions header is present', len(blocks) >= 1,
          f'found {len(blocks)}')
    owning = [b for b in blocks if '_CLANGSAN_X64_SAN_FLAGS' in b]
    check('exactly one SMM block sets the sanitizer flags', len(owning) == 1,
          f'{len(owning)} of {len(blocks)} SMM blocks set SAN_FLAGS; this file holds its '
          f'body twice and the later statement wins, so two would be ambiguous')
    body = owning[0] if owning else ''
    flags = re.findall(r'\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*(.*)', body)
    check('that block has one arm per knob setting', len(flags) == 2,
          f'found {len(flags)}: expected the TRUE arm and the !else arm')
    check('the enabled arm restates the full flag string',
          any('$(ASAN_SAN_FLAGS)' in f and '-asan-stack=0' in f for f in flags),
          '"==" replaces, and the tools_def default carries -fsanitize=local-bounds '
          'whose handler AsanLib does not define')
    check('the disabled arm restores the old behaviour',
          any(f.strip() == '-Wno-frame-address' for f in flags))
    check('it is gated on the same knob as the include',
          '!if "$(ASAN_SMM)" == "TRUE"' in body,
          'an ungated platform gate overrides the knob, because this file is included '
          'after Asan.dsc.inc and the later statement wins')

    print('\nthe SMM pool redzone')
    pool = read(POOL_C)
    check('the poisoned span ends at POOL_TAIL, not at AsanRightRZSize',
          'PoisonEnd -= sizeof (POOL_TAIL);' in pool
          and 'PoolHdr->AsanRightRZSize,\n      kAsanHeapLeftRedzoneMagic' not in pool,
          'ComputePoolRightRedzoneSize sizes a redzone, not the slack a bucket leaves')
    check('the span starts at the end of the caller buffer',
          'UserEnd     = (UINTN)(PoolHdr + 1) + PoolHdr->OriSize;' in pool)
    check('the span is derived from the block size',
          'PoisonEnd = (UINTN)PoolHdr + PoolHdr->Size;' in pool)
    check('POOL_TAIL is left addressable',
          'PoisonEnd -= sizeof (POOL_TAIL);' in pool,
          'SmmInternalFreePool reads PoolTail->Signature and ->Size BEFORE it unpoisons '
          'the block, and those reads are checked once SMM_CORE is instrumented')
    check('HasPoolTail is computed the way the free path computes it',
          pool.count('PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0)') >= 2,
          'if the two disagree, one of them poisons or reads the wrong byte')
    check('nothing is poisoned when the span is empty',
          'if (PoisonEnd > UserEnd) {' in pool,
          'PoisonPool asserts Size != 0')

    print('\nthe arithmetic that made SmmSpi invisible')
    head = read(SMM_H)
    rz = re.search(r'#define\s+kAsanHeapLeftRedzoneSize\s+(\d+)', head)
    check('kAsanHeapLeftRedzoneSize is readable', rz is not None)
    left = int(rz.group(1)) if rz else 0
    check('the left redzone is 128 bytes', left == 128, f'got {left}')
    # Let ctypes apply the x86-64 ABI rather than hand-padding it: the first attempt at
    # this computed 164 by forgetting the 4 bytes that align Size, which is exactly the
    # kind of arithmetic slip the assertion exists to catch.
    import ctypes

    class PoolHeader(ctypes.Structure):
        _fields_ = [('Signature', ctypes.c_uint32),
                    ('Available', ctypes.c_uint8),
                    ('Type', ctypes.c_int),            # EFI_MEMORY_TYPE is an enum
                    ('Size', ctypes.c_uint64),
                    ('OriSize', ctypes.c_uint64),
                    ('AsanRightRZSize', ctypes.c_uint64),
                    ('AsanLeftRZ', ctypes.c_char * left)]

    class PoolTail(ctypes.Structure):
        _fields_ = [('Signature', ctypes.c_uint32),
                    ('Reserved', ctypes.c_uint32),
                    ('Size', ctypes.c_uint64)]

    header = ctypes.sizeof(PoolHeader)
    tail = ctypes.sizeof(PoolTail)
    check('AsanLeftRZ ends immediately before the caller buffer',
          PoolHeader.AsanLeftRZ.offset + left == header,
          f'redzone at {PoolHeader.AsanLeftRZ.offset}, header {header} -- a gap here '
          f'would make an underflow land in padding instead of the left redzone')
    check('sizeof (POOL_HEADER) is 168', header == 168, f'computed {header}')
    check('sizeof (POOL_TAIL) is 16', tail == 16, f'computed {tail}')
    # The SmmSpi message: *CommBufferSize == SPI_COMM_HDR_SIZE == 16.
    request, block = 16, 256
    user_end = header + request
    old_span = (user_end, user_end + 16)              # ComputePoolRightRedzoneSize(16)
    new_span = (user_end, block - tail)               # to the tail
    write_at = header + 32                            # SmmSpiReadDataIn->Buffer
    check('the old redzone did not reach the SmmSpi write',
          not (old_span[0] <= write_at < old_span[1]),
          f'block+{write_at} against old span {old_span}')
    check('the new span does reach it',
          new_span[0] <= write_at < new_span[1],
          f'block+{write_at} against new span {new_span}')
    check('the new span stops short of POOL_TAIL',
          new_span[1] == block - tail == 240,
          f'ends at {new_span[1]}, tail at {block - tail}')

    print('\nthe pool shadow range guard')
    for path in ASAN_C:
        where = os.path.relpath(path, REPO)
        text = read(path)
        check(f'{where} defines AsanPoolRangeHasShadow',
              'AsanPoolRangeHasShadow (' in text,
              'PoisonPool and UnpoisonPool wrote shadow with no bounds test at all, '
              'unlike PoisonPages')
        check(f'{where} guards on MEM_TO_SHADOW of both ends',
              'ShadowBegin = MEM_TO_SHADOW (Addr);' in text
              and 'ShadowEnd   = MEM_TO_SHADOW (Addr + Size - 1);' in text,
              'the bound variables bound the SHADOW region, so testing the memory '
              'address against them is a different question with a plausible answer')
        check(f'{where} bounds-tests FastPoisonShadow too',
              'if ((shadow_beg < mAsanShadowMemoryStart) || '
              '(shadow_end - 1 > mAsanShadowMemoryEnd)) {' in text,
              'it is the only shadow writer PoisonGlobalRedZone reaches, and the 0xf9 '
              'bytes measured at TSEG addresses have no other source; guarding '
              'UnpoisonPool alone left the two halves of register_global disagreeing')
        check(f'{where} calls it from both poison entry points',
              text.count('if (!AsanPoolRangeHasShadow (Addr, Size)) {') == 2,
              f"found {text.count('if (!AsanPoolRangeHasShadow (Addr, Size)) {')}, "
              f'expected one in PoisonPool and one in UnpoisonPool')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
