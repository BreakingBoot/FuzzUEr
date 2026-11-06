#!/usr/bin/env python3
"""Assert a parameter block field the firmware tests against a constant is reachable.

An SMI handler reads a struct the caller supplies and then tests nearly every field in it.
Filling each field from its own raw width makes those tests one-sided: a UINT32 compared
against zero takes its other branch for one input in 2^32, a bitmask field is rejected for
any bit the mask does not name, and a UINTN that becomes a size is over every bound the
callee checks.

Measured on EVAL-1 run 42176147435. RWVariableHandler was dispatched 10548 times over
71418 iterations, with 100% edge stability and zero objectives. Its get path needs a
(name, GUID) pair that exists in the variable store; its set path hands SmmSetVariable a
pointer the input places and needs, at once:

    AccessType == 0                 UINT32, the path is behind `if (CommData->AccessType)`
    Attributes & ~0x7F == 0         SetVariable refuses any bit the attribute mask omits
    VariableNameSize small, != 0    it becomes the DataSize, bounded by MaxVariableSize

Zero-filling does not rescue it and makes it worse. ReadBytes zeroes what the input cannot
supply, so a short input zeroes AccessType -- and that same shortness zeroes
VariableNameSize, which returns the handler before the branch. The two conditions are
mutually exclusive in exactly the regime that satisfies the first one for free. That is why
0 must NOT be one of the selector's special cases, and this checks it.

This is about the ENCODING, not about one tree: the three shapes above -- tested against
zero, a bitmask, a size -- are what every edk2 comm buffer is made of.
"""

import os
import re
import signal
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(os.path.dirname(HERE), 'firness', 'harness_generator')
sys.path.insert(0, GEN)

FAILURES = []


def _ring(signum, frame):
    raise TimeoutError('scalar_field_type did not return')


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


# RW_VARIABLE_INFO as the analyser records it, field for field, including the two shapes
# the selector must leave alone: a nested struct and an array that carries its extent in
# the type.
BLOCK = [
    ('Status', 'EFI_STATUS'),
    ('Signature', 'UINT32'),
    ('AccessType', 'UINT32'),
    ('VarGuid', 'EFI_GUID'),
    ('Attributes', 'UINT32'),
    ('VariableNameSize', 'UINTN'),
    ('Offset', 'UINTN'),
    ('Data', 'UINT8[1024]'),
    ('Next', 'RW_VARIABLE_INFO *'),
]


def render(fields, aliases=None):
    from common.types import TypeInfo, FieldInfo
    import uefi_harness.smi_harness_template as smi
    smi.aliases_map.clear()
    smi.aliases_map.update(aliases or {})
    info = TypeInfo()
    info.fields = [FieldInfo(name=n, type=t) for n, t in fields]
    lines = smi.generator_struct_args('RW_VARIABLE_INFO *', 'HandlerData', {},
                                      {'RW_VARIABLE_INFO': info}, False)
    return smi, '\n'.join(lines)


def main():
    import uefi_harness.smi_harness_template as smi
    _, text = render(BLOCK, {'EFI_STATUS': 'RETURN_STATUS', 'RETURN_STATUS': 'UINTN'})

    print('which fields get a selector')
    for name in ('AccessType', 'Attributes', 'VariableNameSize', 'Offset', 'Signature'):
        check(f'{name} does', f'case 4: HandlerData->{name} = 0;' in text,
              'the firmware tests it against a constant and the raw width cannot reach one')
    check('a field whose type is an alias chain does too',
          'case 4: HandlerData->Status = 0;' in text,
          'EFI_STATUS -> RETURN_STATUS -> UINTN must resolve')
    check('an array does not',
          'HandlerData->Data = 0;' not in text,
          'UINT8[1024] is not assignable and zeroing it is not a value choice')
    check('a nested struct does not', 'HandlerData->VarGuid = 0;' not in text,
          'EFI_GUID has no integer value to pick')
    check('a pointer field keeps the fill-in-place form',
          'ReadBytes(Input, sizeof(HandlerData->Next), (VOID *)(HandlerData->Next));' in text,
          'writing random bytes into the pointer itself hands the driver a wild address')

    print('what the selector offers')
    for case, value in ((4, '0'), (5, '1')):
        check(f'case {case} is {value}',
              f'case {case}: HandlerData->AccessType = {value};' in text)
    check('one case is the low byte',
          'HandlerData->AccessType = (UINT32)(HandlerData->AccessType & 0xFF);' in text,
          'a bitmask field and a size field are both reachable only through a small value')
    check('one case is all ones',
          'HandlerData->AccessType = (UINT32)~0ULL;' in text,
          'an overflow or a maximum check needs the top of the range')
    check('the cast is the type as written, not the type it resolves to',
          '(EFI_STATUS)~0ULL' in text and '(UINTN)(HandlerData->Status' not in text,
          'an alias landing on a wider spelling would truncate on assignment')

    print('and what it must not do')
    # The whole point. A spent input reads zero, and zero has to mean "leave it alone".
    check('selector 0 is the raw read',
          not re.search(r'case 0:', text),
          'ReadBytes zeroes a spent input, so a 0 case would zero every field in the '
          'block at once -- which returns RWVariableHandler early on VariableNameSize')
    for case in (1, 2, 3):
        check(f'selector {case} is the raw read too', f'case {case}:' not in text,
              'half the selector range stays raw so nothing that worked before stops')
    check('there is a default arm', 'default: break;' in text)

    print('how the selector is declared')
    decl = re.findall(r'UINT8 (\w+) = 0;', text)
    check('one selector variable for the whole block', len(decl) == 1, f'{decl}')
    check('its name is a C identifier',
          bool(decl) and re.fullmatch(r'[A-Za-z_]\w*', decl[0]), f'{decl}')
    check('it is declared before its first use',
          bool(decl) and text.index(f'UINT8 {decl[0]} = 0;') < text.index(f'{decl[0]} & 7'))
    check('it is read once per scalar field',
          text.count('ReadBytes(Input, sizeof(HandlerDataScalarChoice)') == 6,
          f"{text.count('ReadBytes(Input, sizeof(HandlerDataScalarChoice)')} of 6 scalars")
    check('the emitted braces balance', text.count('{') == text.count('}'),
          f"{text.count('{')} open, {text.count('}')} close")

    print('and that a block with nothing to choose stays as it was')
    _, plain = render([('VarGuid', 'EFI_GUID'), ('Data', 'UINT8[64]')])
    check('no selector is declared when no field is scalar',
          'ScalarChoice' not in plain, plain)
    check('an unresolvable alias is left alone, not guessed',
          smi.scalar_field_type('SOME_OPAQUE_HANDLE') == '')
    # An alias map read out of a tree can be cyclic, and the generator runs before anything
    # has had the chance to say so. Under a deadline, because the failure this guards
    # against is a hang: a `seen` set and a hop bound BOTH stop it, so asserting only the
    # return value passes while either one is still there, and the check cannot tell which
    # mutation it caught. Nothing but a clock falsifies "it comes back at all".
    smi.aliases_map.clear()
    smi.aliases_map.update({'A': 'B', 'B': 'A'})
    settled, kind = None, ''
    try:
        signal.signal(signal.SIGALRM, _ring)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        settled = smi.scalar_field_type('A')
    except TimeoutError:
        kind = 'it did not come back within 5s'
    except RecursionError:
        kind = 'it recursed until the stack ran out'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    check('a cyclic alias map terminates', settled == '', kind or f'returned {settled!r}')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
