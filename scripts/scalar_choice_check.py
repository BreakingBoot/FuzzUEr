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


def render(fields, aliases=None, constants=None):
    from common.types import TypeInfo, FieldInfo
    import uefi_harness.smi_harness_template as smi
    smi.aliases_map.clear()
    smi.aliases_map.update(aliases or {})
    info = TypeInfo()
    info.fields = [FieldInfo(name=n, type=t) for n, t in fields]
    lines = smi.generator_struct_args('RW_VARIABLE_INFO *', 'HandlerData', {},
                                      {'RW_VARIABLE_INFO': info}, False,
                                      field_constants=constants)
    return smi, '\n'.join(lines)


def main():
    import uefi_harness.smi_harness_template as smi
    _, text = render(BLOCK, {'EFI_STATUS': 'RETURN_STATUS', 'RETURN_STATUS': 'UINTN'})

    print('which fields get a selector')
    for name in ('AccessType', 'Attributes', 'VariableNameSize', 'Offset', 'Signature'):
        check(f'{name} does', f'case 8: HandlerData->{name} = 0;' in text,
              'the firmware tests it against a constant and the raw width cannot reach one')
    check('a field whose type is an alias chain does too',
          'case 8: HandlerData->Status = 0;' in text,
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
    for case, value in ((8, '0'), (9, '1')):
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
          not re.search(r'^    case 0:', text, re.M),
          'ReadBytes zeroes a spent input, so a 0 case would zero every field in the '
          'block at once -- which returns RWVariableHandler early on VariableNameSize')
    for case in (1, 2, 3, 4, 5, 6, 7):
        check(f'selector {case} is the raw read too',
              not re.search(rf'^    case {case}:', text, re.M),
              'half the selector range stays raw so nothing that worked before stops')
    check('there is a default arm', 'default: break;' in text)

    print('how the selector is declared')
    decl = re.findall(r'UINT8 (\w+) = 0;', text)
    check('one selector variable for the whole block', len(decl) == 1, f'{decl}')
    check('its name is a C identifier',
          bool(decl) and re.fullmatch(r'[A-Za-z_]\w*', decl[0]), f'{decl}')
    check('it is declared before its first use',
          bool(decl) and f'{decl[0]} & 15' in text
          and text.index(f'UINT8 {decl[0]} = 0;') < text.index(f'{decl[0]} & 15'))
    check('it is read once per scalar field',
          text.count('ReadBytes(Input, sizeof(HandlerDataScalarChoice)') == 6,
          f"{text.count('ReadBytes(Input, sizeof(HandlerDataScalarChoice)')} of 6 scalars")
    check('the emitted braces balance', text.count('{') == text.count('}'),
          f"{text.count('{')} open, {text.count('}')} close")

    print('the constants the source tests a field against')
    #
    # The arithmetic this exists for. HwLight gates its only interesting path on
    # `switch (CommunicationData->Function) { case UNREGISTER_FROM_RSC:` -- 0x3 in a UINTN.
    # Through the generic cases alone that arm needs the low-byte case AND a 1-in-256
    # landing, and the message length has to be exactly right at the same time: about 1 in
    # 13000 per dispatch. Run 42490347442 dispatched it 37278 times, so the arm was taken a
    # handful of times across many boots -- and the defect behind it needs the arm taken
    # TWICE IN ONE BOOT, which at that rate never happens.
    #
    _, withc = render(BLOCK, {'EFI_STATUS': 'RETURN_STATUS', 'RETURN_STATUS': 'UINTN'},
                      constants={'AccessType': ['UNREGISTER_FROM_RSC', 'REGISTER_RSC']})
    check('a constant the source names is offered',
          'HandlerData->AccessType = (UINT32)REGISTER_RSC;' in withc, withc)
    check('and so is the second one',
          'HandlerData->AccessType = (UINT32)UNREGISTER_FROM_RSC;' in withc, withc)
    check('it is cast to the field type as written',
          '(UINT32)UNREGISTER_FROM_RSC' in withc,
          'a UINTN constant assigned to a UINT32 field without a cast warns, and the '
          'build runs with warnings as errors')
    check('the constants do not displace the generic cases',
          all(f'case {c}: HandlerData->AccessType' in withc for c in (8, 9, 10, 11)), withc)
    check('all four constant slots reach the table',
          all(f'    case {c}:\n' in withc + '\n' for c in (12, 13, 14, 15)),
          'one slot would give a 1-in-16 selector; four give 1 in 4')
    check('an index byte picks which constant',
          'switch (HandlerDataConstChoice % 2) {' in withc, withc)
    # On the single-field block there is exactly one of each, so the order is unambiguous.
    _, one_field = render([('Function', 'UINTN')], constants={'Function': ['CMD_A', 'CMD_B']})

    def before(text, first, second):
        """True when both are present and `first` comes first.

        Absence has to be False and not an exception: str.index raises, which crashed this
        script instead of failing a check, and two mutations -- removing the index read
        and narrowing the selector mask -- went undetected behind that crash.
        """
        if first not in text or second not in text:
            return False
        return text.index(first) < text.index(second)

    check('the index byte is read unconditionally, not inside the arm',
          before(one_field, 'ReadBytes(Input, sizeof(HandlerDataConstChoice)',
                 'switch (HandlerDataScalarChoice & 15)'),
          'a read inside the arm makes every later field\'s input offset depend on which '
          'branch this one took, and the fuzzer models a byte as meaning one thing')
    check('the selector is masked to the full sixteen values',
          'switch (HandlerDataScalarChoice & 15) {' in one_field,
          'at & 7 the generic cases 8..11 and every constant case are unreachable, and '
          'the harness silently loses both')
    check('a field with no constants gets none',
          'HandlerData->Offset = (UINT32)REGISTER_RSC' not in withc
          and 'HandlerData->Offset = (UINTN)REGISTER_RSC' not in withc,
          "one field's constants must not be emitted on another's")
    check('half the selector range is still the raw read',
          not any(re.search(rf'^    case {c}:', withc, re.M) for c in range(8)),
          'the invariant the whole selector design rests on -- anchored to the OUTER '
          "switch's indentation, because '    case 0:' is a substring of the nested "
          "'            case 0:' and matched it by accident")
    check('the nested switch has a default arm',
          withc.count('default: break;') >= 2,
          'an index modulo cannot fall out of range, but a missing default is a warning')
    check('the emitted braces still balance with a nested switch',
          withc.count('{') == withc.count('}'),
          f"{withc.count('{')} open, {withc.count('}')} close")

    # Many constants: the shape that four dedicated slots could not have expressed.
    _, many = render([('Function', 'UINTN')],
                     constants={'Function': [f'CMD_{i}' for i in range(8)]})
    check('eight command codes all reach the harness',
          all(f'(UINTN)CMD_{i};' in many for i in range(8)), many)
    check('and the index is taken modulo their count',
          'switch (HandlerDataConstChoice % 8) {' in many, many)
    check('no index byte is declared for a block with no constants',
          'ConstChoice' not in render(BLOCK)[1],
          'a block with nothing to offer must emit what it emitted before')

    print('and what a constant may not be')
    check('a non-identifier is dropped, not pasted into C',
          smi.field_constants_for('x', ['a b', 'f()', 'A|B', '-1', '']) == [],
          'the generated file has to compile; a malformed constant breaks the port, not '
          'just the harness')
    check('an identifier and a hex literal are kept',
          smi.field_constants_for('x', ['OK_NAME', '0x3F']) == ['OK_NAME', '0x3F'])
    check('0 and 1 are dropped as already offered',
          smi.field_constants_for('x', ['0', '1', '0x0', '0x1', 'KEEP']) == ['KEEP'],
          'cases 8 and 9 assign them, so re-offering spends an arm for nothing')
    # Found by running the analyzer on a fixture: HwLight tests
    # `if (CommunicationData->Disable == FALSE) break;`, so FALSE came back as Disable's
    # only constant and the four constant selector values all assigned the one value that
    # makes the handler bail -- turning a 0.875 chance of a non-zero Disable into 0.69.
    check('TRUE and FALSE are dropped too',
          smi.field_constants_for('x', ['FALSE', 'TRUE']) == [],
          'a BOOLEAN whose only source constant is FALSE would spend the constant arm on '
          'the value that makes the handler return')
    check('and such a field then declares no index byte',
          'ConstChoice' not in render([('Disable', 'BOOLEAN')],
                                      constants={'Disable': ['FALSE']})[1],
          'it falls back to the generic cases, where 1, the low byte and all ones are '
          'each non-zero')
    check('the list is bounded so generated code cannot run away',
          len(smi.field_constants_for('x', [f'C_{i}' for i in range(40)]))
          == smi.MAX_FIELD_CONSTANTS,
          f'{smi.MAX_FIELD_CONSTANTS} is the cap; the index byte means slots are not the '
          f'limit, but a switch arm per constant still lands in a compiled image')
    check('eight constants are NOT capped -- the shape four slots could not express',
          len(smi.field_constants_for('x', [f'C_{i}' for i in range(8)])) == 8,
          'VariableSmm switches on eight command codes and SmmSpi on several')
    check('names are kept before bare numerals when the cap bites',
          smi.field_constants_for(
              'x', ['0x7', '0x8'] + [f'C_{i:02d}' for i in range(smi.MAX_FIELD_CONSTANTS)])
          == [f'C_{i:02d}' for i in range(smi.MAX_FIELD_CONSTANTS)],
          'a numeral that survived is a literal in a comparison; a name is a command code')
    check('the order does not depend on set iteration order',
          smi.field_constants_for('x', {'B', 'A', 'C'})
          == smi.field_constants_for('x', {'C', 'B', 'A'}),
          'two runs of the generator must emit the same harness')
    check('a constant list that is None is not an error',
          smi.field_constants_for('x', None) == [])

    print('how SmiInfo holds them')
    from common.types import SmiInfo
    shared = {'Function': ['A']}
    info = SmiInfo('h', 'T *', 'g', field_constants=shared)
    info.field_constants['Function'] = ['MUTATED']
    check('SmiInfo copies the mapping instead of aliasing it',
          shared == {'Function': ['A']}, str(shared) + ' -- the loader hands it the dict '
          'it parsed out of the analyzer JSON, and editing one handler\'s constants must '
          'not reach back into that')
    a, b = SmiInfo('a', 'T *', 'g'), SmiInfo('b', 'T *', 'g')
    a.field_constants['F'] = ['X']
    check('and two handlers with no constants do not share one dict',
          b.field_constants == {}, str(b.field_constants))

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
