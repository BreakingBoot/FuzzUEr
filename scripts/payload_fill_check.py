#!/usr/bin/env python3
"""Assert an SMI comm buffer's trailing member is filled as a payload, not as one byte.

Every edk2 SMM comm buffer is a small header followed by `UINT8 Data[1]`, and the
command's arguments live in that tail. The generator's field loop treated Data as an
ordinary field and emitted

    ReadBytes(Input, sizeof(HandlerData->Data), (VOID *)&(HandlerData->Data));

which for a `Data[1]` tail reads EXACTLY ONE BYTE. On EVAL-1 run 42703964006 SmmSpiHandler
was dispatched 7253 times and "buffer location invalid" -- its third guard -- was printed
zero times in 294674 iterations, because the 24-byte SMM_SPI_READ_DATA behind the header
was one input byte followed by whatever the previous iteration left in the shared
communication region. The same hole sat under SmmVariableHandler, whose payload is
whichever of a dozen structs the Function field selected.

So the command-code selector picked the right arm and the arm then read its arguments from
noise. These assertions cover the fill, the plants that reach a guard raw bytes cannot, and
the three properties that are easy to regress: a plant must stay inside the message, the
input reads must stay a fixed size, and a fixed array in the MIDDLE of a block must still
be an ordinary field.

Run: python3 scripts/payload_fill_check.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The image flattens harness_generator next to scripts/; a checkout keeps it under
# firness/. Try both and say so if neither is there -- a missing module must not read as a
# clean result.
CANDIDATES = (
    os.path.join(os.path.dirname(HERE), 'firness', 'harness_generator'),
    os.path.join(os.path.dirname(HERE), 'harness_generator'),
    os.path.join(HERE, 'harness_generator'),
)

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


class Field:
    def __init__(self, name, type_):
        self.name = name
        self.type = type_


def main():
    root = next((c for c in CANDIDATES
                 if os.path.exists(os.path.join(c, 'uefi_harness',
                                                'smi_harness_template.py'))), '')
    if not root:
        print('[FAIL] smi_harness_template.py is not in any known layout:')
        for candidate in CANDIDATES:
            print(f'        {candidate}')
        return 1
    sys.path.insert(0, root)
    from uefi_harness import smi_harness_template as tpl

    print('the trailing-array test')
    for spelling in ('UINT8[1]', 'UINT8 [1]', 'UINT8[]', 'CHAR8[16]', 'INT8[4]'):
        check(f'{spelling!r} is a payload tail', tpl.payload_tail(spelling))
    for spelling in ('UINT8', 'UINT8 *', 'UINTN', 'EFI_GUID[2]',
                     'SMM_SPI_READ_DATA[1]', 'BOOLEAN'):
        check(f'{spelling!r} is not a payload tail', not tpl.payload_tail(spelling),
              'a non-byte array is a real field, and filling it as a payload would '
              'write over the fields after it')

    print('\nthe emitted payload region')
    body = '\n'.join(tpl.payload_region('HandlerData', 'Data'))

    check('the one-byte read of the tail is gone',
          'sizeof(HandlerData->Data)' not in body
          and 'sizeof (HandlerData->Data)' not in body,
          'sizeof of a Data[1] tail is 1, which is the whole defect')
    check('the payload is filled from the input',
          re.search(r'CopyMem \(\(UINT8 \*\)\(HandlerData->Data\), '
                    r'HandlerDataPayloadFill,', body) is not None)
    check('the fill is clamped to the message, not to the array',
          'MIN (HandlerDataPayloadRoom, sizeof (HandlerDataPayloadFill))' in body,
          'an unclamped copy writes past the end of the communication region')
    check('the room comes from MessageLength minus the tail offset',
          'HandlerDataPayloadRoom = CommHeader->MessageLength - HandlerDataPayloadAt'
          in body,
          'the handler computes its own DataSize exactly this way')
    check('the tail offset is derived from the pointers, not a type name',
          '(UINTN)((UINT8 *)(HandlerData->Data) - (UINT8 *)HandlerData)' in body
          and 'OFFSET_OF' not in body,
          'a spelled-out struct name goes stale against a respelled block')
    check('the region past the fill is zeroed',
          re.search(r'SetMem \(\(UINT8 \*\)\(HandlerData->Data\) \+ '
                    r'sizeof \(HandlerDataPayloadFill\),', body) is not None,
          'the comm region is shared by every iteration of the boot, so leftovers make '
          'one input mean two behaviours and the coverage feedback read its own history')
    check('and the zeroing is reached only when there is a region past the fill',
          'if (HandlerDataPayloadRoom > sizeof (HandlerDataPayloadFill)) {' in body,
          'guarding it with anything else -- or with nothing -- either skips the zeroing '
          'or runs SetMem with a length that underflowed')

    print('\noffset stability: every read of the input is a fixed size')
    reads = re.findall(r'ReadBytes\(Input, ([^,]+),', body)
    check('the payload region reads the input at all', len(reads) >= 4,
          f'found {len(reads)}')
    for argument in reads:
        check(f'ReadBytes({argument.strip()}, ...) is a fixed size',
              argument.strip().startswith('sizeof('),
              'a variable-length read moves the input offset of every later harness, and '
              'FirnessMain runs up to eight of them per input')

    print('\nthe plant policy')
    # Asserted as VALUES, not against the constants the emitter used: deriving the
    # expectation from the same constant makes the comparison a tautology, which is how a
    # window of 4096 survived this check once.
    check('the plant window stays inside a payload struct',
          0 < tpl.PAYLOAD_PLANT_WINDOW <= 128,
          f'{tpl.PAYLOAD_PLANT_WINDOW} bytes of window is {tpl.PAYLOAD_PLANT_WINDOW // 8} '
          f'pointer slots, and the one that holds the pointer is drawn that rarely; an SMM '
          f'payload struct is tens of bytes')
    check('there are enough plants for a pointer and a count together',
          tpl.PAYLOAD_PLANTS >= 8,
          'the SmmSpi READ arm needs an exact pointer AND a small ByteCount in the same '
          'dispatch, so one plant each is the minimum and both have to be drawn')
    check('the fill covers a payload struct',
          tpl.PAYLOAD_FILL_BYTES >= 64,
          'a fill shorter than the struct leaves its tail fields to whatever the last '
          'iteration wrote')
    check('the fill does not exceed the plant window',
          tpl.PAYLOAD_FILL_BYTES <= tpl.PAYLOAD_PLANT_WINDOW,
          f'{tpl.PAYLOAD_FILL_BYTES} filled against a {tpl.PAYLOAD_PLANT_WINDOW}-byte '
          f'window: the extra bytes cost input budget and no plant can reach them')

    # The invariant that actually broke, and it spans two files. One harness call now reads
    # the whole payload region, FirnessMain runs up to eight calls per input, and when the
    # input runs out ReadBytes zero-fills -- which is NOT neutral: a zeroed length selector
    # leaves MessageLength at sizeof(the block) and the handler refuses it on size. Run
    # 42933720452 measured 216 bytes a call against a 1024-byte seed.
    STEPS = 8
    OTHER_FIELDS = 88          # measured: RWVariable's fields beside the payload region
    per_call = tpl.PAYLOAD_FILL_BYTES + 3 * tpl.PAYLOAD_PLANTS + OTHER_FIELDS
    firness = ''
    for candidate in (os.path.join(HERE, 'firness.py'),
                      os.path.join(os.path.dirname(HERE), 'scripts', 'firness.py')):
        if os.path.exists(candidate):
            with open(candidate, encoding='utf-8', errors='replace') as handle:
                firness = handle.read()
            break
    seed = re.search(r"FIRNESS_SEED_SIZE',\s*'(\d+)'\)", firness)
    check('the default seed size is readable from firness.py', seed is not None,
          'without it this invariant cannot be checked and the budget silently regresses')
    budget = int(seed.group(1)) if seed else 0
    check(f'{STEPS} calls at {per_call} bytes fit the {budget}-byte default seed',
          per_call * STEPS <= budget,
          f'{per_call * STEPS} wanted against {budget}: the tail of every sequence runs '
          f'on zero-filled input, which parks MessageLength at sizeof(the block)')

    print('\nthe plants')
    check('the abutting pointer is tied to its own slot',
          'HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + '
          'HandlerDataPlantAt + sizeof (VOID *));' in body,
          'this is the edk2 idiom -- a pointer field that ends its struct holds the '
          'address just past itself -- and drawing the slot and the value apart spends '
          'the same 1/8 twice')
    check('pointer slots are capped to the plant window',
          f'MIN (HandlerDataPayloadRoom / sizeof (VOID *), '
          f'{tpl.PAYLOAD_PLANT_WINDOW // 8})' in body,
          'uncapped, a 4072-byte message gives 509 slots and the right one is never '
          'drawn')
    check('scalar slots are capped to the plant window',
          f'MIN (HandlerDataPayloadRoom / sizeof (UINT32), '
          f'{tpl.PAYLOAD_PLANT_WINDOW // 4})' in body)
    check('a slot is an aligned index, never a byte offset',
          re.search(r'% HandlerDataPlantSlots\) \* sizeof \(VOID \*\)', body) is not None
          and re.search(r'% HandlerDataPlantSlots\) \* sizeof \(UINT32\)', body)
          is not None,
          'indexing aligned slots is what keeps slot + sizeof inside the region however '
          'short the message is')
    check('a zero slot count is skipped rather than divided by',
          body.count('if (HandlerDataPlantSlots == 0) {') == 3,
          'room can be smaller than one slot, and % 0 is a fault in the harness')
    check('the loop runs PAYLOAD_PLANTS times',
          f'HandlerDataPlant < {tpl.PAYLOAD_PLANTS};' in body)
    check('a scalar plant can supply a small count',
          "'0'" in str(tpl.PAYLOAD_SCALAR_VALUES) and '0xFFFFFFFF'
          in str(tpl.PAYLOAD_SCALAR_VALUES),
          'the guard below the location check bounds Buffer + ByteCount against the end '
          'of the message, and a raw 32-bit count clears it about once in 2^29')
    check('one draw in four plants nothing',
          'a spent input plants nothing' in body,
          'the raw fill has to survive somewhere: a wild pointer from it is what reaches '
          'the #GP in VariableSmm\'s cache-context arm')
    check('the emitted braces balance',
          body.count('{') == body.count('}'),
          f"{body.count('{')} open against {body.count('}')} close")

    print('\na tail only counts when it is last')
    fields = [Field('Data', 'UINT8[1]'), Field('Function', 'UINTN')]

    class Info:
        def __init__(self):
            self.fields = fields
    tpl.aliases_map.clear()
    emitted = '\n'.join(tpl.generator_struct_args(
        'SPI_COMM_HEADER *', 'HandlerData', {}, {'SPI_COMM_HEADER': Info()},
        indent=False, field_constants=None))
    check('a byte array before other fields stays an ordinary field',
          'HandlerDataPayloadFill' not in emitted
          and 'sizeof(HandlerData->Data)' in emitted,
          'filling a mid-block array as a payload overwrites every field after it')

    fields_tail = [Field('Function', 'UINTN'), Field('Data', 'UINT8[1]')]

    class InfoTail:
        def __init__(self):
            self.fields = fields_tail
    emitted_tail = '\n'.join(tpl.generator_struct_args(
        'SPI_COMM_HEADER *', 'HandlerData', {}, {'SPI_COMM_HEADER': InfoTail()},
        indent=False, field_constants=None))
    check('the same array as the last field is the payload',
          'HandlerDataPayloadFill' in emitted_tail,
          'this is the layout every edk2 SMM comm buffer actually has')
    check('the fields before it are still read one by one',
          'ReadBytes(Input, sizeof(HandlerData->Function)' in emitted_tail)

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
