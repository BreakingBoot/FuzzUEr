#!/usr/bin/env python3
"""Assert a count argument is bounded by the ELEMENTS of its buffer, not by its bytes.

Measured on the 138-target sweep 43454245046, where the top two severities were one
generator defect. Every size argument was bounded by the buffer's size in BYTES, however
the declaration said the callee would walk it:

    UINTN*  Read_Arg_4 = (UINTN* )AllocateZeroPool(4096);   // IN OUT VOID *Buffer
    ReadBytes(Input, sizeof(Read_Arg_3), (VOID *)&Read_Arg_3);
    Read_Arg_3 = Read_Arg_3 % (4096 + 1);                   // IN UINTN Count

EFI_CPU_IO2_PROTOCOL.Mem.Read advances the buffer by mOutStride[Width] per step -- eight
bytes with EfiCpuIoWidthUint64 -- so a Count the harness called legal wrote 32768 bytes
into 4096. CpuIoCheckParameter validates Width, Address, Count and Buffer != NULL and
cannot check the capacity, because the PI spec makes that the caller's duty: the firmware
is correct and the harness overran its own allocation. That was 12 reports of a severity 5
heap-buffer-overflow WRITE at CpuIo2Dxe.c:254-256, 6 of a read at 335-337, 3 more at 548,
and one #DE -- all of it attributed to upstream edk2.

Four shapes have to answer the same question, "how many bytes is one element", and only
the first of them can be answered at generation time:

  * a width enum names the stride at runtime, so the bound is computed in the EMITTED C
    (1 << (Width & 0x03) -- the same expression the drivers index their stride tables
    with);
  * the buffer's pointee gives it statically, as sizeof (EFI_IPv6_ADDRESS) for Decline's
    AddressCount, which was bounded at sixteen against room for one address;
  * two arguments multiply into the extent, where the dimensions are bounded by a constant
    and the ALLOCATION has to carry the element size instead;
  * nothing names it, and then the bound is the widest stride a UEFI accessor steps by,
    said so in a comment. A bound that is too small costs coverage; a bound that is too
    large manufactures a severity 5.

A count of bytes under another name -- DeleteCount, whose DeleteList is UINT8 * -- is a
byte count, and everything about it stays as it was: the bound, the reallocation that puts
a redzone after the length, and the extent the call registers.

Run: python3 scripts/element_count_check.py
"""

import io
import json
import os
import re
import sys
import types as pytypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

# The sweep this was measured on, for the corroboration at the end. Absent on a runner.
SWEEP = '/home/gl055/fuzzuer-eval1/43454245046'

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def gen_source(path):
    """One of the generator's own files, by its path under harness_generator."""
    return io.open(os.path.join(GEN, path), encoding='utf-8').read()


def code(text):
    """A definition with its prose removed -- docstring and comments both.

    Every comment in the region asserted on here quotes the defect: the byte bound, the
    constant 4096, the name of the function that must be asked. Reading the raw text finds
    the explanation rather than the statements, and passes with the statement deleted.
    """
    found = re.search(r'"""', text)
    while found:
        try:
            closing = text.index('"""', found.end())
        except ValueError:
            break
        text = text[:found.start()] + text[closing + 3:]
        found = re.search(r'"""', text)
    kept = []
    for line in text.splitlines():
        if line.strip().startswith('#'):
            continue
        kept.append(line.split('  #')[0])
    return '\n'.join(kept)


def body(src, marker):
    """One definition's text, from its `def` to the next top-level one."""
    start = src.index(marker)
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Z_]+ = |@)', rest)
    return src[start:start + len(marker) + (end.start() if end else len(rest))]


def generator():
    """The generator's own modules, with the one import a runner does not have stubbed.

    analyze.py pulls fuzzywuzzy at module scope and it is not installed on a runner. It
    scores how close a generator function's NAME is to the function under test, which has
    nothing to do with a size argument's unit -- the fixtures below declare no generators.
    """
    if GEN not in sys.path:
        sys.path.insert(0, GEN)
    if 'fuzzywuzzy' not in sys.modules:
        package = pytypes.ModuleType('fuzzywuzzy')
        fuzz = pytypes.ModuleType('fuzzywuzzy.fuzz')
        fuzz.ratio = lambda one, two: 0
        package.fuzz = fuzz
        sys.modules['fuzzywuzzy'] = package
        sys.modules['fuzzywuzzy.fuzz'] = fuzz
    from common import types as common_types
    import uefi_harness.harnesses_template as template
    return common_types, template


COMMON, TEMPLATE = generator()


def argument(arg_type, param_name='', arg_dir='IN', variable='__FUZZABLE__',
             data_type=''):
    return [COMMON.Argument(arg_dir, arg_type, '', data_type, '', variable,
                            param_name=param_name)]


def emit(args, random=False):
    """Declare, fill and call one function block, as the three sections do.

    Returns (declarations, the fill lines for every argument, the FirnessUntrusted lines).
    The span and the array-ness are taken from the same functions the generator takes them
    from, so a fixture cannot pass by being told something the generator is not.
    """
    block = COMMON.FunctionBlock(args, 'Fuzz', 'protocol', [], 'EFI_STATUS')
    span = (TEMPLATE.dimension_span(args) if TEMPLATE.has_dimension_arg(args) else 0)
    tracked = []
    declared = []
    for key, entry in args.items():
        declared += TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False,
                                         random, TEMPLATE.walks_as_array(args, key), span)
    filled = []
    for key in args:
        filled += TEMPLATE.fuzzable_args('Fuzz', key, False, tracked, args, '')
    called = TEMPLATE.call_function('Fuzz', block, {'Fuzz': block}, 'Protocol', tracked,
                                   False, '')
    return declared, filled, [line for line in called if 'FirnessUntrusted' in line]


def bound_of(filled, name):
    """The right-hand side of the clamp on `name`, or None if it is not clamped."""
    for line in filled:
        found = re.search(rf'\*?Fuzz_{name} = \*?Fuzz_{name} % \((.*) \+ 1\);$',
                          line.strip())
        if found:
            return found.group(1)
    return None


def allocation_of(declared, name):
    for line in declared:
        found = re.search(rf'Fuzz_{name} = \([^)]*\)AllocateZeroPool\((.*)\);$',
                          line.strip())
        if found:
            return found.group(1)
    return None


def extent_of(registrations, name):
    for line in registrations:
        found = re.search(rf'FirnessUntrusted\(Fuzz_{name}, (.*)\);$', line.strip())
        if found:
            return found.group(1)
    return None


def resized(filled, name):
    """Whether the buffer `name` is reallocated to the size it was told it has."""
    return any(f'Fuzz_{name} = ' in line and 'AllocateZeroPool' in line
               for line in filled)


def late_resizes(args):
    """The reallocations the pass after the output declarations emits.

    An OUT buffer is declared after the input section, so its reallocation cannot be
    emitted beside the size that drives it and is done here instead. It is the same
    decision and a separate reader of it.
    """
    block = COMMON.FunctionBlock(args, 'Fuzz', 'protocol', [], 'EFI_STATUS')
    tracked = []
    for key, entry in args.items():
        TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False, False,
                             TEMPLATE.walks_as_array(args, key), 0)
    return TEMPLATE.resize_output_buffers(block, tracked)


# ---------------------------------------------------------------------------------------
# The fixtures. Each pair below differs in ONE attribute from the case it is compared with,
# because an assertion about a fixture that differs in two says nothing about either.

def cpu_io(order=('This', 'Width', 'Address', 'Count', 'Buffer'), count_name='Count'):
    """EFI_CPU_IO_PROTOCOL_IO_MEM, with the argument order under the caller's control."""
    pieces = {
        'This': argument('EFI_CPU_IO2_PROTOCOL *', 'This', variable='__PROTOCOL__'),
        'Width': argument('EFI_CPU_IO_PROTOCOL_WIDTH', 'Width', variable='__ENUM_ARG__',
                          data_type='int'),
        'Address': argument('UINT64', 'Address'),
        'Count': argument('UINTN', count_name),
        'Buffer': argument('VOID *', 'Buffer', arg_dir='IN OUT'),
    }
    return {f'Arg_{index}': pieces[name] for index, name in enumerate(order)}


DECLINE = {  # EFI_DHCP6_PROTOCOL.Decline
    'Arg_0': argument('EFI_DHCP6_PROTOCOL *', 'This', variable='__PROTOCOL__'),
    'Arg_1': argument('UINT32', 'AddressCount'),
    'Arg_2': argument('EFI_IPv6_ADDRESS *', 'Addresses'),
}

BOOT_LOGO = {  # EDKII_BOOT_LOGO2_PROTOCOL.SetBootLogo
    'Arg_0': argument('EDKII_BOOT_LOGO2_PROTOCOL *', 'This', variable='__PROTOCOL__'),
    'Arg_1': argument('EFI_GRAPHICS_OUTPUT_BLT_PIXEL *', 'BltBuffer'),
    'Arg_2': argument('UINTN', 'DestinationX'),
    'Arg_3': argument('UINTN', 'DestinationY'),
    'Arg_4': argument('UINTN', 'Width'),
    'Arg_5': argument('UINTN', 'Height'),
}


def main():
    print('a count with a runtime stride is bounded in elements, in the emitted C')
    _declared, filled, registered = emit(cpu_io())
    count = bound_of(filled, 'Arg_3')
    check('the count is bounded', count is not None,
          'an unbounded count walks until it faults')
    check('and not by the buffer\'s size in bytes', count != '4096',
          f'got {count!r} -- this is the defect: 4096 strides of up to eight bytes '
          f'through 4096 bytes')
    check('the bound divides the capacity by the stride',
          count == '(4096 / (1 << (Fuzz_Arg_1 & 0x03)))', f'got {count!r}')
    check('the stride is computed in C, from the width the fuzzer picked',
          count is not None and 'Fuzz_Arg_1' in count,
          'the harness cannot know the width at generation time, so a constant here is '
          'either wrong or the conservative one')
    check('and it is the log2 of the low two bits, as the drivers read it',
          count is not None and '& 0x03' in count,
          'CpuIo2Dxe does OperationWidth = Width & 0x03 and indexes mOutStride with it')
    check('the width is reported as a runtime decision',
          TEMPLATE.element_size_for('Count', 'Arg_4', cpu_io(), 'Fuzz')[1] == 'runtime')

    print('\nthe same call with the count renamed a size keeps the byte bound')
    # One attribute apart: Count -> BufferSize, same types, same order, same buffer.
    _d, sized, _r = emit(cpu_io(count_name='BufferSize'))
    check('a byte count is bounded by bytes', bound_of(sized, 'Arg_3') == '4096',
          f'got {bound_of(sized, "Arg_3")!r} -- a size is already in the unit the '
          f'allocation is in, and tightening it would cost coverage for nothing')
    check('counts_elements tells the two apart',
          TEMPLATE.counts_elements('Count') and not TEMPLATE.counts_elements('BufferSize'))
    for name in ('NumberOfBytes', 'DataLength', 'FatSize', 'PacketLen'):
        check(f'{name} is a byte count', not TEMPLATE.counts_elements(name))
    for name in ('Count', 'OptionCount', 'AddressCount', 'HandleCount'):
        check(f'{name} counts elements', TEMPLATE.counts_elements(name))
    for name in ('TokenNumber', 'ModeNumber', 'ProcessorNumber', 'Index', 'Attributes'):
        check(f'{name} is neither -- it is an index',
              not TEMPLATE.counts_elements(name),
              'bounding an identifier by a buffer it has nothing to do with is how a '
              'wide net costs coverage')

    print('\na width spelled after the count is not read before it is set')
    reordered = cpu_io(order=('This', 'Count', 'Address', 'Width', 'Buffer'))
    check('io_width_arg finds the width when it comes first',
          TEMPLATE.io_width_arg(cpu_io(), before='Arg_3') == 'Arg_1')
    check('and refuses it when it comes after the count',
          TEMPLATE.io_width_arg(reordered, before='Arg_1') == '',
          'the declarations all come first, so reading it there compiles and reads {0}, '
          'which gives a stride of one and quietly restores the byte bound')
    _d, late, _r = emit(reordered)
    late_bound = bound_of(late, 'Arg_1')
    check('so the emitted bound does not name the width variable',
          late_bound is not None and 'Fuzz_Arg_3' not in late_bound, f'got {late_bound!r}')
    check('it is the conservative stride instead',
          late_bound == f'(4096 / {TEMPLATE.FIRNESS_UNKNOWN_STRIDE})', f'got {late_bound!r}')
    check('and the harness says why in a comment',
          any('names the stride' in line for line in late),
          'a bound nobody can explain is the one that gets reverted')

    print('\na count whose buffer gives the element size statically')
    declared, filled, registered = emit(DECLINE)
    bound = bound_of(filled, 'Arg_1')
    check('AddressCount is bounded by addresses, not bytes',
          bound == '(4096 / sizeof(EFI_IPv6_ADDRESS))',
          f'got {bound!r} -- sixteen was sixteen addresses out of room for one')
    check('and the buffer is allocated as the array the count says it is',
          allocation_of(declared, 'Arg_2') == '4096',
          f'got {allocation_of(declared, "Arg_2")!r} -- one element, with a count of '
          f'them, is the same overflow from the other side')
    check('the extent registered is the allocation, not the count',
          extent_of(registered, 'Arg_2') == allocation_of(declared, 'Arg_2'),
          f'registered {extent_of(registered, "Arg_2")!r}, allocated '
          f'{allocation_of(declared, "Arg_2")!r} -- a count of addresses is not a '
          f'number of bytes, and nothing reallocated the buffer to it')
    check('a UINT64 * buffer with a plain Count is bounded by its own element',
          bound_of(emit({
              'Arg_0': argument('UINT64 *', 'Buffer'),
              'Arg_1': argument('UINTN', 'Count')})[1], 'Arg_1')
          == '(4096 / sizeof(UINT64))',
          'the buffer is the only one in the call, so there is no ambiguity about what '
          'the count counts')

    print('\na count handed over by pointer is bounded the same way')
    # UEFI spells a good half of these as IN OUT UINTN *Count beside the buffer, and that
    # branch of the template is the one that was left unbounded the last time a size bound
    # was fixed. Same shape as Decline above, one declarator apart.
    by_pointer = {'Arg_0': argument('UINT32 *', 'AddressCount', arg_dir='IN OUT'),
                  'Arg_1': argument('EFI_IPv6_ADDRESS *', 'Address')}
    _d, filled, _r = emit(by_pointer)
    check('*AddressCount is bounded by addresses too',
          bound_of(filled, 'Arg_0') == '(4096 / sizeof(EFI_IPv6_ADDRESS))',
          f'got {bound_of(filled, "Arg_0")!r} -- the two branches emit the same bound in '
          f'the same unit or one of them is the next defect')
    # the same pointer, named a size: one attribute apart.
    _d, sized, _r = emit({'Arg_0': argument('UINT32 *', 'AddressSize', arg_dir='IN OUT'),
                          'Arg_1': argument('EFI_IPv6_ADDRESS *', 'Address')})
    check('and a size by pointer keeps the byte bound',
          bound_of(sized, 'Arg_0') == 'sizeof(EFI_IPv6_ADDRESS)',
          f'got {bound_of(sized, "Arg_0")!r}')

    print('\nand a count of bytes under another name is left alone')
    # DHCP4's DeleteCount, whose DeleteList is a UINT8 * of option tags: an element count
    # by name, a byte count in fact. One attribute apart from Decline: the pointee type.
    bytes_pair = {'Arg_0': argument('UINT8 *', 'DeleteList'),
                  'Arg_1': argument('UINTN', 'DeleteCount')}
    declared, filled, registered = emit(bytes_pair)
    check('the bound is the buffer\'s size', bound_of(filled, 'Arg_1') == '4096',
          f'got {bound_of(filled, "Arg_1")!r}')
    check('the reallocation that puts a redzone after it is kept',
          resized(filled, 'Arg_0'),
          'this is what makes a firmware write past the length detectable, and a count '
          'of one-byte elements still agrees with it')
    check('and the size argument is still the extent',
          extent_of(registered, 'Arg_0') == 'Fuzz_Arg_1',
          f'got {extent_of(registered, "Arg_0")!r}')
    check('element_size_for calls a UINT8 element one byte',
          TEMPLATE.element_size_for('DeleteCount', 'Arg_0', bytes_pair) == ('1', 'bytes'))

    print('\nthe pass that reallocates an OUT buffer makes the same distinction')
    # An OUT buffer is declared after the input section, so its reallocation is emitted by
    # a later pass -- a second reader of the same decision. Reallocating to a count of
    # UINT64 elements leaves the buffer a stride too short per element, which is the same
    # overflow the byte bound asked for, moved into the allocation.
    out_count = {'Arg_0': argument('UINT64 *', 'Buffer', arg_dir='OUT'),
                 'Arg_1': argument('UINTN', 'BufferCount')}
    check('an element count does not become a byte reallocation',
          not resized(late_resizes(out_count), 'Arg_0'),
          f'{late_resizes(out_count)}')
    # the same call with the count named a size: one attribute apart, and this one must
    # still be reallocated or the redzone moves away from the length the callee was given
    out_size = {'Arg_0': argument('UINT64 *', 'Buffer', arg_dir='OUT'),
                'Arg_1': argument('UINTN', 'BufferSize')}
    check('and a byte size still is',
          resized(late_resizes(out_size), 'Arg_0'),
          f'{late_resizes(out_size)}')

    print('\ntwo arguments that multiply: the allocation carries the element size')
    declared, filled, registered = emit(BOOT_LOGO)
    allocated = allocation_of(declared, 'Arg_1')
    check('the dimensioned allocation names the element',
          allocated is not None and 'sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)' in allocated,
          f'got {allocated!r} -- 16 x 16 of a 32 byte element is 8192, and a page of it '
          f'is the harness asking for the overrun')
    check('it is never smaller than the page it used to be',
          allocated is not None and allocated.startswith('(4096 > '),
          f'got {allocated!r} -- over-allocating cannot produce a false overflow; '
          f'under-allocating always can')
    check('and the extent follows it',
          extent_of(registered, 'Arg_1') == allocated,
          f'registered {extent_of(registered, "Arg_1")!r}')
    check('the dimensions themselves keep the constant cap',
          bound_of(filled, 'Arg_4') == str(TEMPLATE.FIRNESS_DIMENSION_MAX)
          and bound_of(filled, 'Arg_5') == str(TEMPLATE.FIRNESS_DIMENSION_MAX),
          f'Width {bound_of(filled, "Arg_4")!r}, Height {bound_of(filled, "Arg_5")!r} -- '
          f'a dimension cannot be bounded by a byte count, which is why the allocation '
          f'is where the element size goes')
    # The same call without its coordinates: one attribute apart, and the reach halves in
    # each dimension because DestinationY + Height is what indexes the buffer.
    no_coords = {key: value for key, value in BOOT_LOGO.items()
                 if key not in ('Arg_2', 'Arg_3')}
    check('coordinates double the span in each dimension',
          TEMPLATE.dimension_span(BOOT_LOGO) == 4 * TEMPLATE.dimension_span(no_coords),
          f'{TEMPLATE.dimension_span(BOOT_LOGO)} with them, '
          f'{TEMPLATE.dimension_span(no_coords)} without')
    check('a dimensioned byte buffer keeps the plain page',
          allocation_of(emit({
              'Arg_0': argument('VOID *', 'Buffer'),
              'Arg_1': argument('UINTN', 'Width')})[0], 'Arg_0') == '4096',
          'the span of a buffer with no element size is counted in bytes already')

    print('\nwhen nothing names the element size, the bound says so')
    # Two buffers and a count that names neither: which one it counts cannot be said.
    ambiguous = {'Arg_0': argument('VOID *', 'Buffer'),
                 'Arg_1': argument('VOID *', 'Scratch'),
                 'Arg_2': argument('UINTN', 'Count')}
    _d, filled, _r = emit(ambiguous)
    check('the count is still bounded', bound_of(filled, 'Arg_2') is not None)
    check('by the widest stride a UEFI accessor steps by',
          bound_of(filled, 'Arg_2') == f'(4096 / {TEMPLATE.FIRNESS_UNKNOWN_STRIDE})',
          f'got {bound_of(filled, "Arg_2")!r}')
    check('and the emitted C explains the choice',
          any('names the stride' in line for line in filled),
          'the next person to read this has to be able to tell a conservative bound '
          'from a wrong one')
    check('sole_buffer_arg answers nothing when there are two',
          TEMPLATE.sole_buffer_arg(ambiguous) == '')
    check('and names the one when there is one',
          TEMPLATE.sole_buffer_arg(cpu_io()) == 'Arg_4',
          'the protocol instance is not a buffer: nothing is allocated for it')

    print('\nthe buffer a count counts is the collection, never another number')
    options = {  # EFI_DHCP6_PROTOCOL.InfoRequest, cut down to the pairing question
        'Arg_0': argument('UINT32', 'OptionCount'),
        'Arg_1': argument('EFI_DHCP6_PACKET_OPTION *', 'OptionRequest'),
        'Arg_2': argument('EFI_DHCP6_PACKET_OPTION **', 'OptionList'),
    }
    check('the list wins over the single option',
          TEMPLATE.buffer_for_count('OptionCount', options) == 'Arg_2',
          'OptionRequest is one option; the count counts the list, and the element '
          'sizes differ by three')
    arp = {  # EFI_ARP_PROTOCOL.Find, cut down likewise
        'Arg_0': argument('UINT32 *', 'EntryLength', arg_dir='OUT'),
        'Arg_1': argument('UINT32 *', 'EntryCount', arg_dir='OUT'),
        'Arg_2': argument('VOID **', 'Entries', arg_dir='OUT'),
    }
    check('a count is never paired with a size',
          TEMPLATE.buffer_for_count('EntryCount', arp) != 'Arg_0',
          'EntryLength is the other out-parameter; pairing them bounds a count by '
          'sizeof (UINT32) and calls four an element size')
    check('an exact stem match still wins',
          TEMPLATE.buffer_for_count('HandleCount', {
              'Arg_0': argument('EFI_HII_HANDLE *', 'Handle'),
              'Arg_1': argument('UINTN', 'HandleCount')}) == 'Arg_0')

    print('\na member with no count and no buffer pair is emitted as it was')
    plain = {'Arg_0': argument('EFI_GUID *', 'Guid'),
             'Arg_1': argument('UINT32', 'Attributes')}
    declared, filled, registered = emit(plain)
    check('no clamp is invented for an integer that sizes nothing',
          bound_of(filled, 'Arg_1') is None,
          f'got {bound_of(filled, "Arg_1")!r}')
    check('the typed pointer keeps its element allocation',
          allocation_of(declared, 'Arg_0') == 'sizeof(EFI_GUID)',
          f'got {allocation_of(declared, "Arg_0")!r}')
    check('and its extent is that allocation',
          extent_of(registered, 'Arg_0') == 'sizeof(EFI_GUID)',
          f'got {extent_of(registered, "Arg_0")!r}')
    check('walks_as_array says no to a call that counts nothing',
          not TEMPLATE.walks_as_array(plain, 'Arg_0'))
    check('and yes to the buffer a count counts',
          TEMPLATE.walks_as_array(DECLINE, 'Arg_2'))
    check('but not to the other arguments of that call',
          not TEMPLATE.walks_as_array(DECLINE, 'Arg_0'),
          'a page for an argument nothing counts registers 4096 untrusted bytes where '
          'the fuzzer filled sizeof(*p)')

    print('\nfour readers, one decision')
    template_src = code(gen_source('uefi_harness/harnesses_template.py'))
    for what, marker in (('the by-value bound', 'def fuzzable_args('),
                         ('the reallocation pass', 'def resize_paired_buffers('),
                         ('the extent the call registers', 'def call_function(')):
        region = code(body(gen_source('uefi_harness/harnesses_template.py'), marker))
        check(f'{what} asks buffer_and_element_for',
              'buffer_and_element_for(' in region,
              'the by-value and by-pointer bounds have drifted apart once already')
    check('the by-pointer bound asks it too',
          code(body(gen_source('uefi_harness/harnesses_template.py'),
                    'def fuzzable_args(')).count('buffer_and_element_for(') >= 2,
          'one call covers the value branch only; the pointer branch is the one that was '
          'left unbounded last time')
    check('nothing bounds a size by the blanket constant without asking the unit',
          'element_limit(' in template_src,
          'the division by the element size is the whole fix')

    if os.path.isdir(SWEEP):
        print('\nand on the member the sweep failed on')
        shipped = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'Firness',
                               'FirnessHarnesses.c')
        recorded = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'Firness',
                                'processed_data.json')
        if os.path.isfile(shipped):
            text = io.open(shipped, encoding='utf-8', errors='ignore').read()
            check('the harness that ran was bounded by bytes',
                  'Read_Arg_3 = Read_Arg_3 % (4096 + 1);' in text,
                  'if this is gone the campaign was regenerated and this file is no '
                  'longer evidence of anything')
        if os.path.isfile(recorded):
            data = json.load(io.open(recorded, encoding='utf-8'))
            blocks = [entry for entry in data if entry.get('function') == 'Read']
            args = {}
            for key, recorded_args in (blocks[0]['arguments'] if blocks else {}).items():
                first = recorded_args[0]
                args[key] = argument(first['Arg Type'], first['Param Name'],
                                     first['Arg Dir'], first['Variable'],
                                     first['Data Type'])
            check('the analyser really did record a width enum beside the count',
                  TEMPLATE.io_width_arg(args, before='Arg_3') == 'Arg_1',
                  f'{[(k, v[0].param_name, v[0].arg_type) for k, v in args.items()]}')
            _d, real, _r = emit(args)
            check('and its own recorded arguments now bound Count by elements',
                  bound_of(real, 'Arg_3') == '(4096 / (1 << (Fuzz_Arg_1 & 0x03)))',
                  f'got {bound_of(real, "Arg_3")!r}')
    else:
        print(f'\n  [skip] {SWEEP} is not on this host')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
