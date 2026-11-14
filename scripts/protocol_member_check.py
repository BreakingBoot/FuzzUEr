#!/usr/bin/env python3
"""Assert a member belongs to its own protocol: its declaration, its type, its address.

Three defects in the harness generator, each measured by regenerating all 142 cached
analyses of EVAL-1 runs 43454245046 (138 campaigns) and 43452927684 (4, SMI) before and
after, with PYTHONHASHSEED pinned so the include lists are comparable.

A declaration keyed by the bare member name. UEFI protocol members share names: Read,
Write, Reset, Configure, GetModeData, Poll. load_function_declares wrote one entry per
name, so a member's declared argument types and param_names were whichever same-named
declaration the analyser read last -- from any driver, for any protocol. EfiCpuIo2's own
functions.json records nothing but EFI_FILE_PROTOCOL's three-parameter Read and Write out
of OvmfPkg/VirtioFsDxe/VirtioFsDxe.h, so EFI_CPU_IO2_PROTOCOL.Read, which takes
(This, Width, Address, Count, Buffer), was described as (This, BufferSize, Buffer). Across
the 142 campaigns that is 122 of 635 requested members, carrying 364 (campaign, argument)
positions, whose declaration belonged to another protocol; none of the 122 is an alias
declared in the requested GUID's own header, so none of the refusals loses a real
declaration. The key is now the protocol struct the declaration's own first parameter
names, normalized the way harness_match already normalizes it, because the header that
declares the GUID is this file's stated authority for what belongs to a protocol.

A body taken from the wrong struct. protocol_struct_body's fallback for an anonymous
typedef was anchored at its END -- `typedef\\s+struct\\s*\\{(.*?)\\n\\}\\s*\\w*?NAME\\s*;`
-- and a non-greedy body is still leftmost-first, so in a header with two anonymous
typedef structs the opening brace came from the FIRST of them. MdePkg/Include/Protocol/
PciIo.h declares EFI_PCI_IO_PROTOCOL_ACCESS at line 189 and
EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS at 228; asked for the second, the answer began inside
the first and EFI_PCI_IO_PROTOCOL.Pci.Read was typed EFI_PCI_IO_PROTOCOL_IO_MEM instead of
EFI_PCI_IO_PROTOCOL_CONFIG. Those differ: CONFIG takes (This, Width, UINT32 Offset, Count,
Buffer) and IO_MEM takes (This, Width, BarIndex, UINT64 Offset, Count, Buffer). With the
types merged the harness assigned Pci.Read to a variable of the other function-pointer
type and called it with an argument too many, and EfiPciIo and EfiPciRootBridgeIo did not
compile at all. Resolved brace for brace now, and because the two signatures are really
different, Pci.Read gets its own harness rather than a cast or a shared switch: all six
PciIo access paths are emitted where two were.

An address bounded by a buffer. The blanket arm reads "this call takes a raw buffer, so
its integer arguments are the sizes and offsets into it", which is not true of an address:
EFI_CPU_IO2_PROTOCOL.Read's Address was bounded to 4096, which through the Io arm of that
protocol is the legacy I/O page -- the PIC at 0x20/0xA0, the PIT at 0x40-0x43, CMOS/RTC at
0x70/0x71, the keyboard controller at 0x60/0x64 -- and EFI_MM_CPU_IO_PROTOCOL's recorded
constants for the same parameter are the ICH9 CPU hotplug registers and ICH9_APM_CNT, the
SMI command port, by name. That campaign managed 111 iterations of an 1800s budget at
0.065 exec/s and reported nothing for its last 27 minutes. Of the 62 address-named
argument positions in the 142 campaigns only six carried the bound, and they are exactly
the three raw-bus accessors; EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.PollMem takes the same
UINT64 Address with no buffer beside it, was never bounded, and ran 2830 iterations.

The Io arms stay. The instruction this closes said dropping them "costs no detection";
EfiCpuIo2's crashes.csv says otherwise -- CpuIo2Dxe.c:548 is inside CpuIoServiceWrite,
which mCpuIo2 reaches only through Io.Write, and three of the six fwsan double-fetch sites
are in it. What is removed instead is the reason the address was small: the buffer bound,
and the recorded constant that started a sweep at a hardware address.

Run: python3 scripts/protocol_member_check.py
"""

import io
import json
import os
import re
import sys
import tempfile
import types as pytypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

# The sweeps the measurements above come from, and the tree they were analysed against.
# A runner has none of them.
SWEEP = '/home/gl055/fuzzuer-eval1/43454245046'
SMI_SWEEP = '/home/gl055/fuzzuer-eval1/43452927684'
TREE = '/home/gl055/eval-trees/eval1_edk2'
PCIIO_H = os.path.join(TREE, 'MdePkg', 'Include', 'Protocol', 'PciIo.h')
CPUIO_C = os.path.join(TREE, 'UefiCpuPkg', 'CpuIo2Dxe', 'CpuIo2Dxe.c')

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

    Every comment in the code asserted on here quotes the defect it fixes by name: the
    4096 clamp, the word Address, the name of the function that must be asked, the regular
    expression that was wrong. An assertion made against the raw text finds the
    explanation rather than the statement and passes with the statement deleted. That
    mutation is the one this project has let through before.
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
    """One definition's text, from its `def` to the next top-level one.

    An absent marker answers with nothing rather than raising. A check that dies on a
    deleted anchor has reported nothing, and a mutation run cannot tell that from a catch.
    """
    try:
        start = src.index(marker)
    except ValueError:
        return ''
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Z_]+ = |@)', rest)
    return src[start:start + len(marker) + (end.start() if end else len(rest))]


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not.

    A bare .index() on an anchor a mutation deleted raises, and a check that dies on its
    own traceback has not caught anything. An ordering assertion also has to insist on
    both ends: `[] < [n]` is true, so "A before B" passes when A has been deleted.
    """
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def occurrences(text, needle):
    """How many times `needle` appears -- so a mutation's anchor can be required to be one."""
    return text.count(needle)


def generator():
    """The generator's own modules, with the one import a runner does not have stubbed.

    analyze.py pulls fuzzywuzzy at module scope and it is not installed on a runner. It
    scores how close a generator function's NAME is to the function under test, which
    decides nothing asserted here -- the fixtures below declare no generators.
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
    from common import utils as common_utils
    from data_analysis import analyze
    import uefi_harness.harnesses_template as template
    return common_types, common_utils, analyze, template


COMMON, UTILS, ANALYZE, TEMPLATE = generator()

# Fetched by name rather than imported, so that REMOVING one is a failing assertion rather
# than an ImportError at the top of the file. A check that dies before its first line of
# output has not caught anything, and nothing reading exit codes can tell that from a
# check that ran.
IS_ADDRESS_NAME = getattr(UTILS, 'is_address_name', None)
ADDRESS_SUFFIXES = getattr(UTILS, 'ADDRESS_NAME_SUFFIXES', None)
DECLARATION_KEY = getattr(ANALYZE, 'declaration_key', None)
DECLARATION_FOR = getattr(ANALYZE, 'declaration_for', None)
DECLARATIONS_NAMED = getattr(ANALYZE, 'declarations_named', None)
ANON_STRUCT_BODY = getattr(ANALYZE, 'anon_struct_body', None)


def argument(arg_type, param_name='', arg_dir='IN', variable='__FUZZABLE__',
             data_type='', usage=''):
    return [COMMON.Argument(arg_dir, arg_type, '', data_type, usage, variable,
                            param_name=param_name)]


def emit(args):
    """Declare and fill, as function_body does in that order.

    Returns (declarations, input fills). The span and the array-ness are taken from the
    same functions the generator takes them from, and the IN exclusions are the ones
    generate_inputs applies, so a fixture cannot pass by being told something the
    generator is not.
    """
    span = TEMPLATE.dimension_span(args) if TEMPLATE.has_dimension_arg(args) else 0
    tracked = []
    declared = []
    for key, entry in args.items():
        if 'IN' not in entry[0].arg_dir:
            continue
        declared += TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False,
                                         False, TEMPLATE.walks_as_array(args, key), span)
    filled = []
    for key, entry in args.items():
        if 'IN' not in entry[0].arg_dir:
            continue
        filled += TEMPLATE.fuzzable_args('Fuzz', key, False, tracked, args, '')
    return declared, filled


def bound_of(lines, name):
    """The right-hand side of the clamp on `name`, or None if it is not clamped."""
    for line in lines:
        found = re.search(rf'^\*?Fuzz_{name} = \*?Fuzz_{name} % \((.*) \+ 1\);$',
                          line.strip())
        if found:
            return found.group(1)
    return None


def declaration(name, params, file='/w/edk2/Driver/Driver.h'):
    """One entry of functions.json, as firness records a declaration."""
    return {
        'File': file, 'Function': name, 'Includes': [file], 'ReturnType': 'EFI_STATUS',
        'Parameters': {
            f'Arg_{index}': {'arg_dir': direction, 'arg_type': arg_type,
                             'assignment': '', 'data_type': '', 'is_optional': False,
                             'potential_outputs': [], 'usage': '', 'variable': variable}
            for index, (arg_type, direction, variable) in enumerate(params)},
    }


def loaded(*entries):
    """load_function_declares over a functions.json holding exactly these entries."""
    handle = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    try:
        json.dump(list(entries), handle)
        handle.close()
        return ANALYZE.load_function_declares(handle.name)
    finally:
        os.unlink(handle.name)


# The two declarations the sweep actually holds for the name "Read": EFI_FILE_PROTOCOL's,
# which is the one that won, and EFI_CPU_IO2_PROTOCOL's, which is what the member takes.
# They differ in the protocol and in nothing else that is asserted about them.
FILE_READ = declaration('Read', [('EFI_FILE_PROTOCOL *', 'IN', '__PROTOCOL__'),
                                 ('UINTN *', 'IN_OUT', 'BufferSize'),
                                 ('void *', 'OUT', 'Buffer')],
                        file='/w/edk2/OvmfPkg/VirtioFsDxe/VirtioFsDxe.h')
CPUIO_READ = declaration('Read', [('EFI_CPU_IO2_PROTOCOL *', 'IN', '__PROTOCOL__'),
                                  ('EFI_CPU_IO_PROTOCOL_WIDTH', 'IN', 'Width'),
                                  ('UINT64', 'IN', 'Address'),
                                  ('UINTN', 'IN', 'Count'),
                                  ('void *', 'IN_OUT', 'Buffer')],
                         file='/w/edk2/UefiCpuPkg/CpuIo2Dxe/CpuIo2Dxe.c')
# the same member declared with edk2's tag spelling, "struct _EFI_CPU_IO2_PROTOCOL"
TAGGED_READ = declaration('Read', [('_EFI_CPU_IO2_PROTOCOL *', 'IN', '__PROTOCOL__'),
                                   ('EFI_CPU_IO_PROTOCOL_WIDTH', 'IN', 'Width'),
                                   ('UINT64', 'IN', 'Address'),
                                   ('UINTN', 'IN', 'Count'),
                                   ('void *', 'IN_OUT', 'Buffer')])
# a free function, whose first parameter names no protocol at all
FREE = declaration('CreateBdsEvent', [('UINTN', 'IN', 'Timeout')],
                   file='/w/edk2/MdeModulePkg/Bds.h')
FREE_AGAIN = declaration('CreateBdsEvent', [('UINTN', 'IN', 'Timeout')],
                         file='/w/edk2/MdeModulePkg/Bds2.h')
FREE_CONFLICT = declaration('CreateBdsEvent', [('CHAR16 *', 'IN', 'Name')],
                            file='/w/edk2/MdeModulePkg/Bds3.h')


# A header with two anonymous typedef structs, the second of which is the one asked for.
# The field names are shared, which is the whole difficulty: the first `Read;` a merged
# body contains belongs to the first struct.
TWO_ANON = '''
typedef struct {
  FIRST_KIND    Read;
  FIRST_KIND    Write;
} FIRST_ACCESS;

typedef struct {
  SECOND_KIND    Read;
  SECOND_KIND    Write;
} SECOND_ACCESS;
'''

# ...and one whose body holds a nested struct closing at column 0. The formatting is
# deliberately adversarial: what it separates is a scan that counts braces from one that
# stops at the first "\n}", and only the first of those can be relied on for a body whose
# shape nobody controls.
NESTED_ANON = '''
typedef struct {
  struct {
    UINT8 Low;
    UINT8 High;
}             Split;
  OUTER_KIND    Read;
} OUTER_ACCESS;
'''

# edk2 also spells the closing name with a tag prefix
TAGGED_ANON = '''
typedef struct {
  TAG_KIND    Read;
} _TAGGED_ACCESS;
'''


def cpu_io(address_name='Address'):
    """EFI_CPU_IO_PROTOCOL_IO_MEM: (This, Width, Address, Count, Buffer)."""
    return {
        'Arg_0': argument('EFI_CPU_IO2_PROTOCOL *', 'This', variable='__PROTOCOL__',
                          usage='gEfiCpuIo2ProtocolGuid'),
        'Arg_1': argument('EFI_CPU_IO_PROTOCOL_WIDTH', 'Width', variable='__ENUM_ARG__',
                          data_type='int'),
        'Arg_2': argument('UINT64', address_name),
        'Arg_3': argument('UINTN', 'Count'),
        'Arg_4': argument('VOID *', 'Buffer', arg_dir='IN OUT'),
    }


def by_pointer(size_name='BufferSize'):
    """A size handed over by pointer, beside the raw buffer it is bounded against."""
    return {
        'Arg_0': argument('EFI_CPU_IO2_PROTOCOL *', 'This', variable='__PROTOCOL__'),
        'Arg_1': argument('UINTN *', size_name, arg_dir='IN OUT'),
        'Arg_2': argument('VOID *', 'Buffer', arg_dir='IN OUT'),
    }


PROTOCOL_HEADER = """
extern EFI_GUID  gTestProtocolGuid;

typedef struct _TEST_PROTOCOL TEST_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *TEST_MEM)(
  IN TEST_PROTOCOL  *This,
  IN UINT64         Address,
  IN UINTN          Count
  );

typedef struct {
  TEST_MEM    Read;
} TEST_MEM_ACCESS;

typedef
EFI_STATUS
(EFIAPI *%s)(
  IN TEST_PROTOCOL  *This,
  IN UINT32         Offset
  );

typedef struct {
  %s    Read;
} TEST_CFG_ACCESS;

struct _TEST_PROTOCOL {
  TEST_MEM_ACCESS     Mem;
  TEST_CFG_ACCESS     Cfg;
};
"""


def synthesised(member='Read', second_kind='TEST_CFG'):
    """What sort_data builds from a protocol header, keyed by harness function name.

    second_kind is the only thing that differs between the two cases below: TEST_CFG
    gives Cfg.Read a signature of its own, and TEST_MEM makes all the paths one
    signature, which is what the merged body used to report for every one of them.
    """
    work = tempfile.mkdtemp(prefix='protocol-member-')
    try:
        folder = os.path.join(work, 'w', 'edk2', 'TestPkg', 'Include', 'Protocol')
        os.makedirs(folder)
        header = os.path.join(folder, 'Test.h')
        io.open(header, 'w', encoding='utf-8').write(PROTOCOL_HEADER % (second_kind,
                                                                       second_kind))
        ANALYZE.guid_protocol_name['gTestProtocolGuid'] = 'TEST_PROTOCOL'
        ANALYZE.guid_header['gTestProtocolGuid'] = header
        ANALYZE._header_source.pop(header, None)
        before_includes = set(ANALYZE.all_includes)
        built = ANALYZE.sort_data({}, {'Protocols': [(member, 'gTestProtocolGuid')]},
                                  False, {})
        gained = set(ANALYZE.all_includes) - before_includes
        ANALYZE.all_includes.difference_update(gained)
        return {name: blocks[0] for name, blocks in built.items() if blocks}, gained
    finally:
        ANALYZE.guid_protocol_name.pop('gTestProtocolGuid', None)
        ANALYZE.guid_header.pop('gTestProtocolGuid', None)
        import shutil
        shutil.rmtree(work, ignore_errors=True)


# The protocol as the types database holds it: Mem and Io, and no member called Read or
# PciRead. Without it protocol_members() answers nothing, every name passes the struct
# check, and the assertions about a derived name would pass for the wrong reason.
PROTOCOL_TYPES = {
    'EFI_CPU_IO2_PROTOCOL': COMMON.TypeInfo(
        'EFI_CPU_IO2_PROTOCOL',
        [COMMON.FieldInfo('Mem', 'EFI_CPU_IO_PROTOCOL_ACCESS'),
         COMMON.FieldInfo('Io', 'EFI_CPU_IO_PROTOCOL_ACCESS')], ''),
}


def collected(param_name, arg_type):
    """The recorded constants collect_known_constants keeps for one argument.

    Three call sites, because its own second pass drops an argument with fewer than three
    recorded values, and everything but the parameter name and its type is held equal --
    so an assertion about one of these is about the attribute it names.
    """
    sites = []
    for value in ('0x20', '0x40', '0x70'):
        args = {
            'Arg_0': argument('EFI_CPU_IO2_PROTOCOL *', 'This', variable='__PROTOCOL__',
                              usage='gEfiCpuIo2ProtocolGuid'),
            'Arg_1': argument(arg_type, param_name, variable='__CONSTANT_UNKNOWN__',
                              usage=value),
        }
        sites.append(COMMON.FunctionBlock(args, 'Read', 'protocol', [], 'EFI_STATUS'))
    pre = ANALYZE.initialize_data({'Read': sites[0]})
    ANALYZE.collect_known_constants({'Read': sites}, pre, {}, {}, {}, {})
    return [entry.usage for entry in (pre['Read'].arguments.get('Arg_1') or [])]


def harness_for(name, args, paths=None, guid='gEfiCpuIo2ProtocolGuid',
                protocol='EFI_CPU_IO2_PROTOCOL'):
    """The whole emitted harness for one member, as harness_generator writes it."""
    block = COMMON.FunctionBlock(args, name, 'protocol', [], 'EFI_STATUS')
    block.protocol_type = f'{protocol} *'
    block.protocol_guid = guid
    if paths:
        block.member_paths = paths
    return TEMPLATE.harness_generator({name: block}, {name: block}, PROTOCOL_TYPES, {},
                                      {},
                                      {'EFI_CPU_IO_PROTOCOL_WIDTH': COMMON.EnumDef()})


def main():
    print('the generator still has the pieces these assertions go through')
    missing = [name for name, value in (('is_address_name', IS_ADDRESS_NAME),
                                        ('ADDRESS_NAME_SUFFIXES', ADDRESS_SUFFIXES),
                                        ('declaration_key', DECLARATION_KEY),
                                        ('declaration_for', DECLARATION_FOR),
                                        ('declarations_named', DECLARATIONS_NAMED),
                                        ('anon_struct_body', ANON_STRUCT_BODY))
               if value is None]
    check('is_address_name, declaration_for and anon_struct_body are all there',
          not missing,
          f'gone: {", ".join(missing)} -- the generator calls them too, so what follows '
          f'would be a traceback rather than a result')
    if missing:
        print(f'\n{PASSED} passed, {FAILED} failed')
        return 1

    analyze_src = gen_source(os.path.join('data_analysis', 'analyze.py'))
    template_src = gen_source(os.path.join('uefi_harness', 'harnesses_template.py'))
    utils_src = gen_source(os.path.join('common', 'utils.py'))

    print('\na declaration belongs to the protocol whose This it takes')
    both = loaded(FILE_READ, CPUIO_READ)
    check('two protocols\' Read both survive the load',
          len(both) == 2,
          f'{sorted(both)} -- keyed by the bare name, one entry per name survived and it '
          f'was whichever file was read last')
    check('and the key names the protocol, not just the member',
          sorted(both) == [('EFICPUIO2PROTOCOL', 'Read'), ('EFIFILEPROTOCOL', 'Read')],
          f'{sorted(both)}')
    picked = DECLARATION_FOR(both, 'Read', 'EFI_CPU_IO2_PROTOCOL')
    check('EFI_CPU_IO2_PROTOCOL.Read resolves to its own five-parameter declaration',
          picked is not None and len(picked.arguments) == 5,
          f'{None if picked is None else sorted(picked.arguments)}')
    # firness records a declaration's parameter NAME in `variable`, not in param_name --
    # param_name is filled in later from the protocol's own typedef -- so that is the
    # field a wrong declaration moves, together with arg_type.
    check('...with Arg_2 declared UINT64 Address, not void * Buffer',
          picked is not None
          and (picked.arguments['Arg_2'][0].arg_type,
               picked.arguments['Arg_2'][0].variable) == ('UINT64', 'Address'),
          f'{None if picked is None else (picked.arguments["Arg_2"][0].arg_type, picked.arguments["Arg_2"][0].variable)}')
    displaced = DECLARATION_FOR(both, 'Read', 'EFI_FILE_PROTOCOL')
    check('...where the declaration that used to win says void * Buffer there',
          displaced is not None
          and (displaced.arguments['Arg_2'][0].arg_type,
               displaced.arguments['Arg_2'][0].variable) == ('void *', 'Buffer'),
          f'{None if displaced is None else (displaced.arguments["Arg_2"][0].arg_type, displaced.arguments["Arg_2"][0].variable)} '
          f'-- the two differ at this position, which is what made the collision matter')
    other = DECLARATION_FOR(both, 'Read', 'EFI_FILE_PROTOCOL')
    check('and EFI_FILE_PROTOCOL.Read still resolves to its own',
          other is not None and len(other.arguments) == 3
          and other.file.endswith('VirtioFsDxe.h'),
          f'{None if other is None else (len(other.arguments), other.file)} -- the fix '
          f'must separate the two, not refuse both')
    only_file = loaded(FILE_READ)
    check('a request whose only candidate is another protocol\'s gets nothing',
          DECLARATION_FOR(only_file, 'Read', 'EFI_CPU_IO2_PROTOCOL') is None,
          'this is the sweep\'s own case: EfiCpuIo2 records only VirtioFsDxe\'s Read, '
          'and a wrong declaration is worse than none because the member is otherwise '
          'built from the protocol typedef, which is authoritative')
    check('edk2\'s tag spelling of the struct still matches the protocol',
          DECLARATION_FOR(loaded(TAGGED_READ), 'Read', 'EFI_CPU_IO2_PROTOCOL') is not None,
          'a call site records "struct _EFI_CPU_IO2_PROTOCOL *" as often as the typedef')
    free = loaded(FREE)
    check('a free function with one declaration still resolves with no protocol',
          DECLARATION_FOR(free, 'CreateBdsEvent') is not None)
    check('two identical declarations of it resolve rather than cancel out',
          DECLARATION_FOR(loaded(FREE, FREE_AGAIN), 'CreateBdsEvent') is not None,
          'the same declaration is recorded once per header that carries it')
    check('two that disagree about the parameters resolve to nothing',
          DECLARATION_FOR(loaded(FREE, FREE_CONFLICT), 'CreateBdsEvent') is None,
          'answering with one of them is the guess this whole key exists to stop')
    check('declarations_named finds a name whatever protocol declared it',
          len(DECLARATIONS_NAMED(both, 'Read')) == 2
          and DECLARATIONS_NAMED(both, 'Reset') == [],
          'the "declared in no includable header" filter asks this, and a tuple key '
          'makes `name not in function_declares` true for everything')
    loader = code(body(analyze_src, 'def load_function_declares'))
    check('the loader keys by declaration_key and no longer by the bare name',
          'declaration_key(function)' in loader
          and 'function_dict[function.function] = function' not in loader,
          f'the collapse was one assignment, inside this loader and no other:\n{loader}')
    check('the type consumer asks declaration_for with the requested protocol',
          'declaration_for(' in code(body(analyze_src, 'def load_data'))
          and 'function_decl.get(function)' not in code(body(analyze_src,
                                                             'def load_data')),
          'edk2_typedef_for settles UINT16 against CHAR16 on the declared type, so a '
          'colliding declaration decided it')
    check('and the undeclarable filter asks declarations_named',
          'declarations_named(function_declares, name)' in code(analyze_src)
          and 'name not in function_declares' not in code(analyze_src))

    print('\nthe second anonymous typedef in a header resolves to its own body')
    second = ANALYZE.protocol_struct_body(TWO_ANON, 'SECOND_ACCESS')
    first = ANALYZE.protocol_struct_body(TWO_ANON, 'FIRST_ACCESS')
    check('the second struct\'s body holds its own fields',
          second is not None and 'SECOND_KIND' in second,
          f'{second!r}')
    check('...and nothing from the struct declared above it',
          second is not None and 'FIRST_KIND' not in second,
          f'{second!r} -- a non-greedy body is still leftmost-first, so the opening '
          f'brace came from the first typedef and the blob spanned both')
    check('the first struct still resolves to its own body',
          first is not None and 'FIRST_KIND' in first and 'SECOND_KIND' not in first,
          f'{first!r} -- the fixtures differ in which one is asked for and in nothing '
          f'else, so this is what makes the assertion above about the second')
    check('the member of the second struct is typed from the second struct',
          ANALYZE.protocol_member_kind(TWO_ANON, 'SECOND_ACCESS', 'Read') == 'SECOND_KIND',
          f'{ANALYZE.protocol_member_kind(TWO_ANON, "SECOND_ACCESS", "Read")}')
    nested = ANALYZE.protocol_struct_body(NESTED_ANON, 'OUTER_ACCESS')
    check('a brace nested inside a body does not end it',
          nested is not None and 'OUTER_KIND' in nested,
          f'{nested!r} -- the scan counts braces rather than stopping at the first "\\n}}"')
    check('a closing name carrying edk2\'s tag prefix still resolves',
          (ANALYZE.protocol_struct_body(TAGGED_ANON, 'TAGGED_ACCESS') or '')
          .find('TAG_KIND') >= 0,
          f'{ANALYZE.protocol_struct_body(TAGGED_ANON, "TAGGED_ACCESS")!r}')
    check('a struct the header does not declare answers nothing',
          ANALYZE.protocol_struct_body(TWO_ANON, 'THIRD_ACCESS') is None)
    check('a struct named at its opening is unchanged',
          (ANALYZE.protocol_struct_body('struct _EFI_X_PROTOCOL {\n  K Read;\n}',
                                        'EFI_X_PROTOCOL') or '').find('K Read') >= 0)
    check('the end-anchored pattern is gone from the fallback',
          'anon_struct_body(source, protocol_name)' in code(
              body(analyze_src, 'def protocol_struct_body'))
          and r'(.*?)\n\}\s*\w*?' not in code(analyze_src),
          'the regular expression itself was the defect')

    print('\nand a member reached by two signatures is harnessed twice, not merged')
    check('a member signature can be asked for by the typedef that declares it',
          'kind: str = ""' in code(body(analyze_src, 'def protocol_member_params')),
          'without it the second signature cannot be read at all')
    split = code(body(analyze_src, 'def sort_data'))
    check('the synthesis groups a member\'s paths by their function-pointer typedef',
          'by_kind' in split and 'protocol_member_signature(header, protocol_name, name, kind)' in split,
          'one block per signature is what puts the second access path in the harness')
    check('...and the derived block is named after the sub-structure that reaches it',
          "harness_name = f'{lead}{name}'" in split,
          'the harness function is named after the block, so the name has to differ')
    two, gained = synthesised()
    check('a member with two signatures is built as two harnesses',
          sorted(two) == ['CfgRead', 'Read'],
          f'{sorted(two)} -- one block means the other access path is never fuzzed')
    check('...each carrying only the paths of its own signature',
          [p for p, _k in getattr(two.get('Read'), 'member_paths', [])] == ['Mem.Read']
          and [p for p, _k in getattr(two.get('CfgRead'), 'member_paths', [])] == ['Cfg.Read'],
          f'{[(n, getattr(b, "member_paths", None)) for n, b in sorted(two.items())]}')
    check('...and each the parameter list its own typedef declares',
          two.get('Read') is not None and two.get('CfgRead') is not None
          and len(two['Read'].arguments) == 3 and len(two['CfgRead'].arguments) == 2,
          f'{[(n, sorted(b.arguments)) for n, b in sorted(two.items())]} -- three '
          f'against two is why one switch over both cannot be written')
    one, _gained = synthesised(second_kind='TEST_MEM')
    check('paths that really do share a signature still share one harness',
          sorted(one) == ['Read']
          and [p for p, _k in getattr(one.get('Read'), 'member_paths', [])]
          == ['Mem.Read', 'Cfg.Read'],
          f'{[(n, getattr(b, "member_paths", None)) for n, b in sorted(one.items())]} -- '
          f'the two headers differ in the second typedef and in nothing else, so '
          f'without this the split assertion could be passing for any reason')
    check('a header a member was built from is added to the includes',
          any(path.endswith('Test.h') for path in gained), f'{gained}')
    absent, absent_gained = synthesised(member='Flush')
    check('...and a member the header does not declare adds nothing',
          absent_gained == set() and 'Flush' not in absent,
          f'{absent_gained} -- adding it per requested member put headers into every '
          f'campaign\'s include list, inf and dsc')

    print('\nan address-shaped argument is not an offset into the call\'s buffer')
    for name in ('Address', 'BaseAddress', 'SrcAddr', 'HpcPciAddress'):
        check(f'{name} names an address', bool(IS_ADDRESS_NAME(name)))
    for name in ('BufferSize', 'Count', 'Width', 'AddressSize', ''):
        check(f'{name or "an empty name"} does not', not IS_ADDRESS_NAME(name))
    _declared, filled = emit(cpu_io())
    check('the address gets no bound from the buffer beside it',
          bound_of(filled, 'Arg_2') is None,
          f'bounded by {bound_of(filled, "Arg_2")!r} -- 4096 is the legacy I/O page')
    check('...and the emitted C says that is deliberate',
          any('Address is a bus address' in line for line in filled),
          'an arm that emits nothing is indistinguishable from an arm never reached, '
          'and this file is the only evidence a campaign leaves behind')
    renamed = emit(cpu_io(address_name='Offset'))[1]
    check('the same argument called Offset is still bounded by the buffer',
          bound_of(renamed, 'Arg_2') == '4096',
          f'{bound_of(renamed, "Arg_2")!r} -- the two fixtures differ in the parameter '
          f'name and in nothing else, so without this the assertion above is vacuous')
    check('the count in the same call keeps its element bound',
          bound_of(filled, 'Arg_3') == '(4096 / (1 << (Fuzz_Arg_1 & 0x03)))',
          f'{bound_of(filled, "Arg_3")!r} -- the address arm must not swallow the count')
    # Through the tracked list declare_var builds, so takes_raw_buffer() says yes and the
    # blanket arm is live: with an empty list nothing would be bounded either way and the
    # assertion below would be vacuous.
    def pointer_clamp_for(size_name):
        args = by_pointer(size_name)
        tracked = []
        for key, entry in args.items():
            TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False, False,
                                 False, 0)
        return TEMPLATE.pointer_size_clamp(f'*Fuzz_Arg_1', size_name, args, tracked,
                                           'UINTN *', 'Fuzz', '', 'Arg_1')

    clamp_address = pointer_clamp_for('BaseAddress')
    clamp_size = pointer_clamp_for('BufferSize')
    fuzzable = code(body(template_src, 'def fuzzable_args'))
    pointer_clamp = code(body(template_src, 'def pointer_size_clamp'))
    check('a size handed over by pointer is still bounded',
          bool(clamp_size), f'{clamp_size}')
    check('and an address handed over by pointer is not',
          not clamp_address,
          f'{clamp_address} -- the by-pointer reader is a second copy of the same arms '
          f'and has been the unbounded one twice now')
    check('...because its only blanket arm asks whether the name says "size"',
          'elif names_a_size(own_name) and (paired or takes_raw_buffer(arg_type_list)):'
          in code(pointer_clamp),
          'the by-value reader bounds an integer merely because the call carries a '
          'buffer; this one does not, and that gate is the whole reason an address '
          'handed over by pointer needs no arm of its own')
    check('the address arm is tested before the ones that reach for the buffer',
          before(fuzzable, 'is_address_name(own_name)',
                 'takes_raw_buffer(arg_type_list)'),
          'the order is what keeps the blanket arm off an address')
    check('...and after the dimension arm, which a Width must still reach',
          before(fuzzable, 'is_dimension_name(own_name)', 'is_address_name(own_name)'))
    check('the suffix table is shared rather than copied into the template',
          'ADDRESS_NAME_SUFFIXES' in code(utils_src)
          and 'ADDRESS_NAME_SUFFIXES' not in code(template_src),
          'the analysis asks the same question of a recorded constant, and a table in '
          'the template would make the analyser import the harness writer')

    print('\na bus address is not driven from a recorded hardware constant either')
    constants = code(body(analyze_src, 'def collect_known_constants'))
    check('an address-shaped scalar is not offered a recorded constant',
          before(constants, 'is_address_name(argument[0].param_name)',
                 '"__CONSTANT" in argument[0].variable and "__CONSTANT_"'),
          'EfiCpuIo2\'s Address came back __CONSTANT_UNKNOWN__ with an arm assigning 0, '
          'and the accessor walks upward one stride per Count, so that arm alone swept '
          'ports 0x0000-0x1000 whatever bound the address itself had')
    check('...only a scalar, because an address by pointer is a struct the callee fills',
          'argument[0].pointer_count == 0' in constants,
          'EFI_SIMPLE_NETWORK.Receive takes EFI_MAC_ADDRESS *SrcAddr')
    check('an address scalar really is left with no recorded constant',
          collected('Address', 'UINT64') == [],
          f'{collected("Address", "UINT64")}')
    check('...while the same argument called Offset keeps its constants',
          collected('Offset', 'UINT64') == ['0x20', '0x40', '0x70'],
          f'{collected("Offset", "UINT64")} -- the two differ in the parameter name and '
          f'in nothing else')
    check('...and an address by pointer keeps its constants too',
          collected('SrcAddr', 'EFI_MAC_ADDRESS *') == ['0x20', '0x40', '0x70'],
          f'{collected("SrcAddr", "EFI_MAC_ADDRESS *")}')

    print('\nthe Io access path stays in the member switch')
    switch = harness_for('Read', cpu_io(),
                         paths=[('Mem.Read', 'EFI_CPU_IO_PROTOCOL_IO_MEM'),
                                ('Io.Read', 'EFI_CPU_IO_PROTOCOL_IO_MEM')])
    check('both Mem.Read and Io.Read are reachable from the harness',
          any('ProtocolVariable->Mem.Read' in line for line in switch)
          and any('ProtocolVariable->Io.Read' in line for line in switch),
          'dropping the Io arms was the instruction this refuses: CpuIo2Dxe.c:548 is '
          'inside CpuIoServiceWrite, which mCpuIo2 reaches only through Io.Write')
    check('and the harness locates its protocol by GUID',
          any('LocateProtocol(&gEfiCpuIo2ProtocolGuid' in line for line in switch),
          'a block harnessed under a derived name carries the guid on itself, and '
          'without reading it the harness emitted "LocateProtocol(&, NULL, ...)"')
    # Arg_0 carries no guid here: the guid is stamped on by matching the REQUEST file's
    # member name, and a block harnessed under a derived name never matches one.
    unstamped = dict(cpu_io(),
                     Arg_0=argument('EFI_CPU_IO2_PROTOCOL *', 'This',
                                    variable='__PROTOCOL__'))
    derived = harness_for('PciRead', unstamped,
                          paths=[('Pci.Read', 'EFI_PCI_IO_PROTOCOL_CONFIG')])
    check('a single-path block calls straight through that path',
          any('ProtocolVariable->Pci.Read(' in line for line in derived)
          and not any(re.match(r'\s*(Status = )?PciRead\(', line) for line in derived),
          f'{[l for l in derived if "PciRead" in l or "Pci.Read" in l]} -- a bare '
          f'PciRead(...) is an implicit declaration, and the types database says '
          f'PciRead is not a member of this struct')
    check('...and finds its guid on the block when no parameter carries one',
          any('LocateProtocol(&gEfiCpuIo2ProtocolGuid' in line for line in derived),
          f'{[l for l in derived if "LocateProtocol" in l]} -- "LocateProtocol(&, NULL" '
          f'is not C')
    check('a width the harness declares no variable for is not named in a bound',
          TEMPLATE.io_width_arg(cpu_io()) == 'Arg_1'
          and TEMPLATE.io_width_arg(
              dict(cpu_io(), Arg_1=argument('EFI_PCI_IO_PROTOCOL_WIDTH', 'Width',
                                            arg_dir='OPTIONAL',
                                            variable='__OPTIONAL__'))) == '',
          'an argument the analysis collected nothing for is spelled into the call as '
          '(EFI_PCI_IO_PROTOCOL_WIDTH){0}, and naming it emitted "Read_Arg_1 undeclared"')
    # On the RAW source, not code(): the thing asserted here IS a comment, and the claim
    # it used to make is the kind a reader acts on.
    raw_template = gen_source(os.path.join('uefi_harness', 'harnesses_template.py'))
    check('the element-count table no longer claims it addressed the #DE',
          'and a #DE: the top of the severity table' not in raw_template
          and 'It is still open' in raw_template,
          'the comment listed a divide error among the reports its fix accounts for; '
          'that campaign\'s crashes.csv has no divide error in it at all')

    if os.path.isfile(PCIIO_H):
        print('\nand on MdePkg/Include/Protocol/PciIo.h itself')
        source = io.open(PCIIO_H, encoding='utf-8', errors='ignore').read()
        check('Pci.Read is typed EFI_PCI_IO_PROTOCOL_CONFIG',
              ANALYZE.protocol_member_kind(source, 'EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS',
                                           'Read') == 'EFI_PCI_IO_PROTOCOL_CONFIG',
              f'{ANALYZE.protocol_member_kind(source, "EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS", "Read")}')
        paths = ANALYZE.protocol_member_access(source, 'EFI_PCI_IO_PROTOCOL', 'Read')
        check('the protocol reaches Read three ways, by two signatures',
              [p for p, _k in paths] == ['Mem.Read', 'Io.Read', 'Pci.Read']
              and len({k for _p, k in paths}) == 2,
              f'{paths}')
        config = ANALYZE.protocol_member_signature(PCIIO_H, 'EFI_PCI_IO_PROTOCOL', 'Read',
                                                   'EFI_PCI_IO_PROTOCOL_CONFIG')
        io_mem = ANALYZE.protocol_member_signature(PCIIO_H, 'EFI_PCI_IO_PROTOCOL', 'Read',
                                                   'EFI_PCI_IO_PROTOCOL_IO_MEM')
        check('the two signatures really are different, so one switch cannot serve both',
              config is not None and io_mem is not None
              and len(config) == 5 and len(io_mem) == 6
              and [t for _k, t, _d, _n in config][2] == 'UINT32'
              and [t for _k, t, _d, _n in io_mem][3] == 'UINT64',
              f'config={config}\n         io_mem={io_mem}')
    else:
        print(f'\n  [skip] {PCIIO_H} is not on this host')

    if os.path.isfile(CPUIO_C):
        source = io.open(CPUIO_C, encoding='utf-8', errors='ignore').read()
        instance = re.search(r'mCpuIo2\s*=\s*\{(.*?)\n\};', source, re.S)
        members = re.findall(r'\b(Cpu\w+Service\w+)\b', instance.group(1) if instance else '')
        check('CpuIoServiceWrite is reachable only through the Io member',
              members == ['CpuMemoryServiceRead', 'CpuMemoryServiceWrite',
                          'CpuIoServiceRead', 'CpuIoServiceWrite'],
              f'{members} -- the Io pair is the second brace of mCpuIo2, so a harness '
              f'without the Io arms cannot reach CpuIo2Dxe.c:548 at all')
    else:
        print(f'  [skip] {CPUIO_C} is not on this host')

    if os.path.isdir(SWEEP):
        print('\nand on what the sweeps recorded')
        declares = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'functions.json')
        if os.path.isfile(declares):
            entries = json.load(io.open(declares, encoding='utf-8')) or []
            reads = [e for e in entries if e.get('Function') == 'Read']
            check('EfiCpuIo2 recorded only another protocol\'s Read',
                  bool(reads)
                  and all(e['File'].endswith('VirtioFsDxe.h') for e in reads)
                  and all(len(e['Parameters']) == 3 for e in reads),
                  f'{[(e.get("File"), len(e.get("Parameters") or {})) for e in reads]}')
            loaded_real = ANALYZE.load_function_declares(declares)
            check('...and it no longer answers for EFI_CPU_IO2_PROTOCOL',
                  DECLARATION_FOR(loaded_real, 'Read', 'EFI_CPU_IO2_PROTOCOL') is None
                  and DECLARATION_FOR(loaded_real, 'Read',
                                      'EFI_FILE_PROTOCOL') is not None)
        crashes = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'crashes.csv')
        if os.path.isfile(crashes):
            rows = io.open(crashes, encoding='utf-8', errors='ignore').read()
            check('the Io path is the only route to one of the five asan sites',
                  'CpuIoServiceWrite' in rows and 'CpuIo2Dxe.c,548' in rows,
                  'the claim that dropping Io.* costs no detection is what this refutes')
            check('and no campaign in that sweep recorded a divide error',
                  not any('divide' in io.open(os.path.join(SWEEP, 'campaigns', name,
                                                           'crashes.csv'),
                                              encoding='utf-8',
                                              errors='ignore').read().lower()
                          for name in sorted(os.listdir(os.path.join(SWEEP, 'campaigns')))
                          if os.path.isfile(os.path.join(SWEEP, 'campaigns', name,
                                                         'crashes.csv'))),
                  'the element-count table claimed the #DE among its measured reports')
        shipped = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'Firness',
                               'FirnessHarnesses.c')
        if os.path.isfile(shipped):
            text = io.open(shipped, encoding='utf-8', errors='ignore').read()
            check('the harness that wedged the guest bounded its address to 4096',
                  'Read_Arg_2 = Read_Arg_2 % (4096 + 1);' in text
                  and 'ProtocolVariable->Io.Read' in text,
                  'if this is gone the campaign was regenerated and this file is no '
                  'longer evidence of anything')
    else:
        print(f'\n  [skip] {SWEEP} is not on this host')

    if os.path.isdir(SMI_SWEEP):
        check('the SMI sweep\'s declarations load under the new key too',
              all(isinstance(key, tuple) and len(key) == 2
                  for name in sorted(os.listdir(os.path.join(SMI_SWEEP, 'campaigns')))
                  for key in ANALYZE.load_function_declares(
                      os.path.join(SMI_SWEEP, 'campaigns', name, 'functions.json'))),
              'the SMI generator reads the same file')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
