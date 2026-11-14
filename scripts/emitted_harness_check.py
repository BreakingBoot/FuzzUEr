#!/usr/bin/env python3
"""Assert the harness declares the type it fuzzes, bounds every size, and is comparable.

Six defects in the generator, each measured by regenerating all 142 cached analyses of
EVAL-1 runs 43454245046 (138 campaigns) and 43452927684 (4, SMI) before and after.

The type a generator argument is declared with. A call site records the type of the
EXPRESSION it passed, so a wide string literal arrives as "unsigned short *". load_data
puts the EDK2 name back for the functions under test; load_generators did not, and a
generator's arguments are declared from the type they carry. FileExplorerLib's ChooseFile
takes CHAR16 *FileType, every recorded call site passes L".efi", and the harness declared

    unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short))

It keeps its star, so it compiles and nothing fails: is_string_pointer says no to
"unsigned short *", so a string the callee walks to its terminator gets two bytes without
one. That is the silent form of the defect that stopped EdkiiVariableLock building at all,
and it was 20 declarations across 8 campaigns -- EfiDevicePathUtilities, EfiAtaPassThru,
EfiExtScsiPassThru, EfiLoadFile, EfiLoadFile2, EfiPciHotPlugInit, EfiRamDisk and the SMI
run's EfiDevicePathUtilities.

The bound on an OUT size. generate_outputs fills the pointee of an OUT argument from the
input and clamped nothing, so an OUT *BufferSize arrived as 2^64-1 against a 4096 byte
buffer and the callee was told to fill memory that does not exist. Nothing downstream
clamps it: the reallocation pass takes by-value sizes only. 34 arguments over 21
campaigns, every one of them a size or a count by name, and the bound is now the one the
input section uses for the same shape -- one function, three callers.

A size paired with itself. buffer_for_size skips an argument with no pointer, which the
size itself has when it is handed over by pointer, and its own name begins with its own
stem: "ADDRESSSIZE".startswith("ADDRESS"). 25 arguments paired with themselves, and the
answer hid the real pair in 8 of them -- including SNP's Statistics, where *StatisticsSize
was bounded at 4096 against a table allocated as sizeof (EFI_NETWORK_STATISTICS). That is
the exact 4KB overflow the StatisticsSize/StatisticsTable fallback was added to close,
still open because the self-match came first.

A raw buffer's contents clamped as a length. The blanket arm reads "the call takes a raw
buffer, so its integers are sizes and offsets into it", which is true of the integers and
not of the buffer -- and a VOID * buffer is declared UINTN *, so by the time that arm runs
the two have the same shape. EfiCpuIo2's Read_Arg_4 IS the VOID *Buffer, and the harness
emitted "*Read_Arg_4 = *Read_Arg_4 % (4096 + 1)" against the first UINTN of its contents.
183 lines over 163 arguments and 67 campaigns, every one a buffer or an identifier by
name, none of them a size.

FirnessHarnesses.inf run to run. [LibraryClasses] came from update_libs, which iterates a
SET of strings, and the two guid sections from classify_guids' sets, so two runs of
identical code over identical inputs emitted the same lines in a different order: 20 lines
moved between PYTHONHASHSEED=1 and 2 on EfiBlockIo alone. The include list was fixed this
way already (analyze_smi: "sorted, not list") and the DSC sorts; the INF was missed. The
FILE_GUID and PLATFORM_GUID uuid4s are deliberate and still differ.

A mutable default. TypeInfo's `fields: List[FieldInfo] = []` is one list, created once and
shared by every default-constructed instance -- three places build one as a `.get`
fallback to read "no fields" from. Nothing appends to .fields, so it never fired;
TypeMap.__missing__ passes an explicit [] for the same reason, which is a workaround for
that line rather than a fix of it.

Run: python3 scripts/emitted_harness_check.py
"""

import io
import json
import os
import re
import shutil
import sys
import tempfile
import types as pytypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

# The sweep the measurements above come from, for the corroboration at the end. A runner
# does not have it.
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

    Every comment in the code asserted on here quotes the defect it fixes: the raw C
    spelling, the 4096 clamp on a buffer's contents, the word sorted, the name of the
    function that must be asked. An assertion made against the raw text finds the
    explanation rather than the statement, and passes with the statement deleted.
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


def generator():
    """The generator's own modules, with the one import a runner does not have stubbed.

    analyze.py pulls fuzzywuzzy at module scope and it is not installed on a runner. It
    scores how close a generator function's NAME is to the function under test, which
    decides nothing asserted here -- the fixtures below declare no generators for any
    function.
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
    from data_analysis import analyze
    import uefi_harness.harnesses_template as template
    import uefi_harness.inf_template as inf_template
    return common_types, analyze, template, inf_template


COMMON, ANALYZE, TEMPLATE, INF = generator()

# Fetched by name rather than imported, so that REMOVING one is a failing assertion rather
# than an ImportError at the top of the file. A check that dies before its first line of
# output has not caught anything, and nothing reading exit codes can tell that from a
# check that ran.
CLAMP = getattr(TEMPLATE, 'pointer_size_clamp', None)
NAMES_A_SIZE = getattr(TEMPLATE, 'names_a_size', None)
BASE_TYPE_OF = getattr(TEMPLATE, 'base_type_of', None)


def argument(arg_type, param_name='', arg_dir='IN', variable='__FUZZABLE__',
             data_type=''):
    return [COMMON.Argument(arg_dir, arg_type, '', data_type, '', variable,
                            param_name=param_name)]


def emit(args, random=False):
    """Declare, fill, declare the outputs and call, as function_body does in that order.

    Returns (declarations, input fills, output section, call). The span and the array-ness
    are taken from the same functions the generator takes them from, and the IN exclusions
    are the ones generate_inputs applies, so a fixture cannot pass by being told something
    the generator is not.
    """
    block = COMMON.FunctionBlock(args, 'Fuzz', 'protocol', [], 'EFI_STATUS')
    span = TEMPLATE.dimension_span(args) if TEMPLATE.has_dimension_arg(args) else 0
    tracked = []
    declared = []
    for key, entry in args.items():
        if 'IN' not in entry[0].arg_dir:
            continue
        declared += TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False,
                                         random, TEMPLATE.walks_as_array(args, key), span)
    filled = []
    for key, entry in args.items():
        if 'IN' not in entry[0].arg_dir:
            continue
        filled += TEMPLATE.fuzzable_args('Fuzz', key, False, tracked, args, '')
    outputs = TEMPLATE.generate_outputs('Fuzz', args, tracked, False, '')
    called = TEMPLATE.call_function('Fuzz', block, {'Fuzz': block}, 'Protocol', tracked,
                                    False, '')
    return declared, filled, outputs, called


def bound_of(lines, name):
    """The right-hand side of the clamp on `name`, or None if it is not clamped."""
    for line in lines:
        found = re.search(rf'^\*?Fuzz_{name} = \*?Fuzz_{name} % \((.*) \+ 1\);$',
                          line.strip())
        if found:
            return found.group(1)
    return None


def allocation_of(lines, name):
    for line in lines:
        found = re.search(rf'Fuzz_{name} = \([^)]*\)AllocateZeroPool\((.*)\);$',
                          line.strip())
        if found:
            return found.group(1)
    return None


def extent_of(lines, name):
    for line in lines:
        found = re.search(rf'FirnessUntrusted\(Fuzz_{name}, (.*)\);$', line.strip())
        if found:
            return found.group(1)
    return None


def inf_lines(libraries, driver_guids=(), protocol_guids=(), timing='application'):
    return INF.gen_firness_inf('deadbeef-0000-0000-0000-000000000000', driver_guids,
                               protocol_guids, libraries, [], [], timing=timing,
                               depex_protocols=[])


def section(lines, header):
    """The entries of one section of an inf."""
    out = []
    inside = False
    for line in lines:
        if line.startswith('['):
            inside = line.strip() == header
            continue
        if inside and line.strip():
            out.append(line.strip())
    return out


def generated(recorded, declared_type, data_type=''):
    """What load_generators leaves on a generator argument, from one recorded call site.

    recorded is the arg_type the analyser wrote down for Arg_1 and declared_type is what
    the generator's own declaration says. Everything else is held equal between the cases
    below, so an assertion is about the one attribute it names.
    """
    work = tempfile.mkdtemp(prefix='emitted-harness-')
    try:
        site = {
            'Function': 'ChooseFile', 'Service': 'library', 'Include': [],
            'ReturnType': 'EFI_STATUS',
            'Arguments': {
                'Arg_0': {'arg_dir': 'IN', 'arg_type': 'EFI_DEVICE_PATH_PROTOCOL *',
                          'assignment': '', 'data_type': '', 'usage': '',
                          'variable': '__PROTOCOL__'},
                'Arg_1': {'arg_dir': 'IN', 'arg_type': recorded, 'assignment': 'L".efi"',
                          'data_type': data_type, 'usage': 'L".efi"',
                          'variable': '__CONSTANT_STRING__'}}}
        path = os.path.join(work, 'generator-database.json')
        io.open(path, 'w', encoding='utf-8').write(json.dumps([site, site]))
        declarations = {}
        if declared_type:
            declarations['ChooseFile'] = COMMON.Function(
                'ChooseFile',
                {'Arg_0': [COMMON.Argument('IN', 'EFI_DEVICE_PATH_PROTOCOL *', '', '',
                                           '', '')],
                 'Arg_1': [COMMON.Argument('IN', declared_type, '', '', '', 'FileType')]},
                'EFI_STATUS', 'library', [])
        loaded = ANALYZE.load_generators(path, {}, declarations)
        return loaded['ChooseFile'][0].arguments['Arg_1'][0]
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------------------
# The fixtures. Each pair differs in ONE attribute from the case it is compared with,
# because an assertion about a fixture that differs in two says nothing about either.

def cpu_io(buffer_name='Buffer'):
    """EFI_CPU_IO_PROTOCOL_IO_MEM: (This, Width, Address, Count, Buffer)."""
    return {
        'Arg_0': argument('EFI_CPU_IO2_PROTOCOL *', 'This', variable='__PROTOCOL__'),
        'Arg_1': argument('EFI_CPU_IO_PROTOCOL_WIDTH', 'Width', variable='__ENUM_ARG__',
                          data_type='int'),
        'Arg_2': argument('UINT64', 'Address'),
        'Arg_3': argument('UINTN', 'Count'),
        'Arg_4': argument('VOID *', buffer_name, arg_dir='IN OUT'),
    }


def statistics(size_dir='IN OUT'):
    """EFI_SIMPLE_NETWORK.Statistics: the size is spelled before the table it sizes."""
    return {
        'Arg_0': argument('EFI_SIMPLE_NETWORK_PROTOCOL *', 'This',
                          variable='__PROTOCOL__'),
        'Arg_1': argument('BOOLEAN', 'Reset'),
        'Arg_2': argument('UINTN *', 'StatisticsSize', arg_dir=size_dir),
        'Arg_3': argument('EFI_NETWORK_STATISTICS *', 'StatisticsTable', arg_dir='OUT'),
    }


def main():
    print('the generator still has the three functions these assertions go through')
    # Reported, then returned on. Deleting one of these does not make an assertion false
    # further down -- it makes generate_outputs raise NameError, and a check that dies
    # inside the code it is testing has reported nothing. Nothing reading exit codes can
    # tell that from a check that ran, so say it here and stop.
    missing = [name for name, value in (('pointer_size_clamp', CLAMP),
                                        ('names_a_size', NAMES_A_SIZE),
                                        ('base_type_of', BASE_TYPE_OF))
               if value is None]
    check('pointer_size_clamp, names_a_size and base_type_of are all there',
          not missing,
          f'gone: {", ".join(missing)} -- the generator calls them too, so what follows '
          f'would be a traceback rather than a result')
    if missing:
        print(f'\n{PASSED} passed, {FAILED} failed')
        return 1

    print('\nthe inf is the same file twice, whatever order the mapping arrives in')
    # update_libs answers a dict built by iterating a set, so the keys arrive in an order
    # that moves between runs. Two orders of ONE set of classes, nothing else different.
    classes = {'UefiLib': 'a.inf', 'BaseLib': 'b.inf', 'DebugLib': 'c.inf',
               'PrintLib': 'd.inf', 'HobLib': 'e.inf'}
    forward = {name: classes[name] for name in sorted(classes)}
    backward = {name: classes[name] for name in sorted(classes, reverse=True)}
    check('[LibraryClasses] is emitted sorted',
          section(inf_lines(backward), '[LibraryClasses]')
          == sorted(classes),
          f"got {section(inf_lines(backward), '[LibraryClasses]')}")
    check('and the same inf comes out of either order',
          inf_lines(forward) == inf_lines(backward),
          'two runs of identical code over identical inputs emitted different files, so '
          'no regenerated harness could be compared with the one it replaced')
    check('every class is still there, none added',
          sorted(section(inf_lines(backward), '[LibraryClasses]')) == sorted(classes),
          'sorting must reorder the section, not filter it')
    guids = {'gZeroGuid', 'gEfiVT100Guid', 'gEfiGlobalVariableGuid', 'gQemuRamfbGuid'}
    protocols = {'gEfiBlockIoProtocolGuid', 'gEfiDebugPortProtocolGuid',
                 'gGetPcdInfoProtocolGuid'}
    check('[Guids] is emitted sorted',
          section(inf_lines(forward, guids, protocols), '[Guids]') == sorted(guids))
    check('[Protocols] is emitted sorted',
          section(inf_lines(forward, guids, protocols), '[Protocols]')
          == sorted(protocols))
    check('and both come out of a set in any order',
          inf_lines(forward, guids, protocols)
          == inf_lines(forward, list(reversed(sorted(guids))),
                       list(reversed(sorted(protocols)))),
          'classify_guids answers with sets, which is where the order came from')
    check('a section given nothing is still emitted, empty',
          section(inf_lines(forward), '[Guids]') == []
          and '[Guids]' in inf_lines(forward))
    check('the FILE_GUID is still the one it was handed',
          any('deadbeef-0000-0000-0000-000000000000' in line
              for line in inf_lines(forward)),
          'the uuid4s are deliberate: they are what makes two harnesses two modules')
    check('NULL is still not a library class',
          'NULL' not in section(inf_lines(dict(forward, NULL='null.inf')),
                                '[LibraryClasses]'))
    dxe = inf_lines({'UefiApplicationEntryPoint': 'a.inf', 'BaseLib': 'b.inf'},
                    timing='dxe')
    check('the dxe arm still swaps the entry point, in sorted position',
          section(dxe, '[LibraryClasses]') == ['BaseLib', 'UefiDriverEntryPoint'],
          f"got {section(dxe, '[LibraryClasses]')}")
    emitter = code(body(gen_source('uefi_harness/inf_template.py'),
                        'def gen_firness_inf('))
    check('the emitter sorts the classes rather than reading the mapping\'s order',
          'for lib in sorted(libraries)' in emitter
          and 'for lib in libraries.keys()' not in emitter,
          'the dsc has sorted(resolved) and the inf was the one that did not')
    check('and sorts both guid sections',
          emitter.count('sorted(driver_guids or [])') == 1
          and emitter.count('sorted(protocol_guids or [])') == 1,
          'these are sets too, and a 25 guid section moved every line between two runs')

    print('\na generator argument keeps its declarator and gets its EDK2 name')
    kept = generated('unsigned short *', 'CHAR16 *', 'wchar_t *')
    check('the recorded "unsigned short *" is still a pointer',
          kept.arg_type.strip().endswith('*'), f'got {kept.arg_type!r}')
    check('and pointer_count still says one', kept.pointer_count == 1,
          f'{kept.arg_type!r} -- pointer_count is counted off the type TEXT')
    check('the raw C spelling is gone', 'unsigned' not in kept.arg_type,
          f'got {kept.arg_type!r} -- this is the defect: the raw spelling reaches the '
          f'emitted declaration and a string gets sizeof(unsigned short)')
    check('the declaration settles which of the two names it is',
          kept.arg_type.strip() == 'CHAR16 *', f'got {kept.arg_type!r}')
    # The same recorded site with the declaration held back: one attribute apart, and the
    # recorded data_type is then the only thing saying the pointee is a character.
    guessed = generated('unsigned short *', '', 'wchar_t *')
    check('without a declaration the recorded data_type says CHAR16',
          guessed.arg_type.strip() == 'CHAR16 *', f'got {guessed.arg_type!r}')
    # ...and the same again with the data_type held back too.
    blind = generated('unsigned short *', '', '')
    check('with neither, the name a plain loop settled on is kept',
          blind.arg_type.strip() == 'UINT16 *', f'got {blind.arg_type!r}')
    check('a declaration of UINT16 * beats a wchar_t data_type',
          generated('unsigned short *', 'UINT16 *',
                    'wchar_t *').arg_type.strip() == 'UINT16 *')
    check('a type the map does not hold is left alone',
          generated('EFI_GUID *', 'EFI_GUID *').arg_type.strip() == 'EFI_GUID *')
    check('a type already spelled in EDK2 is not touched',
          generated('CHAR16 *', 'CHAR16 *', 'wchar_t *').arg_type.strip() == 'CHAR16 *')
    check('a scalar is normalised without growing a star',
          generated('unsigned int', 'UINT32').arg_type.strip() == 'UINT32')
    loader = code(body(gen_source('data_analysis/analyze.py'), 'def load_generators('))
    check('load_generators asks edk2_typedef_for',
          'edk2_typedef_for(' in loader,
          'load_data has asked it since the loud form of this defect was fixed; this is '
          'the loader that did not')
    check('and keeps the declarator by replacing inside the spelling',
          'remove_ref_symbols(argument[0].arg_type), edk2_name)' in loader,
          'assigning the bare name is what turned "unsigned short *" into a scalar in '
          'load_data')
    whole = code(gen_source('data_analysis/analyze.py'))
    check('the declarations are loaded before the generators that need them',
          whole.index('generator_declares = load_generator_declares(')
          < whole.index('generators = load_generators('),
          'without the declaration the ambiguity is settled by the recorded data_type '
          'alone, and a generator argument recorded as UINT16 * would stay one')
    check('and they are passed in',
          'load_generators(generator_file, macros_val, generator_declares)' in whole)

    print('\nso the string that argument is gets a string\'s allocation')
    declared, _f, _o, called = emit({'Arg_0': argument(kept.arg_type, 'FileType')})
    check('a CHAR16 * generator argument is declared CHAR16 *',
          declared and declared[0].startswith('CHAR16 * Fuzz_Arg_0 ='), f'{declared[:1]}')
    check('with room for a string', allocation_of(declared, 'Arg_0') == '32 * sizeof(CHAR16)',
          f'got {allocation_of(declared, "Arg_0")!r}')
    check('and the string\'s own extent is registered',
          extent_of(called, 'Arg_0') == '32 * sizeof(CHAR16)',
          f'got {extent_of(called, "Arg_0")!r}')
    # the same argument under the raw spelling, which is the defect, for comparison
    raw = emit({'Arg_0': argument('unsigned short *', 'FileType')})[0]
    check('the raw spelling would have given it two bytes',
          allocation_of(raw, 'Arg_0') == 'sizeof(unsigned short)',
          f'got {allocation_of(raw, "Arg_0")!r} -- if this ever stops being true the '
          f'comparison above has lost its point')

    print('\na size never pairs with itself')
    lone = {'Arg_0': argument('UINTN *', 'AddressSize', arg_dir='IN OUT')}
    check('a pointer size with no buffer in the call pairs with nothing',
          TEMPLATE.buffer_for_size('AddressSize', lone) == '',
          f'got {TEMPLATE.buffer_for_size("AddressSize", lone)!r} -- Arg_0 is the size '
          f'itself, and the bound then comes from sizeof its own pointee')
    # the same call with a buffer added whose name the stem only prefixes: one attribute
    # apart, and the self-match used to win because the size comes first
    with_buffer = dict(lone,
                       Arg_1=argument('EFI_IPv6_ADDRESS *', 'AddressList', arg_dir='OUT'))
    check('and finds the buffer the self-match was hiding',
          TEMPLATE.buffer_for_size('AddressSize', with_buffer) == 'Arg_1',
          f'got {TEMPLATE.buffer_for_size("AddressSize", with_buffer)!r}')
    check('an exact stem match still wins over a prefix',
          TEMPLATE.buffer_for_size('AddressSize', {
              'Arg_0': argument('UINTN *', 'AddressSize', arg_dir='IN OUT'),
              'Arg_1': argument('EFI_IPv6_ADDRESS *', 'AddressList'),
              'Arg_2': argument('EFI_IPv6_ADDRESS *', 'Address')}) == 'Arg_2')
    check('a length is not paired with a count',
          TEMPLATE.buffer_for_size('EntryLength', {
              'Arg_0': argument('UINT32 *', 'EntryLength', arg_dir='OUT'),
              'Arg_1': argument('UINT32 *', 'EntryCount', arg_dir='OUT'),
              'Arg_2': argument('VOID **', 'Entries', arg_dir='OUT')}) == '',
          'ARP\'s Find: pairing the two numbers bounds a length by sizeof (UINT32) and '
          'calls four an extent')
    check('a by-value size is unaffected -- it was never a candidate',
          TEMPLATE.buffer_for_size('BufferSize', {
              'Arg_0': argument('UINTN', 'BufferSize'),
              'Arg_1': argument('VOID *', 'Buffer')}) == 'Arg_1')
    check('buffer_for_size and buffer_for_count now state the same rule',
          code(body(gen_source('uefi_harness/harnesses_template.py'),
                    'def buffer_for_size(')).count(
              'name.endswith(SIZE_NAME_SUFFIXES) or name.endswith(COUNT_NAME_SUFFIXES)')
          == 1,
          'the sibling had it and this one did not, which is the whole defect')
    _d, filled, _o, called = emit(statistics())
    check('*StatisticsSize is bounded by the table, not by a page',
          bound_of(filled, 'Arg_2') == 'sizeof(EFI_NETWORK_STATISTICS)',
          f'got {bound_of(filled, "Arg_2")!r} -- 4096 against a 176 byte table is the '
          f'4KB overflow the harness asked for, and it came out of the matrix as a '
          f'severity 5 heap-buffer-overflow write')
    check('and the table is pinned to it, so neither half is drawn from the live tables',
          not any('Arg_3_LiveChoice' in line for line in called),
          'substituting one half of a size and buffer pair is a 62KB write that belongs '
          'to the harness')

    print('\nand a raw buffer\'s contents are not clamped as if they were a length')
    _d, filled, _o, _c = emit(cpu_io())
    check('the VOID * buffer of a raw-buffer call is not clamped',
          bound_of(filled, 'Arg_4') is None,
          f'got {bound_of(filled, "Arg_4")!r} -- that is the first UINTN of the buffer\'s '
          f'own contents, and it costs eight bytes of content diversity per iteration')
    check('while the count beside it still is',
          bound_of(filled, 'Arg_3') == '(4096 / (1 << (Fuzz_Arg_1 & 0x03)))',
          f'got {bound_of(filled, "Arg_3")!r}')
    # The same call with the buffer RENAMED to a size: one attribute apart, and the name
    # is the only thing that says which of the two an argument is.
    _d, renamed, _o, _c = emit(cpu_io(buffer_name='BufferSize'))
    check('the same argument named a size is clamped',
          bound_of(renamed, 'Arg_4') == '4096',
          f'got {bound_of(renamed, "Arg_4")!r} -- the declaration is the only thing that '
          f'tells a size from the buffer it sizes')
    for name in ('BufferSize', 'DataLength', 'NumberOfBytes', 'OptionCount', 'HeaderLen',
                 'EntryCount'):
        check(f'{name} reads as a size', NAMES_A_SIZE and NAMES_A_SIZE(name))
    for name in ('Buffer', 'Context', 'HostAddress', 'Data', 'TokenNumber', 'Lun', ''):
        check(f'{name or "an unnamed argument"} does not',
              NAMES_A_SIZE is not None and not NAMES_A_SIZE(name))
    check('the by-value blanket is untouched: an integer beside a raw buffer is a size',
          bound_of(emit({'Arg_0': argument('VOID *', 'Buffer'),
                         'Arg_1': argument('UINTN', 'Offset')})[1], 'Arg_1') == '4096',
          'an integer in a call that takes a raw buffer is a size or an offset into it; '
          'only the buffer itself was wrong')

    print('\nan OUT size is bounded, by the same statement the input section uses')
    out_pair = {'Arg_0': argument('EFI_PROTOCOL *', 'This', variable='__PROTOCOL__'),
                'Arg_1': argument('UINTN *', 'BufferSize', arg_dir='OUT'),
                'Arg_2': argument('VOID *', 'Buffer', arg_dir='OUT')}
    _d, _f, outputs, _c = emit(out_pair)
    check('an OUT *BufferSize is clamped at all', bound_of(outputs, 'Arg_1') is not None,
          'eight fuzzed bytes make it 2^64-1 and the callee is told to fill memory that '
          'does not exist')
    check('by the allocation of the buffer it names',
          bound_of(outputs, 'Arg_1') == '4096',
          f'got {bound_of(outputs, "Arg_1")!r}')
    # The same argument declared IN OUT: one attribute apart, so the two sections are
    # being asked the same question about the same argument.
    in_out = dict(out_pair, Arg_1=argument('UINTN *', 'BufferSize', arg_dir='IN OUT'))
    check('and the input section says the same thing for the same argument',
          bound_of(emit(in_out)[1], 'Arg_1') == bound_of(outputs, 'Arg_1'),
          f'IN OUT {bound_of(emit(in_out)[1], "Arg_1")!r} against OUT '
          f'{bound_of(outputs, "Arg_1")!r} -- one of these two has been the unbounded one '
          f'twice now')
    fill = next((index for index, line in enumerate(outputs)
                 if 'ReadBytes' in line and '(VOID *)Fuzz_Arg_1);' in line), None)
    clamped = next((index for index, line in enumerate(outputs)
                    if bound_of([line], 'Arg_1')), None)
    # Both ends named, not "the fill is not after the clamp": with the fill deleted there
    # is nothing the clamp can be after, and an assertion written that way passes.
    check('the input is read into it, and the clamp comes after that read',
          fill is not None and clamped is not None and fill < clamped,
          f'fill at {fill}, clamp at {clamped} -- clamping first bounds the zero the '
          f'declaration left there, and the fuzzed value then reaches the callee')
    # Short-circuited on purpose: with either end missing this has to report a failure,
    # not raise. A check that dies has reported nothing, and a mutation run cannot tell
    # that from a catch.
    inside = (fill is not None and clamped is not None
              and outputs[fill].startswith('    ')
              and outputs[clamped].startswith('    ')
              and any(line.strip() == '}' for line in outputs[clamped + 1:]))
    check('and both are inside the branch that does the filling', inside, f'{outputs}')
    typed = dict(out_pair, Arg_1=argument('EFI_GUID *', 'BufferSize', arg_dir='OUT'))
    check('an OUT pointer to a struct is not clamped',
          bound_of(emit(typed)[2], 'Arg_1') is None,
          '*p % N does not compile when p points at an EFI_GUID')
    plain = dict(out_pair, Arg_1=argument('UINTN *', 'TableKey', arg_dir='OUT'))
    check('an OUT pointer that sizes nothing is not clamped',
          bound_of(emit(plain)[2], 'Arg_1') is None,
          'InstallAcpiTable\'s TableKey is an identifier the callee writes; bounding it '
          'by a buffer it has nothing to do with is how a wide net costs coverage')
    counted = {'Arg_0': argument('UINT32 *', 'AddressCount', arg_dir='OUT'),
               'Arg_1': argument('EFI_IPv6_ADDRESS *', 'Addresses', arg_dir='OUT')}
    check('an OUT element count is bounded in elements',
          bound_of(emit(counted)[2], 'Arg_0') == '(4096 / sizeof(EFI_IPv6_ADDRESS))',
          f'got {bound_of(emit(counted)[2], "Arg_0")!r}')
    check('an OUT dimension is bounded as a dimension',
          bound_of(emit({'Arg_0': argument('UINTN *', 'Width', arg_dir='OUT'),
                         'Arg_1': argument('EFI_GRAPHICS_OUTPUT_BLT_PIXEL *', 'BltBuffer',
                                           arg_dir='OUT')})[2], 'Arg_0')
          == str(TEMPLATE.FIRNESS_DIMENSION_MAX))
    outputs_src = code(body(gen_source('uefi_harness/harnesses_template.py'),
                            'def generate_outputs('))
    check('generate_outputs asks pointer_size_clamp',
          'pointer_size_clamp(' in outputs_src,
          'restating the bound here is how the two sections came apart')
    check('and fuzzable_args asks the same function',
          'pointer_size_clamp(' in code(body(
              gen_source('uefi_harness/harnesses_template.py'), 'def fuzzable_args(')))
    clamp_src = code(body(gen_source('uefi_harness/harnesses_template.py'),
                          'def pointer_size_clamp('))
    check('which takes the capacity from the allocation, not from a new constant',
          'buffer_capacity(' in clamp_src and 'buffer_and_element_for(' in clamp_src,
          'allocation_bytes is the single statement of a buffer\'s size, through '
          'buffer_capacity')
    check('and the output section uses the type the declaration emitted',
          'tracked.arg_type' in outputs_src,
          'a VOID * is declared UINTN *, and the allocation follows the declaration')

    print('\nno bound is sizeof of something that has no size')
    const_void = {'Arg_0': argument('UINTN *', 'DataSize', arg_dir='OUT'),
                  'Arg_1': argument('CONST VOID **', 'Data', arg_dir='OUT')}
    check('a CONST VOID ** pair does not answer sizeof(CONST VOID)',
          'sizeof' not in TEMPLATE.size_limit_for('Arg_1', const_void),
          f'got {TEMPLATE.size_limit_for("Arg_1", const_void)!r} -- sizeof of an '
          f'incomplete type; clang refuses it and gcc calls it one byte, so the bound '
          f'the harness emits is "% 2"')
    check('it answers the page a byte buffer gets',
          TEMPLATE.size_limit_for('Arg_1', const_void) == str(TEMPLATE.FIRNESS_BUFFER_BYTES))
    check('and the emitted clamp is that page',
          bound_of(emit(const_void)[2], 'Arg_0') == '4096',
          f'got {bound_of(emit(const_void)[2], "Arg_0")!r} -- EFI_ACPI_SDT_PROTOCOL.'
          f'GetOption is the member, and its DataSize is OUT, which is why no build had '
          f'reached this expression')
    check('the qualifier is read off the type, not left attached to it',
          BASE_TYPE_OF is not None
          and (BASE_TYPE_OF('CONST VOID **'), BASE_TYPE_OF('const UINT8 *'),
               BASE_TYPE_OF('EFI_GUID *')) == ('VOID', 'UINT8', 'EFI_GUID'))
    check('a const-qualified struct still sizes as itself',
          TEMPLATE.size_limit_for('Arg_1', {
              'Arg_0': argument('UINTN *', 'DataSize', arg_dir='OUT'),
              'Arg_1': argument('CONST EFI_GUID *', 'Data')}) == 'sizeof(CONST EFI_GUID)',
          'the spelling is left alone: it is a complete type and it compiles')
    for arg_type in ('VOID *', 'CONST VOID *', 'UINT8 *', 'CONST UINT8 *'):
        check(f'a {arg_type} buffer is allocated a page, not sizeof its pointee',
              TEMPLATE.allocation_bytes(arg_type) == str(TEMPLATE.FIRNESS_BUFFER_BYTES),
              f'got {TEMPLATE.allocation_bytes(arg_type)!r}')

    print('\nno TypeInfo shares another\'s fields')
    one, other = COMMON.TypeInfo(), COMMON.TypeInfo()
    check('two default TypeInfos do not hold one list',
          one.fields is not other.fields,
          'a list in a default argument is created once, at definition time')
    one.fields.append(COMMON.FieldInfo('Leaked', 'UINT32'))
    check('and appending to one does not reach the other', other.fields == [],
          f'{[f.name for f in other.fields]} -- a type would be emitted with the fields '
          f'of another')
    check('a third, made after the append, is still empty',
          COMMON.TypeInfo().fields == [])
    recorded_fields = [COMMON.FieldInfo('Real', 'UINT32')]
    check('an explicit list is still the caller\'s own list',
          COMMON.TypeInfo('X', recorded_fields, 'f.h').fields is recorded_fields,
          'load_types builds the list and hands it over; copying it here would give two '
          'owners two answers')
    check('a miss in the type map still reads as a type with no fields',
          COMMON.TypeMap()['nobody recorded this'].fields == [])
    check('and still stores nothing',
          len(dict(COMMON.TypeMap(a=1))) == 1
          and 'absent' not in (lambda m: (m['absent'], m)[1])(COMMON.TypeMap()),
          'a defaultdict mutates on read, which is what made the map claim to know a '
          'type the analyser never saw')
    check('the default is not a list literal',
          not re.search(r'def __init__\(self, name: str = "", fields[^)]*= \[\]',
                        code(body(gen_source('common/types.py'), 'class TypeInfo:'))),
          'this is the line')

    if os.path.isdir(SWEEP):
        print('\nand on the harnesses the sweep actually ran')
        shipped = os.path.join(SWEEP, 'campaigns', 'EfiCpuIo2', 'Firness',
                               'FirnessHarnesses.c')
        if os.path.isfile(shipped):
            text = io.open(shipped, encoding='utf-8', errors='ignore').read()
            check('the harness that ran clamped its raw buffer\'s contents',
                  '*Read_Arg_4 = *Read_Arg_4 % (4096 + 1);' in text,
                  'if this is gone the campaign was regenerated and the file is no '
                  'longer evidence of anything')
        strings = os.path.join(SWEEP, 'campaigns', 'EfiDevicePathUtilities', 'Firness',
                               'FirnessHarnesses.c')
        if os.path.isfile(strings):
            text = io.open(strings, encoding='utf-8', errors='ignore').read()
            check('and declared its generator\'s CHAR16 * in raw C',
                  'unsigned short * ChooseFile_Arg_1 = (unsigned short *)'
                  'AllocateZeroPool(sizeof(unsigned short));' in text,
                  'the measured 20 declarations across 8 campaigns start here')
        snp = os.path.join(SWEEP, 'campaigns', 'EfiSimpleNetwork', 'Firness',
                           'FirnessHarnesses.c')
        if os.path.isfile(snp):
            text = io.open(snp, encoding='utf-8', errors='ignore').read()
            check('and bounded *StatisticsSize by a page against a 176 byte table',
                  '*Statistics_Arg_2 = *Statistics_Arg_2 % (4096 + 1);' in text
                  and 'Statistics_Arg_3 = (EFI_NETWORK_STATISTICS *)AllocateZeroPool('
                      'sizeof(EFI_NETWORK_STATISTICS));' in text,
                  'the allocation and the bound are both in that file, disagreeing by a '
                  'factor of 23')
    else:
        print(f'\n  [skip] {SWEEP} is not on this host')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
