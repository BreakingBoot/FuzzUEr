#!/usr/bin/env python3
"""Assert a fuzzed pointer keeps its declarator, and is declared untrusted for its size.

Two decisions in the generator, measured on EVAL-1 run 43454245046 and on the 142 cached
analyses under fuzzuer-genreview.

The type. A call site records the type of the EXPRESSION it passed, so a wide string
literal arrives as "unsigned short *" rather than "CHAR16 *". load_data puts the EDK2 name
back by reading type_defs backwards, and wrote the name ALONE -- every star dropped.
pointer_count is counted off the type TEXT, so the argument stopped being a pointer:
EdkiiVariableLock declared "UINT16 RequestToLock_Arg_1" for its CHAR16 *VariableName,
read input bytes into it and passed it by value. clang refused the call --
"incompatible integer to pointer conversion ... take the address with &" -- and the
protocol got no harness at all. Three more members are one recorded call site away from
the same thing: EfiUnicodeCollation's StriColl Arg_1 and Arg_2 and MetaiMatch Arg_2, which
escape only because the block the template is taken from happens to spell them CHAR16.

Keeping the star is half of it. "unsigned short" is BOTH UINT16 and CHAR16 in type_defs,
and reading a dict backwards for a key that has two is a choice: UINT16 * compiles against
CHAR16 * with no diagnostic at all, and then is_string_pointer says no, so the argument
gets AllocateZeroPool(sizeof(UINT16)) -- a two byte buffer with no terminator, handed to a
callee that walks it to one. That is the harness fault that cost EdkiiVarCheck 914 false
solutions, and it would have been the silent form of the same defect.

The extent. FirnessUntrusted tells the firmware sanitizer which bytes the caller chose, so
that a length read twice out of them is a double fetch. It was given the constant 4096
whatever had been allocated: in the same generated file, an EFI_GUID * allocated
sizeof(EFI_GUID) -- sixteen bytes -- was registered as four thousand and ninety six. The
4080 bytes after it are other allocations, their pool headers and the free list, and a
read of any of them is then a double fetch reported against this call. The allocation and
the registration were simply two unjoined statements of the same number; allocation_bytes
is now the one statement and both read it.

The near miss is asserted here too: the generator's own comment named size_limit_for as
the cure, and size_limit_for has no device path branch. Routing the extent through it
answers sizeof(EFI_DEVICE_PATH_PROTOCOL) -- four bytes -- and unmarks the part of the path
the fuzzer wrote, on exactly the protocols where a device path is the attack surface.

Run: python3 scripts/untrusted_extent_check.py
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

    The comment beside the registration names size_limit_for, to say why the extent is
    NOT taken from it. An assertion made against the raw text reads that explanation as
    the thing it forbids.
    """
    found = re.search(r'"""', text)
    if found:
        closing = text.index('"""', found.end())
        text = text[:found.start()] + text[closing + 3:]
    kept = []
    for line in text.splitlines():
        if line.strip().startswith('#'):
            continue
        kept.append(line)
    return '\n'.join(kept)


def body(src, marker):
    """One definition's text, from its `def` to the next top-level one."""
    start = src.index(marker)
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Z_]+ = |@)', rest)
    return src[start:start + len(marker) + (end.start() if end else len(rest))]


def generator():
    """The generator's own modules, with the one import a runner does not have stubbed.

    analyze.py pulls fuzzywuzzy at module scope and it is not installed on a runner.
    fuzz.ratio decides whether a generator function's NAME is close enough to the
    function under test to be rejected as a generator for it, which is nothing to do with
    either defect here -- the fixtures below declare no generators at all.
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
    from common import utils
    from data_analysis import analyze
    import uefi_harness.harnesses_template as template
    return common_types, utils, analyze, template


COMMON, UTILS, ANALYZE, TEMPLATE = generator()


def argument(arg_type, arg_dir='IN', variable='', data_type='', param_name=''):
    return [COMMON.Argument(arg_dir, arg_type, '', data_type, '', variable,
                            param_name=param_name)]


def emit(args, random=False):
    """Declare and call one function block, as generate_inputs and call_function do.

    Returns the declaration lines and the FirnessUntrusted lines, which are the two
    statements of the buffer's size that had drifted apart.
    """
    block = COMMON.FunctionBlock(args, 'Fuzz', 'protocol', [], 'EFI_STATUS')
    tracked = []
    declared = []
    # the array-ness and the span are taken from the same two functions call_function
    # takes them from. Telling declare_var less than the call is told is how the two
    # statements of one number came apart in the first place, and the pair assertion
    # below would then be comparing the fixture's mistake with the generator's answer.
    span = TEMPLATE.dimension_span(args) if TEMPLATE.has_dimension_arg(args) else 0
    for key, entry in args.items():
        declared += TEMPLATE.declare_var('Fuzz', key, entry, tracked, False, False, False,
                                         random, TEMPLATE.walks_as_array(args, key), span)
    called = TEMPLATE.call_function('Fuzz', block, {'Fuzz': block}, 'Protocol', tracked,
                                    False, '')
    return declared, [line for line in called if 'FirnessUntrusted' in line]


def allocation_of(declared, name='Fuzz_Arg_0'):
    """The byte count a declaration line asks AllocateZeroPool for."""
    for line in declared:
        found = re.search(rf'{name} = \([^)]*\)AllocateZeroPool\((.*)\);$', line)
        if found:
            return found.group(1)
    return None


def extent_of(registrations, name='Fuzz_Arg_0'):
    for line in registrations:
        found = re.search(rf'FirnessUntrusted\({name}, (.*)\);$', line)
        if found:
            return found.group(1)
    return None


def harnessed(recorded, declared_type):
    """What load_data leaves on the template argument, from one recorded call site.

    recorded is the (arg_type, data_type) the analyser wrote down for Arg_1 and
    declared_type is what the protocol's own declaration says. Everything else is held
    equal between the cases below, so an assertion is about the one attribute it names.
    """
    work = tempfile.mkdtemp(prefix='untrusted-extent-')
    try:
        site = {
            'Function': 'RequestToLock', 'Service': 'protocol', 'Include': [],
            'ReturnType': 'EFI_STATUS',
            'Arguments': {
                'Arg_0': {'arg_dir': 'IN', 'arg_type': 'EDKII_VARIABLE_LOCK_PROTOCOL *',
                          'assignment': '', 'data_type': '', 'usage': '',
                          'variable': '__PROTOCOL__'},
                'Arg_1': {'arg_dir': 'IN', 'arg_type': recorded[0], 'assignment': '',
                          'data_type': recorded[1], 'usage': '',
                          'variable': '__CONSTANT_STRING__'}}}
        path = os.path.join(work, 'call-database.json')
        io.open(path, 'w', encoding='utf-8').write(json.dumps([site, site]))
        declaration = {}
        if declared_type:
            declaration['RequestToLock'] = COMMON.Function(
                'RequestToLock',
                {'Arg_0': [COMMON.Argument('IN', 'EDKII_VARIABLE_LOCK_PROTOCOL *', '',
                                           '', '', '')],
                 'Arg_1': [COMMON.Argument('IN', declared_type, '', '', '',
                                           'VariableName')]},
                'EFI_STATUS', 'protocol', [])
        _data, template = ANALYZE.load_data(
            path, {'Protocols': [('RequestToLock', 'gEdkiiVariableLockProtocolGuid')]},
            {}, False, False, declaration)
        return template['RequestToLock'].arguments['Arg_1'][0]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    print('a pointer to a typedef\'d scalar keeps its declarator')
    kept = harnessed(('unsigned short *', 'wchar_t *'), 'CHAR16 *')
    check('the recorded "unsigned short *" is still a pointer',
          kept.arg_type.strip().endswith('*'),
          f'got {kept.arg_type!r} -- this is the defect: the name was written back '
          f'without the star and the argument became a scalar')
    check('and pointer_count still says one',
          COMMON.Argument('IN', kept.arg_type, '', '', '', '').pointer_count == 1,
          f'{kept.arg_type!r} -- pointer_count is counted off the type text, and '
          f'get_directly_fuzzable rebuilds the Argument from it')
    check('the EDK2 name replaces the raw spelling', 'unsigned' not in kept.arg_type,
          f'got {kept.arg_type!r} -- the raw C spelling reaches the emitted harness')

    print('\nand CHAR16 is not rewritten to UINT16')
    check('the declaration settles which name it is', kept.arg_type.strip() == 'CHAR16 *',
          f'got {kept.arg_type!r} -- UINT16 * compiles against CHAR16 * with no '
          f'diagnostic, so the loud failure becomes a silent one')
    # Same recorded call site, no declaration to read: the recorded data_type is the only
    # thing left that says the pointee is a character.
    guessed = harnessed(('unsigned short *', 'wchar_t *'), '')
    check('without a declaration the recorded data_type says CHAR16',
          guessed.arg_type.strip() == 'CHAR16 *', f'got {guessed.arg_type!r}')
    # ...and the same again with the data_type held back, which is the only attribute
    # that differs from the case above.
    blind = harnessed(('unsigned short *', ''), '')
    check('with neither, the name a plain loop settled on is kept',
          blind.arg_type.strip() == 'UINT16 *', f'got {blind.arg_type!r}')
    check('a type the map does not hold is left alone',
          harnessed(('EFI_GUID *', ''), 'EFI_GUID *').arg_type.strip() == 'EFI_GUID *')
    already = harnessed(('CHAR16 *', 'wchar_t *'), 'CHAR16 *')
    check('a type already spelled in EDK2 is not touched',
          already.arg_type.strip() == 'CHAR16 *', f'got {already.arg_type!r}')

    print('\nthe ambiguous reverse map resolves deterministically')
    check('"unsigned short" alone is UINT16',
          UTILS.edk2_typedef_for('unsigned short') == 'UINT16')
    check('"unsigned short" with a wchar_t pointee is CHAR16',
          UTILS.edk2_typedef_for('unsigned short *', '', 'wchar_t *') == 'CHAR16')
    check('a declaration beats the recorded data_type',
          UTILS.edk2_typedef_for('unsigned short *', 'UINT16 *', 'wchar_t *') == 'UINT16',
          'the declaration is the type the callee was written with')
    check('"unsigned char" alone is BOOLEAN',
          UTILS.edk2_typedef_for('unsigned char') == 'BOOLEAN',
          'the other name sharing that spelling is UINT8; this is what the loop '
          'settled on before and nothing here is meant to change it')
    check('an unambiguous entry still maps',
          (UTILS.edk2_typedef_for('unsigned int'),
           UTILS.edk2_typedef_for('long long')) == ('UINT32', 'INT64'))
    check('a spelling the map does not hold answers with nothing',
          UTILS.edk2_typedef_for('EFI_GUID *') == '')
    # Reversing a dict by iterating it answers with whichever key came first, so the
    # answer must not move when the dict is built in another order.
    reversed_defs = dict(reversed(list(COMMON.type_defs.items())))
    saved = COMMON.type_defs
    try:
        UTILS.type_defs = reversed_defs
        shuffled = (UTILS.edk2_typedef_for('unsigned short'),
                    UTILS.edk2_typedef_for('unsigned char'),
                    UTILS.edk2_typedef_for('unsigned short *', '', 'wchar_t *'))
    finally:
        UTILS.type_defs = saved
    check('the answer does not move when type_defs is built in another order',
          shuffled == ('UINT16', 'BOOLEAN', 'CHAR16'), f'{shuffled}')
    # The two ambiguities in the map today are named in the preference list. One that is
    # not -- an entry added later -- still cannot be answered by whichever key the loop
    # reached first.
    invented = dict(COMMON.type_defs, ZEBRA_T='wobble', ALPHA_T='wobble')
    try:
        UTILS.type_defs = invented
        one = UTILS.edk2_typedef_for('wobble *')
        UTILS.type_defs = dict(reversed(list(invented.items())))
        other = UTILS.edk2_typedef_for('wobble *')
    finally:
        UTILS.type_defs = saved
    check('an ambiguity the preference list does not name is stable too',
          one == other and one in ('ALPHA_T', 'ZEBRA_T'), f'{one!r} then {other!r}')
    lookup = code(body(gen_source('data_analysis/analyze.py'), 'def load_data('))
    check('load_data no longer assigns the bare name',
          not re.search(r'\[0\]\.arg_type = name\b', lookup),
          'writing the name alone is what dropped the declarator')

    print('\na string pointer gets a string allocation')
    check('is_string_pointer reads CHAR16 * as a string',
          TEMPLATE.is_string_pointer('CHAR16 *'))
    check('and does not read UINT16 * as one',
          not TEMPLATE.is_string_pointer('UINT16 *'),
          'this is why the name matters after the star is kept: the wrong one is a '
          'two byte unterminated buffer the callee walks past')
    declared, registered = emit({'Arg_0': argument('CHAR16 *')})
    check('a CHAR16 * is allocated room for a string',
          allocation_of(declared) == '32 * sizeof(CHAR16)',
          f'got {allocation_of(declared)!r}')
    check('a UINT16 * is not',
          allocation_of(emit({'Arg_0': argument('UINT16 *')})[0]) == 'sizeof(UINT16)',
          'the same argument under the wrong name, for comparison')

    print('\nthe untrusted extent is the allocation, for every shape')
    shapes = [
        ('a typed pointer', 'EFI_GUID *', 'sizeof(EFI_GUID)'),
        ('a wide string', 'CHAR16 *', '32 * sizeof(CHAR16)'),
        ('a narrow string', 'CHAR8 *', '32 * sizeof(CHAR8)'),
        ('a raw buffer', 'UINT8 *', '4096'),
        ('a device path', 'EFI_DEVICE_PATH_PROTOCOL *', '4096'),
    ]
    for what, arg_type, expected in shapes:
        declared, registered = emit({'Arg_0': argument(arg_type)})
        allocated = allocation_of(declared)
        extent = extent_of(registered)
        check(f'{what} is allocated {expected}', allocated == expected,
              f'got {allocated!r}')
        check(f'{what} is registered for what it was allocated', extent == allocated,
              f'allocated {allocated!r}, registered {extent!r}')
    check('a VOID * follows the type it was declared with, not the parameter\'s',
          extent_of(emit({'Arg_0': argument('VOID *')})[1]) == '4096',
          'declare_var rewrites a VOID * to UINTN *, and the allocation follows the '
          'declaration')
    # --random declares every pointer UINTN *, so the parameter's own type and the type
    # the variable was declared with say different things about the same allocation.
    # Same argument as the typed pointer above, one flag apart.
    declared, registered = emit({'Arg_0': argument('EFI_GUID *')}, random=True)
    check('under --random the allocation is a page, not the parameter\'s element',
          allocation_of(declared) == '4096', f'got {allocation_of(declared)!r}')
    check('and the extent is that page',
          extent_of(registered) == allocation_of(declared),
          f'registered {extent_of(registered)!r} -- taken from the parameter it would '
          f'be sixteen bytes of a 4096 byte buffer the fuzzer fills')

    print('\nand the device path keeps its page, which size_limit_for would not')
    check('size_limit_for would shrink a device path to its header',
          TEMPLATE.size_limit_for('Arg_0', {'Arg_0': argument(
              'EFI_DEVICE_PATH_PROTOCOL *')}) == 'sizeof(EFI_DEVICE_PATH_PROTOCOL)',
          'this is the near miss: it has a string branch and a raw buffer branch and '
          'no device path branch')
    registration = code(body(gen_source('uefi_harness/harnesses_template.py'),
                             'def call_function('))
    check('so the registration does not call it',
          'size_limit_for(' not in registration,
          'four bytes of a 4096 byte path registered would unmark everything the '
          'fuzzer wrote into it')
    check('the registration asks allocation_bytes instead',
          'allocation_bytes(' in registration)
    check('and the allocation asks the same function',
          'allocation_bytes(' in code(body(gen_source('uefi_harness/harnesses_template.py'),
                                           'def set_undefined_constants(')),
          'two statements of one number is how they came apart in the first place')

    print('\na size argument still names the extent when there is one')
    paired = {'Arg_0': argument('VOID *', param_name='Buffer'),
              'Arg_1': argument('UINTN', param_name='BufferSize')}
    check('a paired size is registered, not the allocation',
          extent_of(emit(paired)[1]) == 'Fuzz_Arg_1',
          'the buffer is reallocated to that size, so the size is the extent')
    # The same call with the size renamed so nothing pairs with it: one attribute apart.
    unpaired = {'Arg_0': argument('VOID *', param_name='Buffer'),
                'Arg_1': argument('UINTN', param_name='Attributes')}
    check('and with nothing to pair, the allocation is',
          extent_of(emit(unpaired)[1]) == '4096')

    print('\na dimension-sized buffer agrees with its own allocation')
    dimensioned = {'Arg_0': argument('EFI_GRAPHICS_OUTPUT_BLT_PIXEL *',
                                     param_name='BltBuffer'),
                   'Arg_1': argument('UINTN', param_name='Width')}
    declared, registered = emit(dimensioned)
    # Not the bare page any more: the dimensions are bounded by a constant, so 16 x 16 of
    # a 32 byte element is 8192 and the allocation is what has to carry the element size.
    # It is a maximum, so it is never smaller than the page it was.
    check('the call carrying a dimension allocates at least a page',
          (allocation_of(declared) or '').startswith('(4096 > '),
          f'got {allocation_of(declared)!r}')
    check('and the element size is in that allocation',
          'sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)' in (allocation_of(declared) or ''),
          f'got {allocation_of(declared)!r}')
    check('and registers what it allocated',
          extent_of(registered) == allocation_of(declared),
          f'registered {extent_of(registered)!r}')
    # The same pixel buffer without the dimension argument: one attribute apart, and the
    # pair has to move together or the extent describes an allocation that was not made.
    alone = {'Arg_0': argument('EFI_GRAPHICS_OUTPUT_BLT_PIXEL *', param_name='BltBuffer'),
             'Arg_1': argument('UINTN', param_name='Attributes')}
    declared, registered = emit(alone)
    check('without one it allocates an element and registers an element',
          allocation_of(declared) == 'sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)'
          and extent_of(registered) == allocation_of(declared),
          f'allocated {allocation_of(declared)!r}, registered {extent_of(registered)!r}')

    print('\nthe blanket constant is gone from the typed registrations')
    for arg_type in ('EFI_GUID *', 'CHAR16 *', 'EFI_FONT_DISPLAY_INFO *'):
        extent = extent_of(emit({'Arg_0': argument(arg_type)})[1])
        check(f'{arg_type} is not registered as 4096', extent != '4096',
              f'got {extent!r}')

    print('\nthe two fixes compose on the member the run failed on')
    kept = harnessed(('unsigned short *', 'wchar_t *'), 'CHAR16 *')
    declared, registered = emit({'Arg_0': argument(kept.arg_type)})
    check('RequestToLock\'s VariableName is declared a CHAR16 *',
          declared and declared[0].startswith('CHAR16 * Fuzz_Arg_0 ='),
          f'{declared[:1]}')
    check('with room for a string', allocation_of(declared) == '32 * sizeof(CHAR16)')
    check('and the string\'s own extent is what is registered',
          extent_of(registered) == '32 * sizeof(CHAR16)',
          f'got {extent_of(registered)!r} -- 4096 against a 64 byte allocation hands '
          f'the sanitizer 4032 bytes of somebody else\'s heap')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
