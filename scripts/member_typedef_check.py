#!/usr/bin/env python3
"""Assert the harness generator finds a protocol member's declaration where edk2 puts it.

Five defects, one family: the reader looked in one place and the declaration was in
another. Measured by regenerating the 138 cached analyses of EVAL-1 run 43454245046 and
the four upstream refs of sweep 43704163314, before and after, and recompiling every
emitted harness.

A typedef declared in an included header. analyze.py's protocol_member_params() and
protocol_member_return() each read the member's OWN header and searched that text for
`(EFIAPI *<KIND>)(...)`. Revision 2 of a protocol includes revision 1 and re-uses its
typedefs, so the search failed two different ways. params returned None and the member was
dropped with "WARNING: <name> was not able to be harnessed!!" -- EdkiiFormBrowserEx2 read
all 6 request lines and emitted 3 Fuzz functions, and EdkiiSmmVarCheck resolved 0 of 3 and
raised the ValueError fuzz_edk2.py classifies as NO_CALL_SITES. return failed SILENTLY: it
answered its EFI_STATUS default for REGISTER_EXIT_HANDLER, which FormBrowserEx.h declares
VOID, so the call would have assigned void to Status. Both now ask _declaring_source(),
which follows #include to INCLUDE_DEPTH 2. Measured: EdkiiFormBrowserEx2 3 -> 6 targets
and FirnessHarnesses.c 91 -> 224 lines, EdkiiSmmVarCheck 0 -> 3 with rc 0.

A const-qualified buffer handed to FirnessUntrusted. The helper was declared
`VOID *Buffer`, and EFI_PCD_PROTOCOL.GetNextTokenSpace takes CONST EFI_GUID **, so the
registration discarded the qualifier. Under the production CLANGSAN toolchain that is
-Werror,-Wincompatible-pointer-types-discards-qualifiers: EfiPcd and Pcd failed to compile
on all four upstream refs of sweep 43704163314, identically, at FirnessHarnesses.c:966:22
and :1468:22. Reproduced byte for byte on the host at the same file, line and column. The
parameter is CONST VOID * now, because the helper records a base and a length and never
writes through the pointer, and because a (VOID *) cast at the call site would also
silence a genuinely wrong argument type.

A member line with a trailing comment. `TYPE NAME;` anchored straight at end-of-line does
not match `TYPE NAME; ///< doc`, and gen_protocol_inputs.py's struct_blocks() registers a
struct only when it collected a member -- so a struct whose members are ALL documented
that way collected none and was not registered at all. Measured over the request files on
three trees, eval1-57825273 (272 files / 1329 member lines), edk2-master (275 / 1342) and
eval_source/edk2 (269 / 1318): exactly two files added on each, EfiSwapAddressRange.txt
(6 members, every one with a trailing //) and EfiIpSec.txt (Process, with ///<), every
other file byte identical. analyze.py's STRUCT_MEMBER had the same anchor and the same
consequence one layer down -- no optional_params entry for the guid, so every pointer
argument of every one of its members got a NULL arm back. 20 function-pointer members in
3 headers of edk2-master, two of them the protocols now requested.

A list mutated while iterated. collect_known_constants' "fewer than 3 values" filter ran
`for arg in argument: argument.remove(arg)`, which skips alternate elements: a 1-entry list
came out empty by luck and a 2-entry list was left with ONE constant arm standing -- an
argument pinned to a single recorded value where the rule says the evidence is too thin to
pin it at all. argument.clear() now.

An enum argument nothing asked enums.json about. A member built from its header has no
call site, so the synthesised block leaves `variable` empty and a declaration-built one
puts the parameter NAME there; neither is a marker any branch of collect_known_constants
recognised. An enum typedef is not in scalable_params either, so get_directly_fuzzable
passed too and handle_optional_arguments spelled it into the call as
(EFI_PCI_IO_PROTOCOL_WIDTH){0} -- a value the fuzzer never chooses, on the one argument
that decides which accessor and which stride EFI_PCI_IO_PROTOCOL uses, which also sent
io_width_arg() to the conservative 8-byte stride for want of a variable to read. The enum
was never missing: EFI_PCI_IO_PROTOCOL_WIDTH is in the enums.json of the EfiPciIo,
EfiPciRootBridgeIo and EfiMmCpuIo campaigns of run 43454245046, with its 14 enumerators.
Measured on EfiPciIo: 7 unfuzzed Width sites -> 0, 4 conservative-stride fallbacks -> 0.

Refused, and the refusal is asserted too. Admitting a structless typedef-alias protocol
(gEfiSmmCpuIo2ProtocolGuid is EFI_MM_CPU_IO_PROTOCOL from <Protocol/MmCpuIo.h>) needs
struct_blocks to resolve across includes. 24 protocol headers on edk2-master have that
shape and 14 of them spell their GUID `#define EFI_SMM_X_GUID EFI_MM_X_GUID` -- the same
128-bit value as an MM-named sibling that already has a request file, 13 of 14 measured
requested. A second campaign would LocateProtocol the same GUID value for the same struct,
the same members and the same typedefs, for a container, a ~10-minute analysis, a firmware
build and a boot budget each. Nor would it be skipped as smm-only: presence.csv for run
43454245046 records EfiMmCpuIo,3242A9D8-CE70-4AA0-955D-5E7B140DE4D2,present.

Run: python3 scripts/member_typedef_check.py
"""

import io
import os
import re
import shutil
import sys
import tempfile
import types as pytypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

# The trees and the sweep the measurements above were taken on. A runner has none of them,
# and the assertions that read them say they were skipped rather than passing.
TREE = '/home/gl055/eval-trees/edk2-master'
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


def script_source(name):
    return io.open(os.path.join(HERE, name), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Every comment on the code asserted here quotes the defect by name: the GUID, the
    protocol, the word CONST, the depth bound. A source assertion made against the raw
    text finds its string in the paragraph explaining why the statement exists and passes
    with the statement deleted. That is the mutation this project has let through.
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
    """One definition's text, from its marker to the next top-level one.

    An absent marker answers with nothing rather than raising. A check that dies on a
    deleted anchor has reported nothing, and a mutation run cannot tell that from a catch.
    """
    try:
        start = src.index(marker)
    except ValueError:
        return ''
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Z_]+ = |@|class )', rest)
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
    from data_analysis import analyze
    import uefi_harness.headers_template as headers
    return common_types, analyze, headers


def inputs_module():
    """scripts/gen_protocol_inputs.py, loaded by path rather than imported as a package."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'gen_protocol_inputs', os.path.join(HERE, 'gen_protocol_inputs.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMMON, ANALYZE, HEADERS = generator()
GPI = inputs_module()

# Fetched by name rather than imported, so REMOVING one is a failing assertion rather than
# an ImportError at the top of the file. A check that dies before its first line of output
# has not caught anything, and nothing reading exit codes can tell that from a check that
# ran.
DECLARING_SOURCE = getattr(ANALYZE, '_declaring_source', None)
INCLUDE_ROOTS = getattr(ANALYZE, 'include_roots', None)
INCLUDE_DEPTH = getattr(ANALYZE, 'INCLUDE_DEPTH', None)
ENUM_TYPE_NAME = getattr(ANALYZE, 'enum_type_name', None)


# ---------------------------------------------------------------------------------------
# Fixtures. Every pair differs in exactly ONE attribute, so a pass cannot be explained by
# the other difference. The protocol struct text, the GUID, the member name and the
# typedef's own spelling are character for character the same in the control and in the
# subject; the only thing that moves is which FILE the typedef is written in.

TYPEDEFS = ('typedef EFI_STATUS (EFIAPI *EFI_INC_PARAMS)(\n'
            '  IN EFI_INC_PROTOCOL *This,\n'
            '  IN UINTN             Count\n'
            '  );\n'
            'typedef VOID (EFIAPI *EFI_INC_VOIDED)(\n'
            '  IN UINTN Only\n'
            '  );\n')

PROTO = '''
extern EFI_GUID  gEfiIncProtocolGuid;
typedef struct _EFI_INC_PROTOCOL EFI_INC_PROTOCOL;
%s
struct _EFI_INC_PROTOCOL {
  EFI_INC_PARAMS    Params;
  EFI_INC_VOIDED    Voided;
};
'''

HOLDERS = []


def tree(files, roots=('Include',)):
    """Write `files` into a fresh directory and register its Include roots, ONLY its own.

    include_roots is what build_guid_struct_map fills from the real tree, and a fixture
    has to put its own there or an angle-bracket include resolves against nothing. It is
    REPLACED rather than added to, because every fixture below writes the same header
    names: left to accumulate, an earlier fixture's IncBase0.h is on the search path of a
    later one, and the depth assertion passes by reading the two-hop fixture's typedefs
    out of the three-hop one. One tree at a time is also what the real walk builds.
    """
    top = tempfile.mkdtemp(prefix='membertypedef-')
    HOLDERS.append(top)
    for name, text in files.items():
        path = os.path.join(top, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        io.open(path, 'w', encoding='utf-8').write(text)
    if INCLUDE_ROOTS is not None:
        INCLUDE_ROOTS.clear()
        for root in roots:
            INCLUDE_ROOTS.add(os.path.join(top, root))
    return top


def forget(path):
    """Drop analyze.py's memo for one file, so a fixture cannot read another's text."""
    cache = getattr(ANALYZE, '_header_source', None)
    if isinstance(cache, dict):
        cache.pop(path, None)


def local_header():
    """Inc.h with both typedefs in its own text."""
    top = tree({'Include/Protocol/Inc.h': PROTO % TYPEDEFS})
    path = os.path.join(top, 'Include', 'Protocol', 'Inc.h')
    forget(path)
    return path


def included_header(hops=1, quoted=False, cycle=False):
    """Inc.h, then `hops` headers, the last of which declares the two typedefs.

    Only the chain LENGTH differs between one call and the next, so what the depth bound
    answers cannot be explained by anything else in the fixture.
    """
    spell = (lambda n: f'#include "{n}"') if quoted else \
            (lambda n: f'#include <Protocol/{n}>')
    files = {'Include/Protocol/Inc.h': PROTO % spell('IncBase0.h')}
    for hop in range(hops):
        last = hop == hops - 1
        nxt = TYPEDEFS if last else spell(f'IncBase{hop + 1}.h')
        back = '#include <Protocol/Inc.h>\n' if cycle else ''
        files[f'Include/Protocol/IncBase{hop}.h'] = back + nxt
    top = tree(files)
    path = os.path.join(top, 'Include', 'Protocol', 'Inc.h')
    for name in files:
        forget(os.path.join(top, name))
    return path


def argument(arg_type, variable='', param_name='', arg_dir='IN'):
    return [COMMON.Argument(arg_dir, arg_type, '', '', '', variable,
                            param_name=param_name)]


def collected(args, enums=(), pointer_counts=None):
    """collect_known_constants over one function, returning its surviving arg lists.

    Called through the generator's own function rather than reimplemented, so a fixture
    cannot pass by being told something the generator does not do.
    """
    enum_map = {name: COMMON.EnumDef(name, list(values), '/w/Enum.h')
                for name, values in enums}
    block = COMMON.FunctionBlock(dict(args), 'Fuzz', 'protocol', [], 'EFI_STATUS')
    # an EMPTY arguments dict, which is what initialize_data() hands it: Step 1 fills a
    # key by setdefault, so no key exists until something claims it. Seeding the keys
    # with empty lists instead makes Step 2 read argument[0] of an empty list and the
    # IndexError takes the whole check down -- a crash a mutation run reads as neither a
    # catch nor a miss
    template = COMMON.FunctionBlock({}, 'Fuzz', 'protocol', [], 'EFI_STATUS')
    out, _macros, _p, _d = ANALYZE.collect_known_constants(
        {'Fuzz': [block]}, {'Fuzz': template}, {}, {}, {}, enum_map)
    return out['Fuzz'].arguments


def main():
    raw_analyze = gen_source(os.path.join('data_analysis', 'analyze.py'))
    raw_headers = gen_source(os.path.join('uefi_harness', 'headers_template.py'))
    raw_inputs = script_source('gen_protocol_inputs.py')

    print('a member\'s typedef is found wherever the header chain declares it')
    check('analyze.py defines _declaring_source', DECLARING_SOURCE is not None,
          'the two readers below have nothing to ask and fall back to one file')
    check('and an Include root set for an angle-bracket include to resolve against',
          INCLUDE_ROOTS is not None)

    here = local_header()
    there = included_header()
    local_params = ANALYZE.protocol_member_params(here, 'EFI_INC_PROTOCOL', 'Params')
    away_params = ANALYZE.protocol_member_params(there, 'EFI_INC_PROTOCOL', 'Params')
    check('the parameter list of a member typed in its own header is read',
          local_params is not None and len(local_params) == 2,
          f'the control fixture is broken, not the fix: {local_params!r}')
    check('and the SAME list for the same member typed from an #include',
          away_params == local_params,
          f'got {away_params!r} against {local_params!r} -- the only difference between '
          f'the two fixtures is which file the typedef is written in')

    local_ret = ANALYZE.protocol_member_return(here, 'EFI_INC_PROTOCOL', 'Voided')
    away_ret = ANALYZE.protocol_member_return(there, 'EFI_INC_PROTOCOL', 'Voided')
    check('a member declared VOID in its own header returns VOID',
          local_ret == 'VOID', f'got {local_ret!r}')
    check('and VOID, not the EFI_STATUS default, when declared from an #include',
          away_ret == 'VOID',
          f'got {away_ret!r} -- this was the silent half: REGISTER_EXIT_HANDLER is VOID '
          f'and the call assigned it to Status')

    check('a quoted include resolves against the including header\'s own directory',
          ANALYZE.protocol_member_params(included_header(quoted=True),
                                         'EFI_INC_PROTOCOL', 'Params') == local_params)
    check('a pair of headers that include each other terminates',
          ANALYZE.protocol_member_params(included_header(cycle=True),
                                         'EFI_INC_PROTOCOL', 'Params') == local_params,
          'the include guards make the cycle legal and common, so the walk has to end '
          'on it rather than spend the depth budget')
    check('the bound is a bound: two hops resolve',
          ANALYZE.protocol_member_params(included_header(hops=2),
                                         'EFI_INC_PROTOCOL', 'Params') == local_params)
    check('and three do not',
          ANALYZE.protocol_member_params(included_header(hops=3),
                                         'EFI_INC_PROTOCOL', 'Params') is None,
          'an unbounded closure keeps growing and every extra header read is another '
          'chance to match a same-named typedef from somewhere unrelated')
    check('the bound is the measured 2', INCLUDE_DEPTH == 2, f'got {INCLUDE_DEPTH!r}')

    orphan = tree({'Include/Protocol/Orphan.h':
                   PROTO % '#include <Protocol/Missing.h>'})
    orphan_h = os.path.join(orphan, 'Include', 'Protocol', 'Orphan.h')
    forget(orphan_h)
    check('an unresolvable typedef still answers None rather than raising',
          ANALYZE.protocol_member_params(orphan_h, 'EFI_INC_PROTOCOL', 'Params') is None)
    check('and the return default is still EFI_STATUS',
          ANALYZE.protocol_member_return(orphan_h, 'EFI_INC_PROTOCOL',
                                         'Voided') == 'EFI_STATUS')

    returns = code(body(raw_analyze, 'def protocol_member_return('))
    params = code(body(raw_analyze, 'def protocol_member_params('))
    check('both readers ask _declaring_source, not the one file they have open',
          '_declaring_source(' in returns and '_declaring_source(' in params,
          'one of the two still reads only the member\'s own header')
    check('and neither opens the header a second time, past the memo',
          'open(header_path' not in returns and 'open(header_path' not in params,
          'header_source() memoises; a direct open re-reads a file read 200 times')
    check('the EFI_STATUS default is no longer silent',
          'WARNING' in returns and 'EFI_STATUS' in returns,
          'a member whose typedef is nowhere in scope was typed EFI_STATUS with nothing '
          'in any log saying the typedef had not been found')
    check('and it is said once per member, not once per read',
          '_unresolved_member_kinds' in returns,
          'the header is read for every requested member; one PeCoff scan made 1188 '
          'reports out of one defect')

    print('\na const buffer can be declared untrusted')
    emitted = '\n'.join(HEADERS.harness_header([], {}))
    check('the emitted FirnessUntrusted takes a CONST VOID *',
          'FirnessUntrusted(CONST VOID *Buffer' in emitted,
          'EFI_PCD_PROTOCOL.GetNextTokenSpace takes CONST EFI_GUID **, and registering '
          'it discarded the qualifier: -Werror on the production toolchain')
    check('and still records a base and a length through it',
          'AsanRegisterUntrusted((UINT64)(UINTN)Buffer' in emitted,
          'a signature nothing registers through compiles and reports nothing')
    check('the declaration is not a (VOID *) cast at the call site',
          'FirnessUntrusted((VOID *)' not in
          code(gen_source(os.path.join('uefi_harness', 'harnesses_template.py'))),
          'a cast there also silences a genuinely wrong argument type, and the extent '
          'beside it is computed')

    print('\na member documented with a trailing comment is still a member')
    plain = ('struct _EFI_DOC_PROTOCOL {\n'
             '  EFI_DOC_ONE    One;\n'
             '  EFI_DOC_TWO    Two;\n'
             '};\n')
    noted = ('struct _EFI_DOC_PROTOCOL {\n'
             '  EFI_DOC_ONE    One; ///< the first\n'
             '  EFI_DOC_TWO    Two; // the second\n'
             '};\n')
    pointed = ('struct _EFI_DOC_PROTOCOL {\n'
               '  EFI_DOC_ONE    *One; ///< the first\n'
               '};\n')
    want = GPI.struct_blocks(plain).get('EFIDOCPROTOCOL')
    check('the control struct registers both of its members',
          want == [('EFI_DOC_ONE', 'One'), ('EFI_DOC_TWO', 'Two')], f'{want!r}')
    check('and the same struct with every member documented registers the same two',
          GPI.struct_blocks(noted).get('EFIDOCPROTOCOL') == want,
          'struct_blocks registers a struct only when it collected a member, so one '
          '///< used to cost the whole struct -- not the member')
    check('a POINTER member still does not match, documented or not',
          GPI.struct_blocks(pointed).get('EFIDOCPROTOCOL') is None,
          'the nested walk descends only into members held by value; a pointer member '
          'is a separate object the protocol may leave NULL')
    check('and the pattern is still anchored at end of line',
          occurrences(code(raw_inputs), r"\s*;'") >= 1 and '$')
    bad = GPI.struct_blocks('struct _EFI_DOC_PROTOCOL {\n'
                            '  EFI_DOC_ONE One, Two;\n};\n')
    check('two declarators on one line are still not two members',
          bad.get('EFIDOCPROTOCOL') is None, f'{bad!r}')

    documented = ('extern EFI_GUID  gEfiDocProtocolGuid;\n'
                  'typedef EFI_STATUS (EFIAPI *EFI_DOC_ONE)(\n'
                  '  IN VOID  *Context OPTIONAL\n'
                  '  );\n'
                  'struct _EFI_DOC_PROTOCOL {\n'
                  '  EFI_DOC_ONE    One; ///< the only one\n'
                  '};\n')
    top = tree({'MdePkg/Include/Protocol/Doc.h': documented}, roots=())
    ANALYZE.guid_struct_map.clear()
    ANALYZE.optional_params.clear()
    ANALYZE.build_guid_struct_map(top)
    optional = ANALYZE.optional_params.get('gEfiDocProtocolGuid', {})
    check('a documented member still carries its OPTIONAL markers into optional_params',
          optional.get('One') == [('Context', True)], f'{optional!r}')

    print('\nthe "fewer than 3 values" filter empties the list it is given')
    one = collected({'Arg_0': argument('UINTN', '__CONSTANT_INT__')})
    two = collected({'Arg_0': argument('UINTN', '__CONSTANT_INT__') +
                     argument('UINTN', '__CONSTANT_INT__')})
    check('a 1-entry constant list comes out empty', one.get('Arg_0') == [],
          f'{one!r}')
    check('and so does a 2-entry one',
          two.get('Arg_0') == [],
          f'got {two.get("Arg_0")!r} -- "for arg in argument: argument.remove(arg)" '
          f'skips alternate elements and leaves one arm pinned to a recorded value')
    filt = code(body(raw_analyze, 'def collect_known_constants('))
    check('by clearing, not by removing while iterating',
          'argument.clear()' in filt and 'argument.remove(' not in filt,
          'the removal was the defect, not the rule')

    print('\nan enum argument is fuzzed over its enumerators')
    width = ('EFI_MM_IO_WIDTH', ('MM_IO_UINT8', 'MM_IO_UINT16'))
    other = ('EFI_IO_WIDTH', ('IO_WIDTH_ONE',))
    check('enum_type_name answers the enum an argument\'s own type names',
          ENUM_TYPE_NAME is not None and ENUM_TYPE_NAME(
              'EFI_MM_IO_WIDTH', {width[0]: COMMON.EnumDef(*width, '/w/E.h'),
                                  other[0]: COMMON.EnumDef(*other, '/w/E.h')},
              {}, {}) == 'EFI_MM_IO_WIDTH')
    check('and nothing for a type no enum is named for',
          ENUM_TYPE_NAME('EFI_MM_IO_WIDTH', {other[0]: COMMON.EnumDef(*other, '/w/E.h')},
                         {}, {}) == '')
    # The two substring directions, each with a fixture that differs from the control in
    # the enum's NAME and nothing else. find_enum() above tests `arg_type in enum_name`,
    # which is how a type that is a PREFIX of another enum takes that enum's enumerators.
    longer = {'EFI_DOC_WIDTH_EXTENDED': COMMON.EnumDef('EFI_DOC_WIDTH_EXTENDED',
                                                       ['DOC_EXT_ONE'], '/w/E.h')}
    shorter = {'DOC_WIDTH': COMMON.EnumDef('DOC_WIDTH', ['DOC_ONE'], '/w/E.h')}
    check('a type that is a prefix of an enum\'s name does not take that enum',
          ENUM_TYPE_NAME('EFI_DOC_WIDTH', longer, {}, {}) == '',
          'EFI_DOC_WIDTH_EXTENDED\'s enumerators are not the ones an EFI_DOC_WIDTH '
          'parameter accepts, and the harness would pass one of them')
    check('nor does a type an enum\'s name is a substring of',
          ENUM_TYPE_NAME('EFI_DOC_WIDTH', shorter, {}, {}) == '')
    check('while the exactly-named enum is still answered',
          ENUM_TYPE_NAME('EFI_DOC_WIDTH',
                         dict(longer, EFI_DOC_WIDTH=COMMON.EnumDef(
                             'EFI_DOC_WIDTH', ['DOC_ONE'], '/w/E.h')), {},
                         {}) == 'EFI_DOC_WIDTH',
          'the control: the only difference from the two fixtures above is that an enum '
          'of that exact name exists')

    synth = collected({'Arg_0': argument('EFI_MM_IO_WIDTH')}, enums=[width, other])
    named = collected({'Arg_0': argument('EFI_MM_IO_WIDTH', 'Width', 'Width')},
                      enums=[width, other])
    marked = collected({'Arg_0': argument('EFI_MM_IO_WIDTH', '__PROTOCOL__')},
                       enums=[width, other])
    check('a synthesised block\'s enum argument becomes an __ENUM_ARG__',
          [a.variable for a in synth.get('Arg_0', [])] == ['__ENUM_ARG__'],
          f'{[(a.variable, a.usage) for a in synth.get("Arg_0", [])]!r} -- otherwise '
          f'handle_optional_arguments spells (EFI_MM_IO_WIDTH){{0}} into the call')
    check('and carries the enum\'s name as its usage',
          [a.usage for a in synth.get('Arg_0', [])] == ['EFI_MM_IO_WIDTH'])
    check('a declaration-built block\'s enum argument does too, parameter name and all',
          [a.variable for a in named.get('Arg_0', [])] == ['__ENUM_ARG__'],
          'PollIo and PollMem are the same protocol, the same typedef and the same '
          'Width; only PollIo\'s block came from a declaration, so variable held "Width"')
    check('a marker the generator set is left exactly as it was',
          [a.variable for a in marked.get('Arg_0', [])] == ['__PROTOCOL__'] or
          marked.get('Arg_0') == [],
          f'{[a.variable for a in marked.get("Arg_0", [])]!r}')
    branch = code(body(raw_analyze, 'def collect_known_constants('))
    check('the enum recovery is the LAST arm of the chain',
          before(branch, 'potential_outputs) > 1', 'enum_type_name('),
          'an argument an earlier branch recognises has to be classified as it was: '
          'ahead of the potential-outputs arm this steals an enum argument that has '
          'more than one recorded output and gives it one arm instead of several')
    check('and after the constant arms, which keep a recorded constant a constant',
          before(branch, '__CONSTANT_SIZEOF__', 'enum_type_name('))
    check('and it is gated on the generator\'s own markers, not on emptiness',
          "variable.startswith('__')" in branch,
          'an emptiness test fixed PollMem and left PollIo spelling '
          '(EFI_PCI_IO_PROTOCOL_WIDTH){0} into the call')

    print('\nthe measurements are recorded where the next reader will look')
    notes = raw_analyze + raw_headers + raw_inputs
    check('the include fix gives the targets it bought, on the campaigns it bought them on',
          'EdkiiFormBrowserEx2' in notes and 'EdkiiSmmVarCheck' in notes,
          'a fix with no measurement beside it is a change nobody can re-check')
    check('the const fix names the toolchain diagnostic and the two refs it blocked',
          'discards-qualifiers' in raw_headers and 'EfiPcd and Pcd' in raw_headers,
          'without the diagnostic\'s name the next reader cannot tell which build it was')
    check('and the line the build failed on',
          '966' in raw_headers and '1468' in raw_headers)
    check('the member-line fix names both protocols it admitted and their member counts',
          'SwapAddressRange' in notes and 'IpSec' in notes and '6 members' in notes,
          'the set of request files is what this one may not otherwise move')
    check('the list fix says which length was left standing',
          '2-entry list' in raw_analyze and 'alternate' in raw_analyze)
    check('the enum fix names the argument and the stride it also cost',
          'EFI_PCI_IO_PROTOCOL_WIDTH' in raw_analyze and 'stride' in raw_analyze)
    check('the refusal names the protocol and the header its struct is in',
          'gEfiSmmCpuIo2ProtocolGuid' in raw_inputs and
          'EFI_MM_CPU_IO_PROTOCOL' in raw_inputs)
    check('and rests on a census, not a preference: how many, and how many duplicate',
          '24 have a GUID' in raw_inputs and '14 of the 24' in raw_inputs,
          'a refusal with no measurement beside it is the next reader\'s rewrite')
    check('and it kills the smm-only reason with the census row that disproves it',
          '3242A9D8-CE70-4AA0-955D-5E7B140DE4D2,present' in raw_inputs,
          'the reason that looks obvious is the wrong one, so it has to be written down '
          'as wrong or it will be given again')
    check('and it names the narrower change it is NOT making, with its size',
          'nine protocols' in raw_inputs and 'GUID macro is not a #define' in raw_inputs,
          'a refusal that does not say what would be defensible reads as "never"')

    print('\nagainst the real trees')
    swap = os.path.join(TREE, 'MdeModulePkg', 'Include', 'Protocol',
                        'SwapAddressRange.h')
    if os.path.isfile(swap):
        text = io.open(swap, encoding='utf-8', errors='ignore').read()
        got = GPI.struct_blocks(text).get('EFISWAPADDRESSRANGEPROTOCOL') or []
        check('EFI_SWAP_ADDRESS_RANGE_PROTOCOL yields its 6 members from the real header',
              len(got) == 6, f'{len(got)} member(s): {got!r}')
        ipsec = os.path.join(TREE, 'MdePkg', 'Include', 'Protocol', 'IpSec.h')
        got = GPI.struct_blocks(io.open(ipsec, encoding='utf-8', errors='ignore').read())
        members = got.get('EFIIPSECPROTOCOL') or []
        # every member the pattern matches, not only the callable ones: a member whose
        # type is another struct is the way into the nested surface, so the one callable
        # member is asserted by name rather than by the list being one long
        check('and EFI_IPSEC_PROTOCOL yields Process',
              ('EFI_IPSEC_PROCESS', 'Process') in members, f'{members!r}')
        check('whose typedef is the only callable one of the three',
              [name for kind, name in members
               if 'EFI_IPSEC' in kind] == ['Process'], f'{members!r}')
        browser = os.path.join(TREE, 'MdeModulePkg', 'Include', 'Protocol',
                               'FormBrowserEx2.h')
        ANALYZE.guid_struct_map.clear()
        if INCLUDE_ROOTS is not None:
            INCLUDE_ROOTS.clear()
        ANALYZE.build_guid_struct_map(TREE)
        forget(browser)
        kind = 'REGISTER_EXIT_HANDLER'
        check('REGISTER_EXIT_HANDLER returns VOID, read through FormBrowserEx2.h',
              ANALYZE.protocol_member_return(
                  browser, 'EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL',
                  'RegiserExitHandler', kind) == 'VOID',
              'FormBrowserEx2.h names it and <Protocol/FormBrowserEx.h> declares it')
        check('and SetScope has a parameter list at all',
              ANALYZE.protocol_member_params(
                  browser, 'EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL', 'SetScope')
              is not None,
              'None here is the "was not able to be harnessed" warning')
    else:
        print(f'  [skip] {TREE} is not on this host')

    presence = os.path.join(SWEEP, 'presence.csv')
    if os.path.isfile(presence):
        rows = io.open(presence, encoding='utf-8', errors='ignore').read()
        check('the alias the refusal names is present, not smm-only',
              re.search(r'^EfiMmCpuIo,[^,]+,present$', rows, re.M) is not None,
              'the refusal rests on a duplicate campaign being RUN, not skipped')
    else:
        print(f'  [skip] {presence} is not on this host')

    for holder in HOLDERS:
        shutil.rmtree(holder, ignore_errors=True)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
