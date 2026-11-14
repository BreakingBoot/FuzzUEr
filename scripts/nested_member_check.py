#!/usr/bin/env python3
"""Assert a protocol member reached through a nested struct is requested, by its leaf name.

gen_protocol_inputs.py collected a protocol's DIRECT function-pointer members, so a member
held one level down was never requested, never harnessed and never fuzzed, with nothing in
any log saying so. Measured over the request files the script emits for the EVAL-1 tree
(271 protocols, 1237 member lines, reachability computed by walking each protocol's struct
to depth 3 through by-value members only): 8 members across 4 protocols and 22 distinct
access paths. EFI_PCI_IO_PROTOCOL and EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL hold their memory,
I/O and config accessors in EFI_PCI_IO_PROTOCOL_ACCESS-style sub-structs, so none of
Mem/Io/Pci Read or Write was ever a target -- the (Width, Address, Count, Buffer) shape
that produced 22 memory-safety reports on EFI_CPU_IO2_PROTOCOL, which escaped only because
its struct has no direct function-pointer member at all and so fell through to the
whole-header fallback. EFI_DEVICE_IO_PROTOCOL and EFI_ISA_IO_PROTOCOL are the other two.

The spelling is the LEAF name, `gEfiPciIoProtocolGuid:Read`, not `Mem.Read`, because that
is the convention already in use end to end: load_functions() splits a request line on the
colon and harness_match() compares the right-hand side to the callee name the analysis
recorded, and a call site writes PciIo->Mem.Read(...) which the analysis records as "Read".
The access path is then recovered by the generator's own protocol_member_paths(). A dotted
request line would arrive as the function name "Mem.Read", match no recorded callee, and
drop the member just as silently as before.

What is asserted here is that a nested member is requested; that the spelling is the one
the generator's own parser and matcher already read; that a direct member and a flat
protocol come out byte for byte as they did; that the walk terminates on a struct that
reaches itself and on a cycle of two; that a pointer, a union and a scalar member are not
walked into; and that the protocol SET is untouched -- only which members a protocol asks
for may change, and a request for a protocol nobody chose is a container and a boot budget.

Run: python3 scripts/nested_member_check.py
"""

import ast
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from typing import Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')
sys.path.insert(0, GEN)

# The campaign whose artifacts carry the convention this check pins: its request file names
# the leaf, its call-database records the leaf, and its generated harness writes the path.
# Absent on a runner, where the assertions that read it are skipped and said to be skipped.
SWEEP = '/home/gl055/fuzzuer-eval1/43454245046/campaigns/EfiCpuIo2'
TREE = '/home/gl055/eval-trees/eval1_edk2/MdePkg/Include/Protocol'

# Imported so that DELETING either is a failing assertion rather than an ImportError at the
# top of the file. A check that dies before its first line of output has caught nothing,
# and nothing reading exit codes can tell that from a check that ran clean.
try:
    import uefi_harness.harnesses_template as uefi_harnesses
except ImportError:
    uefi_harnesses = None
try:
    from common.types import TypeInfo, FieldInfo
except ImportError:
    TypeInfo = FieldInfo = None

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Every comment in the code under test explains this defect by name and quotes the very
    spellings being matched on -- `Mem.Read`, `ProtocolVariable->Mem.Read`, the names of
    the three bounds -- so a source assertion made against the raw text finds its string
    in the paragraph that says why the statement exists and passes with the statement
    deleted. That mutation is the one this project has let through before.
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
        if not line.strip().startswith('#'):
            kept.append(line.split('  #')[0])
    return '\n'.join(kept)


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not.

    A bare .index() on an anchor a mutation deleted raises, and a check that dies on its
    own traceback has not caught anything -- it has stopped reporting.
    """
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def lift(names):
    """Run the named top-level definitions out of analyze.py without importing it.

    analyze.py imports fuzzywuzzy at module scope, which is not installed on a runner and
    has nothing to do with how a request line is spelled. This compiles the real source of
    the real definitions, so the check still fails when they change.
    """
    path = os.path.join(GEN, 'data_analysis', 'analyze.py')
    tree = ast.parse(io.open(path, encoding='utf-8').read())

    def names_of(node):
        if isinstance(node, ast.FunctionDef):
            return [node.name]
        if isinstance(node, ast.Assign):
            return [t.id for t in node.targets if getattr(t, 'id', None)]
        return []

    want = [node for node in tree.body if set(names_of(node)) & set(names)]
    have = {n for node in want for n in names_of(node)}
    missing = [n for n in names if n not in have]
    if missing:
        raise SystemExit(f'analyze.py no longer defines: {", ".join(missing)}')
    space = {'os': os, 're': re, 'json': json, 'print': print, 'open': open,
             'defaultdict': defaultdict, 'Dict': Dict, 'List': List, 'Tuple': Tuple}
    exec(compile(ast.Module(body=want, type_ignores=[]), 'analyze.py', 'exec'), space)
    return space


# ---------------------------------------------------------------------------------------
# Fixtures. Each pair differs in exactly ONE attribute, so a pass cannot be explained by
# the other difference: the pointer header is the by-value header with a single `*` added,
# and the union header is the struct header with one keyword changed.

FLAT = '''
extern EFI_GUID  gEfiFlatProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_FLAT_ONE)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_FLAT_TWO)(VOID);
struct _EFI_FLAT_PROTOCOL {
  EFI_FLAT_ONE    First;
  UINT64          RomSize;
  EFI_FLAT_TWO    Second;
};
'''

# the EFI_PCI_IO_PROTOCOL shape: a direct member, three by-value sub-structs two of which
# are the same type and one of which is a different one declaring the same leaf names, and
# a direct member after them
NESTED = '''
extern EFI_GUID  gEfiNestProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_NEST_POLL)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_NEST_IO_MEM)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_NEST_CONFIG)(VOID);
typedef struct {
  EFI_NEST_IO_MEM    Read;
  EFI_NEST_IO_MEM    Write;
} EFI_NEST_PROTOCOL_ACCESS;
typedef struct {
  EFI_NEST_CONFIG    Read;
  EFI_NEST_CONFIG    Write;
} EFI_NEST_PROTOCOL_CONFIG_ACCESS;
struct _EFI_NEST_PROTOCOL {
  EFI_NEST_POLL                      PollMem;
  EFI_NEST_PROTOCOL_ACCESS           Mem;
  EFI_NEST_PROTOCOL_ACCESS           Io;
  EFI_NEST_PROTOCOL_CONFIG_ACCESS    Pci;
  EFI_NEST_POLL                      Flush;
};
'''

# a struct the protocol does not reach at all. EFI_DHCP4_CONFIG_DATA.Dhcp4Callback is a
# callback the caller supplies, not an entry point the harness may call, and widening the
# walk must not start harvesting those
UNREACHED = '''
extern EFI_GUID  gEfiAsideProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_ASIDE_ONE)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_ASIDE_CALLBACK)(VOID);
typedef struct {
  EFI_ASIDE_CALLBACK    AsideCallback;
} EFI_ASIDE_CONFIG_DATA;
struct _EFI_ASIDE_PROTOCOL {
  EFI_ASIDE_ONE    Configure;
};
'''

_PTR_SHAPE = '''
extern EFI_GUID  gEfiPtrProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_PTR_ONE)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_PTR_DEEP)(VOID);
typedef struct {
  EFI_PTR_DEEP    Deep;
} EFI_PTR_SUB;
struct _EFI_PTR_PROTOCOL {
  EFI_PTR_ONE    First;
  EFI_PTR_SUB %sSub;
};
'''
BY_VALUE = _PTR_SHAPE % ''
BY_POINTER = _PTR_SHAPE % '*'

_UNI_SHAPE = '''
extern EFI_GUID  gEfiUniProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_UNI_ONE)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_UNI_PICKED)(VOID);
typedef %s {
  EFI_UNI_PICKED    Picked;
} EFI_UNI_SUB;
struct _EFI_UNI_PROTOCOL {
  EFI_UNI_ONE    First;
  EFI_UNI_SUB    Sub;
};
'''
AS_STRUCT = _UNI_SHAPE % 'struct'
AS_UNION = _UNI_SHAPE % 'union'

# the protocol names itself as a by-value member. C forbids it; the scan is textual and
# will walk whatever a header says, so the walk has to refuse it rather than rely on the
# compiler having done so
SELF = '''
extern EFI_GUID  gEfiSelfProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_SELF_ONE)(VOID);
struct _EFI_SELF_PROTOCOL {
  EFI_SELF_ONE         First;
  EFI_SELF_PROTOCOL    Again;
};
'''

# two structs that reach each other, which the depth budget alone would not stop inside
# three levels
CYCLE = '''
extern EFI_GUID  gEfiCycProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_CYC_ONE)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_CYC_IN_A)(VOID);
typedef EFI_STATUS (EFIAPI *EFI_CYC_IN_B)(VOID);
typedef struct {
  EFI_CYC_IN_A    InA;
  EFI_CYC_B       Bee;
} EFI_CYC_A;
typedef struct {
  EFI_CYC_IN_B    InB;
  EFI_CYC_A       Ay;
} EFI_CYC_B;
struct _EFI_CYC_PROTOCOL {
  EFI_CYC_ONE    Top;
  EFI_CYC_A      Ay;
};
'''

# a chain one level deeper than the budget, with a differently named member at each level
DEEP = '''
extern EFI_GUID  gEfiDeepProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_DEEP_FN)(VOID);
typedef struct {
  EFI_DEEP_FN    AtFour;
} EFI_DEEP_L4;
typedef struct {
  EFI_DEEP_FN    AtThree;
  EFI_DEEP_L4    Four;
} EFI_DEEP_L3;
typedef struct {
  EFI_DEEP_FN    AtTwo;
  EFI_DEEP_L3    Three;
} EFI_DEEP_L2;
typedef struct {
  EFI_DEEP_FN    AtOne;
  EFI_DEEP_L2    Two;
} EFI_DEEP_L1;
struct _EFI_DEEP_PROTOCOL {
  EFI_DEEP_FN    AtTop;
  EFI_DEEP_L1    One;
};
'''

# the EFI_CPU_IO2_PROTOCOL shape: no direct function-pointer member at all
ONLY_NESTED = '''
extern EFI_GUID  gEfiOnlyNestedProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_ONLY_IO_MEM)(VOID);
typedef struct {
  EFI_ONLY_IO_MEM    Read;
  EFI_ONLY_IO_MEM    Write;
} EFI_ONLY_NESTED_PROTOCOL_ACCESS;
struct _EFI_ONLY_NESTED_PROTOCOL {
  EFI_ONLY_NESTED_PROTOCOL_ACCESS    Mem;
  EFI_ONLY_NESTED_PROTOCOL_ACCESS    Io;
};
'''

FIXTURES = {'Flat.h': FLAT, 'Nest.h': NESTED, 'Aside.h': UNREACHED,
            'Ptr.h': BY_POINTER, 'Uni.h': AS_UNION, 'Self.h': SELF,
            'Cyc.h': CYCLE, 'Deep.h': DEEP, 'OnlyNested.h': ONLY_NESTED}


class quiet:
    """write_inputs reports what it wrote on stdout; here that is not the report."""

    def __enter__(self):
        self.saved = sys.stdout
        sys.stdout = io.StringIO()

    def __exit__(self, *_):
        sys.stdout = self.saved


def members(gpi, src, guid):
    return gpi.struct_members(src, guid, set(gpi.FPTYPE_RE.findall(src)))


def direct_only(gpi, src, guid):
    """What the pre-fix walk produced: the protocol's direct members and nothing below."""
    blocks = gpi.struct_blocks(src)
    want = gpi.guid_struct_key(guid)
    return gpi.expand_members(blocks.get(want, []), blocks,
                              set(gpi.FPTYPE_RE.findall(src)), 0, (want,))


def written(gpi, headers, out):
    """The request files scan_roots + write_inputs produce for a set of fixtures."""
    holder = tempfile.mkdtemp()
    for name, text in headers.items():
        io.open(os.path.join(holder, name), 'w').write(text)
    with quiet():
        protocols = gpi.scan_roots([holder])
        gpi.write_inputs(protocols, out, 1, 0)
    return sorted(os.listdir(out))


def main():
    gpi = load('gen_protocol_inputs')
    gsrc = code(source('gen_protocol_inputs'))

    print('a member held in a nested struct is requested, by its leaf name')
    nest = members(gpi, NESTED, 'gEfiNestProtocolGuid')
    check('the nested leaf Read is requested', 'Read' in nest, f'{nest}')
    check('and Write', 'Write' in nest, f'{nest}')
    check('as the leaf name, not as an access path',
          not any('.' in m for m in nest),
          f'{nest} -- load_functions would hand harness_match "Mem.Read", which equals '
          f'no callee the analysis ever recorded')
    check('one request line per leaf however many paths reach it',
          nest.count('Read') == 1 and nest.count('Write') == 1,
          f'{nest} -- Mem, Io and Pci all declare Read; the generator expands the paths')
    check('the direct members are still there and still in declaration order',
          [m for m in nest if m in ('PollMem', 'Flush')] == ['PollMem', 'Flush'],
          f'{nest}')
    check('and the nested ones take the place the sub-struct is declared at',
          nest == ['PollMem', 'Read', 'Write', 'Flush'], f'{nest}')
    check('a struct the protocol does not reach is still not harvested',
          members(gpi, UNREACHED, 'gEfiAsideProtocolGuid') == ['Configure'],
          'EFI_DHCP4_CONFIG_DATA.Dhcp4Callback is a callback the caller supplies, not an '
          'entry point, and widening the walk must not start collecting those')

    print('\nthe spelling is the one the generator already reads')
    space = lift(['load_functions'])
    holder = tempfile.TemporaryDirectory()
    request = os.path.join(holder.name, 'EfiNest.txt')
    with quiet():
        gpi.write_inputs({'gEfiNestProtocolGuid': ('Nest.h', nest)}, holder.name, 1, 0)
    parsed = space['load_functions'](request)['Protocols']
    check('the request file firness reads back names the leaf and the guid',
          ('Read', 'gEfiNestProtocolGuid') in parsed, f'{parsed}')
    check('no entry it reads back carries a dotted path',
          all('.' not in name for name, _guid in parsed), f'{parsed}')
    asrc = code(io.open(os.path.join(GEN, 'data_analysis', 'analyze.py'),
                        encoding='utf-8').read())
    check('harness_match still decides by equality with the recorded callee name',
          'if function != name:' in asrc,
          'if this changed, the leaf spelling may no longer be the one that matches')
    if uefi_harnesses is not None and TypeInfo is not None:
        types = {
            'EFI_NEST_PROTOCOL': TypeInfo('EFI_NEST_PROTOCOL', [
                FieldInfo('PollMem', 'EFI_NEST_POLL'),
                FieldInfo('Mem', 'EFI_NEST_PROTOCOL_ACCESS'),
                FieldInfo('Io', 'EFI_NEST_PROTOCOL_ACCESS'),
                FieldInfo('Pci', 'EFI_NEST_PROTOCOL_CONFIG_ACCESS')], ''),
            'EFI_NEST_PROTOCOL_ACCESS': TypeInfo('EFI_NEST_PROTOCOL_ACCESS', [
                FieldInfo('Read', 'EFI_NEST_IO_MEM'),
                FieldInfo('Write', 'EFI_NEST_IO_MEM')], ''),
            'EFI_NEST_PROTOCOL_CONFIG_ACCESS': TypeInfo(
                'EFI_NEST_PROTOCOL_CONFIG_ACCESS', [
                    FieldInfo('Read', 'EFI_NEST_CONFIG'),
                    FieldInfo('Write', 'EFI_NEST_CONFIG')], ''),
        }
        paths = uefi_harnesses.protocol_member_paths('EFI_NEST_PROTOCOL *', 'Read', types)
        check('the generator recovers the access path from the leaf, so we must not emit '
              'one', sorted(p for p, _k in paths) == ['Io.Read', 'Mem.Read', 'Pci.Read'],
              f'{paths}')
        check('and it walks to the same depth this script requests to',
              uefi_harnesses.protocol_member_paths.__defaults__[0] == gpi.NEST_DEPTH,
              f'generator {uefi_harnesses.protocol_member_paths.__defaults__} '
              f'vs NEST_DEPTH {gpi.NEST_DEPTH} -- requesting a member the generator '
              f'cannot resolve a path for only buys a dropped target')
    else:
        print('  [skip] the generator templates did not import')

    if os.path.isdir(SWEEP):
        print('\nand it is the spelling the campaign that already works used')
        req = os.path.join(SWEEP, 'EfiCpuIo2.txt')
        harness = os.path.join(SWEEP, 'Firness', 'FirnessHarnesses.c')
        db = os.path.join(SWEEP, 'call-database.json')
        if os.path.isfile(db):
            recorded = {e.get('Function') for e in json.load(open(db)) or []}
            check('the analysis recorded the callee as the bare leaf',
                  'Read' in recorded and not any('.' in (f or '') for f in recorded),
                  f'{sorted(recorded)[:6]}')
        if os.path.isfile(harness):
            text = io.open(harness, encoding='utf-8', errors='ignore').read()
            check('while the harness it generated writes the nested path itself',
                  'ProtocolVariable->Mem.Read' in text,
                  'the path is the generator\'s output, not the request file\'s input')
        if os.path.isfile(req):
            check('and the request file that produced it named only the leaf',
                  ':Read' in io.open(req).read() and ':Mem.Read' not in io.open(req).read())
    else:
        print(f'\n  [skip] {SWEEP} is not on this host')

    print('\na flat protocol comes out exactly as it did')
    flat = members(gpi, FLAT, 'gEfiFlatProtocolGuid')
    check('its member list is its direct members, in order',
          flat == ['First', 'Second'], f'{flat}')
    check('and is identical to what the direct-only walk gives',
          flat == direct_only(gpi, FLAT, 'gEfiFlatProtocolGuid'), f'{flat}')
    check('a non-function-pointer member is still not a member',
          'RomSize' not in flat, f'{flat}')
    check('a protocol with no nested member is byte-identical in the file too',
          _file_of(gpi, FLAT, 'gEfiFlatProtocolGuid', 'Flat.h')
          == _file_of(gpi, FLAT, 'gEfiFlatProtocolGuid', 'Flat.h', depth=0),
          'the file, not just the list -- the header comment and the guid prefix are in it')

    print('\nthe walk terminates, and says what bounds it')
    self_members = members(gpi, SELF, 'gEfiSelfProtocolGuid')
    check('a struct that names itself terminates', self_members == ['First'],
          f'{self_members}')
    cyc = members(gpi, CYCLE, 'gEfiCycProtocolGuid')
    check('a cycle of two terminates', cyc == ['Top', 'InA', 'InB'], f'{cyc}')
    deep = members(gpi, DEEP, 'gEfiDeepProtocolGuid')
    check('a member three levels down is reached',
          deep == ['AtTop', 'AtOne', 'AtTwo', 'AtThree'], f'{deep}')
    check('one four levels down is not, because the generator cannot path to it',
          'AtFour' not in deep, f'{deep}')
    check('the depth is a named constant, not a literal in the walk',
          'depth=NEST_DEPTH' in gsrc and re.search(r'^NEST_DEPTH = \d+$', gsrc, re.M),
          'a literal is a number the next reader cannot tie to the generator\'s')
    check('the walk carries the structs already on the path',
          'seen' in gsrc and 'in seen' in gsrc,
          'the depth budget alone does not stop a cycle of two inside three levels')
    check('and the protocol\'s own struct is on it before the walk starts',
          before(gsrc, 'seen=(want,)', 'def scan_header'),
          'otherwise a self-reference is refused one level in rather than at the first '
          'step; absent entirely if the argument is gone')

    print('\na member that is not a by-value struct is not walked into')
    value = members(gpi, BY_VALUE, 'gEfiPtrProtocolGuid')
    pointer = members(gpi, BY_POINTER, 'gEfiPtrProtocolGuid')
    check('the by-value control IS walked into', value == ['First', 'Deep'], f'{value}')
    check('the same header with one * added is not',
          pointer == ['First'],
          f'{pointer} -- a pointer member is a separate object the protocol may leave '
          f'NULL, so a function behind one is not this protocol\'s surface')
    as_struct = members(gpi, AS_STRUCT, 'gEfiUniProtocolGuid')
    as_union = members(gpi, AS_UNION, 'gEfiUniProtocolGuid')
    check('the struct control IS walked into', as_struct == ['First', 'Picked'],
          f'{as_struct}')
    check('the same header with the keyword changed to union is not',
          as_union == ['First'], f'{as_union}')
    if os.path.isfile(os.path.join(TREE, 'PciRootBridgeIo.h')):
        real = io.open(os.path.join(TREE, 'PciRootBridgeIo.h'),
                       encoding='utf-8', errors='ignore').read()
        got = members(gpi, real, 'gEfiPciRootBridgeIoProtocolGuid')
        check('on the real header the nested accessors are requested',
              'Read' in got and 'Write' in got, f'{got}')
        check('and a typedef\'d pointer member written without a star is not walked into',
              'ParentHandle' not in got,
              f'{got} -- EFI_HANDLE ParentHandle matches the member pattern exactly')
    else:
        print(f'  [skip] {TREE} is not on this host')

    print('\nthe protocol set is untouched -- only the members within one')
    with tempfile.TemporaryDirectory() as out, tempfile.TemporaryDirectory() as out0:
        now = written(gpi, FIXTURES, out)
        real_expand = gpi.expand_members
        gpi.expand_members = (lambda m, b, f, depth=0, seen=():
                              real_expand(m, b, f, 0, seen))
        try:
            then = written(gpi, FIXTURES, out0)
        finally:
            gpi.expand_members = real_expand
        check('the same request files exist with the walk on as with it off',
              now == then, f'{now}\n         vs {then}')
        check('including the one whose whole surface is nested',
              'EfiOnlyNested.txt' in now and 'EfiOnlyNested.txt' in then,
              f'{now} -- it reached the set through the whole-header fallback before and '
              f'must not leave it now that the walk finds its struct')
        check('and every fixture protocol got one', len(now) == len(FIXTURES), f'{now}')
    check('the install-site index still gates discovery on the DIRECT members',
          gpi.normalize('_EFI_ONLY_NESTED_PROTOCOL') not in gpi.structs_in(ONLY_NESTED),
          'widening that gate would let scan_installations discover a protocol the '
          'header scan never matched -- an addition to the target set, which is a '
          'different question from this one')
    check('while the list that index reports is the expanded one',
          gpi.structs_in(NESTED).get(gpi.normalize('_EFI_NEST_PROTOCOL'))
          == ['PollMem', 'Read', 'Write', 'Flush'],
          f'{gpi.structs_in(NESTED)}')
    if os.path.isdir(TREE):
        real_expand = gpi.expand_members
        found_now = gpi.scan_roots([TREE])
        gpi.expand_members = (lambda m, b, f, depth=0, seen=():
                              real_expand(m, b, f, 0, seen))
        try:
            found_then = gpi.scan_roots([TREE])
        finally:
            gpi.expand_members = real_expand
        check('on the real MdePkg protocol headers the guid set is unchanged',
              set(found_now) == set(found_then),
              f'{len(found_now)} with the walk, {len(found_then)} without: '
              f'{sorted(set(found_now) ^ set(found_then))[:6]}')
        # the fourth, gEfiIsaIoProtocolGuid, is declared under OvmfPkg/Csm, not MdePkg,
        # and so is not in this directory's scan at all
        check('and the protocols that gain members are the ones measured',
              {g for g in found_now if found_now[g][1] != found_then[g][1]}
              == {'gEfiPciIoProtocolGuid', 'gEfiPciRootBridgeIoProtocolGuid',
                  'gEfiDeviceIoProtocolGuid'},
              f'{sorted(g for g in found_now if found_now[g][1] != found_then[g][1])}')
        check('and each gains exactly the two accessors, nothing else',
              all(sorted(set(found_now[g][1]) - set(found_then[g][1]))
                  == ['Read', 'Write']
                  for g in found_now if found_now[g][1] != found_then[g][1]),
              f'{ {g: sorted(set(found_now[g][1]) - set(found_then[g][1])) for g in found_now if found_now[g][1] != found_then[g][1]} }')

    print('\nthe measurement is recorded where the next reader will look')
    raw = source('gen_protocol_inputs')
    check('the comment gives the size of the hole, not just that there was one',
          '8 members across 4 protocols' in raw and '22 distinct' in raw,
          'a fix with no measurement beside it is a change nobody can re-check')
    check('it names the protocols it was measured on',
          'EFI_PCI_IO_PROTOCOL' in raw and 'EFI_ISA_IO_PROTOCOL' in raw)
    check('it says why the spelling is the leaf and not the path',
          'load_functions' in raw and 'protocol_member_paths' in raw,
          'the next person will otherwise invent the second convention')
    check('and it names all three bounds',
          'NEST_DEPTH' in raw and 'seen' in raw and 'MEMBER_RE' in raw)

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def _file_of(gpi, src, guid, header, depth=None):
    """The request file write_inputs produces for one protocol, as bytes."""
    fptypes = set(gpi.FPTYPE_RE.findall(src))
    if depth is None:
        found = gpi.struct_members(src, guid, fptypes)
    else:
        found = direct_only(gpi, src, guid)
    with tempfile.TemporaryDirectory() as out:
        with quiet():
            gpi.write_inputs({guid: (header, found)}, out, 1, 0)
        name = os.listdir(out)[0]
        return io.open(os.path.join(out, name), 'rb').read()


if __name__ == '__main__':
    sys.exit(main())
