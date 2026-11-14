#!/usr/bin/env python3
"""Assert a protocol member whose function-pointer typedef is in an included header is
requested, by its leaf name, without changing which protocols get a request at all.

gen_protocol_inputs.py built its set of function-pointer typedefs from the one file it had
open, so a member typed from an #include was not recognised as callable: not requested, not
harnessed, not fuzzed, and nothing in any log said so. Measured by running the generator
before and after over whole trees and diffing every request file -- eval1_edk2 (271 files,
1315 member lines), edk2-master (274) and eval_source/edk2 (268): the same 11 members
across the same 2 protocols on all three.

    EfiEapManagement2.txt     requested 1 of 9. GetKey is typed in EapManagement2.h; the
                              other 8 are typed in <Protocol/EapManagement.h>.
    EdkiiFormBrowserEx2.txt   requested 3 of 6. SetScope, RegisterHotKey and
                              RegiserExitHandler are typed in <Protocol/FormBrowserEx.h>.

Both are one edk2 idiom -- revision 2 of a protocol includes revision 1 and re-uses its
typedefs -- so the shape recurs rather than the headers being odd.

The request spelling stays the bare leaf, as 423e260f established: load_functions() splits
a request line on the colon and harness_match() compares the right-hand side to the callee
name the analysis recorded. The two fixes have to compose, so a typedef resolved from
elsewhere may not reclassify a by-value sub-struct as a function pointer and strand the
leaves below it -- there is a fixture for exactly that collision.

What may NOT change is the set of request files. The decision of which GUIDs a header
yields, and which branch of scan_header runs, is still made from the typedefs declared in
the header; only the member lists are resolved wider. Widening the decision as well turns
gEdkiiSmmVarCheckProtocolGuid into a request file on every tree, because SmmVarCheck.h
declares a GUID and a three-member struct and not one typedef of its own -- a protocol
nobody chose, costing a container, an analysis, a build and a whole boot budget. The
install-site pass structs_in() feeds is untouched for the same reason one level down.

Known limitation, measured and not fixed here: firness has the same one-file assumption.
data_analysis/analyze.py's protocol_member_params() looks for the member's typedef in the
protocol header's own text, so for a member with no call sites it returns None and the
member is dropped with "WARNING: <name> was not able to be harnessed!!". Run offline on
the EdkiiFormBrowserEx2 campaign of sweep 43454245046, the generator read all 6 request
lines and emitted 3 Fuzz functions; with protocol_member_params() resolving the include in
a scratch copy it emitted 6. 10 of the 11 members have no call site in eval1_edk2 and so
depend on that path. The request file is the prerequisite, not the whole fix.

Run: python3 scripts/include_typedef_check.py
"""

import ast
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from typing import Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')
sys.path.insert(0, GEN)

# The two Include/Protocol directories the measurement above was taken on. Absent on a
# runner, where the assertions that read them are skipped and said to be skipped.
TREES = [os.path.join('/home/gl055/eval-trees/eval1_edk2', pkg, 'Include', 'Protocol')
         for pkg in ('MdePkg', 'MdeModulePkg')]

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

    The comment above the fix names every spelling under test: INCLUDE_DEPTH, the GUID that
    must NOT become a request file, structs_in, `seen`. A source assertion made against the
    raw text finds its string in the paragraph explaining why the statement exists, and
    passes with the statement deleted. That is the mutation this project has let through.
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


def body_of(text, name):
    """One top-level definition's source, so an assertion about it cannot read another's."""
    start = text.find(f'def {name}(')
    if start < 0:
        return ''
    rest = text[start:]
    nxt = re.search(r'\n(?=\S)', rest[len(f'def {name}('):])
    return rest if not nxt else rest[:len(f'def {name}(') + nxt.start() + 1]


def lift(names):
    """Run the named top-level definitions out of analyze.py without importing it.

    analyze.py imports fuzzywuzzy at module scope, which is not installed on a runner and
    has nothing to do with how a request line is spelled.
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
# Fixtures. Every pair differs in exactly ONE attribute, so a pass cannot be explained by
# the other difference: the protocol's struct text, its GUID and its local typedef are
# character for character the same in the control and in the subject, and the only thing
# that moves is which FILE the two remaining typedefs are written in.

AWAY_FIRST = 'typedef EFI_STATUS (EFIAPI *EFI_INC_FIRST)(VOID);\n'
AWAY_SECOND = 'typedef EFI_STATUS (EFIAPI *EFI_INC_SECOND)(VOID);\n'
AWAY = AWAY_FIRST + AWAY_SECOND

# the EapManagement2.h shape: one typedef of its own, the rest from an include
PROTO = '''
extern EFI_GUID  gEfiIncProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_INC_LOCAL)(VOID);
%s
struct _EFI_INC_PROTOCOL {
  EFI_INC_FIRST     First;
  EFI_INC_SECOND    Second;
  EFI_INC_LOCAL     Local;
};
'''
LOCAL_TREE = {'Include/Protocol/Inc.h': PROTO % AWAY}
INCLUDED_TREE = {'Include/Protocol/Inc.h': PROTO % '#include <Protocol/IncBase.h>',
                 'Include/Protocol/IncBase.h': AWAY}


def chain(hops):
    """Inc.h, then `hops` headers, the last of which declares the two typedefs.

    Only the chain LENGTH differs between one call and the next, so what the depth bound
    does is the only thing the comparison can be measuring.
    """
    files = {'Include/Protocol/Inc.h': PROTO % '#include <Protocol/Hop1.h>'}
    for step in range(1, hops):
        files[f'Include/Protocol/Hop{step}.h'] = f'#include <Protocol/Hop{step + 1}.h>\n'
    files[f'Include/Protocol/Hop{hops}.h'] = AWAY
    return files


# two headers that include each other, which the include guards make legal and common,
# with the typedefs one hop past the ring
RING_TREE = {
    'Include/Protocol/Inc.h': PROTO % '#include <Protocol/Ring.h>',
    'Include/Protocol/Ring.h': ('#include <Protocol/Inc.h>\n'
                                '#include <Protocol/RingBase.h>\n'),
    'Include/Protocol/RingBase.h': AWAY,
}

# a quoted include means the file beside this one, and there is no Include tree to key on
BESIDE_TREE = {'Include/Protocol/Inc.h': PROTO % '#include "IncBase.h"',
               'Include/Protocol/IncBase.h': AWAY}

# a diamond: two headers that both include the same third. the answer is the same either
# way, so `seen` is a cost guard rather than a correctness one -- and the only way to see
# it work is to count the resolutions, because an unguarded walk fans out multiplicatively
DIAMOND_TREE = {
    'Include/Protocol/Inc.h': PROTO % ('#include <Protocol/Left.h>\n'
                                       '#include <Protocol/Right.h>'),
    'Include/Protocol/Left.h': '#include <Protocol/IncBase.h>\n',
    'Include/Protocol/Right.h': '#include <Protocol/IncBase.h>\n',
    'Include/Protocol/IncBase.h': AWAY,
}

# 423e260f's shape with a name collision bolted on: the included header declares a
# function-pointer typedef called EFI_COL_ACCESS, which is also the name of a by-value
# sub-struct HERE. Taking the include's word for it makes Mem a leaf and strands Read and
# Write, undoing the nested walk by accident.
COL_PROTO = '''
extern EFI_GUID  gEfiColProtocolGuid;
typedef EFI_STATUS (EFIAPI *EFI_COL_LOCAL)(VOID);
%s
typedef struct {
  EFI_COL_LEAF    Read;
  EFI_COL_LEAF    Write;
} EFI_COL_ACCESS;
struct _EFI_COL_PROTOCOL {
  EFI_COL_LOCAL     Poll;
  EFI_COL_ACCESS    Mem;
};
'''
COL_CLEAN = 'typedef EFI_STATUS (EFIAPI *EFI_COL_LEAF)(VOID);\n'
COL_DIRTY = COL_CLEAN + 'typedef EFI_STATUS (EFIAPI *EFI_COL_ACCESS)(VOID);\n'
COL_CONTROL = {'Include/Protocol/Inc.h': COL_PROTO % '#include <Protocol/ColBase.h>',
               'Include/Protocol/ColBase.h': COL_CLEAN}
COL_COLLIDE = {'Include/Protocol/Inc.h': COL_PROTO % '#include <Protocol/ColBase.h>',
               'Include/Protocol/ColBase.h': COL_DIRTY}

# the SmmVarCheck.h shape: a GUID, a struct with members, and not one typedef of its own.
# resolving the DECISION as well as the list would make it a protocol the scan has never
# reported, which is an addition to the target set and a different question. The control
# moves one of the two typedefs back into the file and changes nothing else -- not the
# struct, not the GUID, not how many typedefs exist.
NOLOCAL = '''
extern EFI_GUID  gEfiNoLocalProtocolGuid;
#include <Protocol/IncBase.h>
%s
struct _EFI_NO_LOCAL_PROTOCOL {
  EFI_INC_FIRST     First;
  EFI_INC_SECOND    Second;
};
'''
NOLOCAL_TREE = {'Include/Protocol/Inc.h': NOLOCAL % '',
                'Include/Protocol/IncBase.h': AWAY_FIRST + AWAY_SECOND}
WITHLOCAL_TREE = {'Include/Protocol/Inc.h': NOLOCAL % AWAY_SECOND,
                  'Include/Protocol/IncBase.h': AWAY_FIRST}

# the FormBrowserEx2.h shape: the GUID's name does not resemble the struct's, so
# guid_struct_key finds no block and the whole-header fallback runs
FALLBACK = '''
extern EFI_GUID  gEdkiiFbProtocolGuid;
%s
struct _EDKII_FB_EXTENSION_PROTOCOL {
  EFI_INC_FIRST    Away;
  FB_LOCAL         Local;
};
'''
FALLBACK_TREE = {
    'Include/Protocol/Inc.h': FALLBACK % ('typedef EFI_STATUS (EFIAPI *FB_LOCAL)(VOID);\n'
                                          '#include <Protocol/IncBase.h>'),
    'Include/Protocol/IncBase.h': AWAY,
}
FALLBACK_NOLOCAL_TREE = {
    'Include/Protocol/Inc.h': FALLBACK % '#include <Protocol/IncBase.h>',
    'Include/Protocol/IncBase.h': AWAY,
}


class quiet:
    """write_inputs reports what it wrote on stdout; here that is not the report."""

    def __enter__(self):
        self.saved = sys.stdout
        sys.stdout = io.StringIO()

    def __exit__(self, *_):
        sys.stdout = self.saved


HOLDERS = []


def lay(files):
    """Write {relative path: text} into a fresh directory, return its Protocol root."""
    holder = tempfile.mkdtemp()
    HOLDERS.append(holder)
    for rel, text in files.items():
        path = os.path.join(holder, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        io.open(path, 'w').write(text)
    return os.path.join(holder, 'Include', 'Protocol')


def found(gpi, files, flat=False):
    """{guid: (header, members)} for a fixture tree, as scan_roots reports it."""
    root = lay(files)
    return gpi.scan_roots([root])


def members(gpi, files, guid):
    return found(gpi, files).get(guid, ('', []))[1]


def written(gpi, files, min_methods=1):
    """The request file NAMES write_inputs produces for a fixture tree."""
    out = tempfile.mkdtemp()
    HOLDERS.append(out)
    with quiet():
        gpi.write_inputs(found(gpi, files), out, min_methods, 0)
    return sorted(os.listdir(out))


def file_of(gpi, files, guid):
    """The request file for one protocol of a fixture tree, as bytes."""
    out = tempfile.mkdtemp()
    HOLDERS.append(out)
    got = found(gpi, files)
    with quiet():
        gpi.write_inputs({guid: got[guid]} if guid in got else {}, out, 1, 0)
    names = os.listdir(out)
    return io.open(os.path.join(out, names[0]), 'rb').read() if names else b''


class flat:
    """INCLUDE_DEPTH forced to 0: the pre-change scan, with the new code still running.

    Patched at the call rather than at the constant because scan_header reads the constant
    as a default argument, which is bound once at definition.
    """

    def __init__(self, gpi):
        self.gpi = gpi

    def __enter__(self):
        self.real = self.gpi.resolved_fptypes
        self.gpi.resolved_fptypes = (lambda path, src, includes=None, depth=0:
                                     self.real(path, src, includes, 0))

    def __exit__(self, *_):
        self.gpi.resolved_fptypes = self.real


def main():
    gpi = load('gen_protocol_inputs')
    gsrc = code(source('gen_protocol_inputs'))
    raw = source('gen_protocol_inputs')

    print('a member typed from an included header is requested, by its leaf name')
    here = members(gpi, LOCAL_TREE, 'gEfiIncProtocolGuid')
    away = members(gpi, INCLUDED_TREE, 'gEfiIncProtocolGuid')
    check('the control, with every typedef in the one file, is unchanged',
          here == ['First', 'Second', 'Local'], f'{here}')
    check('moving those two typedefs into an included header changes nothing',
          away == here, f'{away} vs {here} -- the struct text and the guid are identical '
                        f'in both; the file the typedefs live in is the only difference')
    check('the member typed locally is still requested',
          'Local' in away, f'{away} -- EapManagement2.h\'s GetKey is this member')
    # not .index(). A mutation that stops resolving leaves 'First' out, and .index would
    # raise inside this call's arguments: the check would die on its own traceback, print
    # no summary, and a harness reading exit codes cannot tell that from a clean run
    check('and the resolved ones are in declaration order, not appended',
          before('|'.join(away), 'First', 'Local'),
          f'{away} -- absent entirely if resolution stopped')
    check('the spelling is the bare leaf, not a path or a typedef name',
          not any('.' in m or m.isupper() for m in away),
          f'{away} -- load_functions splits on the colon and harness_match compares the '
          f'right-hand side to the recorded callee name')
    with flat(gpi):
        shut = members(gpi, INCLUDED_TREE, 'gEfiIncProtocolGuid')
    check('with resolution off the same header gives only the local member',
          shut == ['Local'],
          f'{shut} -- if this is already the full list the comparison above is vacuous')

    print('\nthe bound is a named constant, and it binds')
    check('INCLUDE_DEPTH is a named constant, not a literal in the walk',
          re.search(r'^INCLUDE_DEPTH = \d+$', gsrc, re.M) is not None
          and 'depth=INCLUDE_DEPTH' in gsrc,
          'a literal is a number the next reader cannot tie to a measurement')
    check('one hop resolves', members(gpi, chain(1), 'gEfiIncProtocolGuid')
          == ['First', 'Second', 'Local'], f'{members(gpi, chain(1), "gEfiIncProtocolGuid")}')
    check('so does a hop through an intermediate, at the depth chosen',
          members(gpi, chain(gpi.INCLUDE_DEPTH), 'gEfiIncProtocolGuid')
          == ['First', 'Second', 'Local'],
          f'{members(gpi, chain(gpi.INCLUDE_DEPTH), "gEfiIncProtocolGuid")}')
    check('one hop past the bound does not, so the walk is bounded',
          members(gpi, chain(gpi.INCLUDE_DEPTH + 1), 'gEfiIncProtocolGuid') == ['Local'],
          f'{members(gpi, chain(gpi.INCLUDE_DEPTH + 1), "gEfiIncProtocolGuid")} -- an '
          f'unbounded closure reaches most of MdePkg/Include from any protocol header')
    check('a pair of headers that include each other terminates and still resolves',
          members(gpi, RING_TREE, 'gEfiIncProtocolGuid') == ['First', 'Second', 'Local'],
          f'{members(gpi, RING_TREE, "gEfiIncProtocolGuid")}')
    check('the walk carries the headers already resolved', 'target in seen' in gsrc,
          'the depth budget alone does not stop a ring of two from spending it')
    seen_calls = []
    real_facts = gpi.header_facts
    gpi.header_facts = lambda path: (seen_calls.append(path), real_facts(path))[1]
    try:
        diamond = members(gpi, DIAMOND_TREE, 'gEfiIncProtocolGuid')
    finally:
        gpi.header_facts = real_facts
    check('a diamond resolves', diamond == ['First', 'Second', 'Local'], f'{diamond}')
    check('and no header on it is resolved twice',
          len(seen_calls) == len(set(seen_calls)),
          f'{seen_calls} -- without `seen` the walk fans out once per path to a header, '
          f'and MdePkg/Include is reachable by very many')
    check('a quoted include resolves to the file beside the header',
          members(gpi, BESIDE_TREE, 'gEfiIncProtocolGuid')
          == ['First', 'Second', 'Local'],
          f'{members(gpi, BESIDE_TREE, "gEfiIncProtocolGuid")}')

    print('\nthe resolution mechanics hold up on their own')
    root = lay(INCLUDED_TREE)
    index = gpi.include_index([root])
    check('the index is keyed the way a header spells the include',
          'Protocol/IncBase.h' in index, f'{sorted(index)}')
    check('and a root that is not under an Include directory contributes nothing',
          gpi.include_index([tempfile.mkdtemp()]) == {})
    facts = gpi.header_facts(os.path.join(root, 'IncBase.h'))
    check('header_facts reports the typedefs and the includes of one file',
          facts[0] == {'EFI_INC_FIRST', 'EFI_INC_SECOND'} and facts[1] == (), f'{facts}')
    check('it is memoised, so a header on two hundred closures is read once',
          gpi.header_facts(os.path.join(root, 'IncBase.h'))[0] is facts[0])
    check('the typedef set it caches is a frozenset',
          isinstance(facts[0], frozenset),
          'a caller unions into its own set; a mutable cached set made every header after '
          'the first report the union of all of them')
    one = gpi.resolved_fptypes(os.path.join(root, 'Inc.h'),
                               io.open(os.path.join(root, 'Inc.h')).read(), index)
    two = gpi.resolved_fptypes(os.path.join(root, 'Inc.h'),
                               io.open(os.path.join(root, 'Inc.h')).read(), index)
    check('and resolving the same header twice gives the same answer', one == two,
          f'{sorted(one)} then {sorted(two)}')
    check('at depth 0 it returns exactly the typedefs the header declares',
          gpi.resolved_fptypes(os.path.join(root, 'Inc.h'),
                               io.open(os.path.join(root, 'Inc.h')).read(), index, 0)
          == {'EFI_INC_LOCAL'},
          'this is the pre-change set, and the inert-in-isolation proof rests on it')

    print('\nit composes with the nested-struct walk rather than undoing it')
    control = members(gpi, COL_CONTROL, 'gEfiColProtocolGuid')
    collide = members(gpi, COL_COLLIDE, 'gEfiColProtocolGuid')
    check('the nested leaves are reached through the by-value sub-struct',
          control == ['Poll', 'Read', 'Write'], f'{control}')
    check('and an included typedef that collides with that sub-struct\'s name is ignored',
          collide == control,
          f'{collide} vs {control} -- taking the include\'s word for EFI_COL_ACCESS makes '
          f'Mem a leaf and strands Read and Write')
    check('the local typedef set is never filtered, only the resolved names',
          'found - local' in gsrc,
          'filtering the local set too would change a pre-change answer')
    check('the nested walk still has its own named depth', hasattr(gpi, 'NEST_DEPTH')
          and re.search(r'^NEST_DEPTH = \d+$', gsrc, re.M) is not None)

    print('\nthe protocol SET is untouched -- only the members within one')
    check('a header with a GUID, a struct and no typedef of its own yields no protocol',
          written(gpi, NOLOCAL_TREE) == [],
          f'{written(gpi, NOLOCAL_TREE)} -- this is SmmVarCheck.h, and resolving the '
          f'decision as well as the list makes it a request file on every tree')
    check('while moving one of its two typedefs back into the file yields one',
          written(gpi, WITHLOCAL_TREE) == ['EfiNoLocal.txt'],
          f'{written(gpi, WITHLOCAL_TREE)} -- if this were empty too the assertion above '
          f'would be measuring the fixture, not the gate')
    check('and that one asks for both members, the resolved one included',
          members(gpi, WITHLOCAL_TREE, 'gEfiNoLocalProtocolGuid') == ['First', 'Second'],
          f'{members(gpi, WITHLOCAL_TREE, "gEfiNoLocalProtocolGuid")}')
    check('the GUID gate is the local typedef set and the list is the resolved one',
          before(gsrc, 'if not struct_members(src, guid, fptypes):',
                 'owned.append((guid, struct_members(src, guid, resolved)))'),
          'absent entirely if either half is gone')
    for files, label in ((LOCAL_TREE, 'local'), (INCLUDED_TREE, 'included'),
                         (chain(1), 'one hop'), (RING_TREE, 'a ring'),
                         (COL_COLLIDE, 'a collision'), (FALLBACK_TREE, 'the fallback')):
        with flat(gpi):
            shut = written(gpi, files)
        check(f'the same request files exist with resolution on as with it off ({label})',
              written(gpi, files) == shut, f'{written(gpi, files)} vs {shut}')

    print('\nand the one way a growing member list CAN move the set is written down')
    check('at --min-methods 1, which every caller passes, the set is the same',
          written(gpi, INCLUDED_TREE, 1) == ['EfiInc.txt']
          and _with_flat(gpi, lambda: written(gpi, INCLUDED_TREE, 1)) == ['EfiInc.txt'],
          f'{written(gpi, INCLUDED_TREE, 1)}')
    check('above it a protocol can cross the floor, because its member count grew',
          written(gpi, INCLUDED_TREE, 2) == ['EfiInc.txt']
          and _with_flat(gpi, lambda: written(gpi, INCLUDED_TREE, 2)) == [],
          f'{written(gpi, INCLUDED_TREE, 2)} vs '
          f'{_with_flat(gpi, lambda: written(gpi, INCLUDED_TREE, 2))} -- this is real, it '
          f'is EfiEapManagement2 at -m 3, and nothing calls the generator that way')
    check('and the comment says so rather than leaving it to be found',
          'min-methods counts members' in raw and 'EfiEapManagement2.txt appears' in raw)

    print('\nthe whole-header fallback is gated the same way')
    fb = members(gpi, FALLBACK_TREE, 'gEdkiiFbProtocolGuid')
    check('a header whose GUID name does not match its struct still falls back',
          fb == ['Away', 'Local'],
          f'{fb} -- EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL arrives here and is 3 of the '
          f'11 members measured')
    with flat(gpi):
        fb0 = members(gpi, FALLBACK_TREE, 'gEdkiiFbProtocolGuid')
    check('and it gains the resolved member it used to drop', fb0 == ['Local'], f'{fb0}')
    check('but a fallback with no local typedef is still no protocol',
          written(gpi, FALLBACK_NOLOCAL_TREE) == [],
          f'{written(gpi, FALLBACK_NOLOCAL_TREE)}')
    check('that branch is decided by the local set too',
          before(gsrc, 'if not local:', 'return [(guids[0], members)]'),
          'the resolved list may fill the file; it may not create one')

    print('\nthe install-site discovery pass is not widened at all')
    text = INCLUDED_TREE['Include/Protocol/Inc.h']
    check('structs_in still reports only what the header itself types',
          gpi.structs_in(text).get(gpi.normalize('_EFI_INC_PROTOCOL')) == ['Local'],
          f'{gpi.structs_in(text)} -- this index is what scan_installations recognises a '
          f'struct by, so widening it adds protocols')
    check('and a struct with no locally typed member is not in it at all',
          gpi.structs_in(NOLOCAL_TREE['Include/Protocol/Inc.h']) == {},
          f'{gpi.structs_in(NOLOCAL_TREE["Include/Protocol/Inc.h"])}')
    check('structs_in does not call the resolver',
          'resolved_fptypes' not in body_of(gsrc, 'structs_in'),
          body_of(gsrc, 'structs_in'))
    check('nor does struct_index, the tree-wide walk it feeds',
          'resolved_fptypes' not in body_of(gsrc, 'struct_index'),
          body_of(gsrc, 'struct_index'))

    print('\na protocol with nothing to resolve is byte-identical in the file, not just '
          'in the list')
    with flat(gpi):
        shut_local = file_of(gpi, LOCAL_TREE, 'gEfiIncProtocolGuid')
        shut_away = file_of(gpi, INCLUDED_TREE, 'gEfiIncProtocolGuid')
    check('the request file for a self-contained header is unchanged',
          file_of(gpi, LOCAL_TREE, 'gEfiIncProtocolGuid') == shut_local,
          'the file, not the list -- the header comment and the guid prefix are in it')
    check('and the one that does change differs only by added lines',
          _added_only(file_of(gpi, INCLUDED_TREE, 'gEfiIncProtocolGuid'), shut_away),
          'a reordered or reworded line is a change to a request that already worked')

    print('\nthe spelling is the one firness reads back')
    space = lift(['load_functions'])
    out = tempfile.mkdtemp()
    HOLDERS.append(out)
    with quiet():
        gpi.write_inputs(found(gpi, INCLUDED_TREE), out, 1, 0)
    request = os.path.join(out, 'EfiInc.txt')
    parsed = (space['load_functions'](request)['Protocols']
              if os.path.isfile(request) else [])
    check('every resolved member comes back as (leaf, guid)',
          ('First', 'gEfiIncProtocolGuid') in parsed
          and ('Second', 'gEfiIncProtocolGuid') in parsed, f'{parsed}')
    check('and none of them carries a dotted path or a typedef name',
          all('.' not in name and not name.isupper() for name, _g in parsed), f'{parsed}')
    asrc = code(io.open(os.path.join(GEN, 'data_analysis', 'analyze.py'),
                        encoding='utf-8').read())
    check('a member the generator cannot harness is still named in a warning',
          'was not able to be harnessed' in asrc,
          'the hole closed here was silent; the one left in protocol_member_params is at '
          'least loud, and that message is how it was found')

    if all(os.path.isdir(t) for t in TREES):
        print('\nand on the real headers the measurement is reproduced')
        now = gpi.scan_roots(TREES)
        with flat(gpi):
            then = gpi.scan_roots(TREES)
        check('the GUID set is unchanged', set(now) == set(then),
              f'{len(now)} with resolution, {len(then)} without: '
              f'{sorted(set(now) ^ set(then))[:6]}')
        # .get on both sides. a mutation that widens the decision adds a GUID to `now`
        # that `then` has never heard of, and a bare subscript raises: the check would die
        # on its own traceback, print no summary, and be scored as a catch by anything
        # reading exit codes. it was, once, while this line read then[g][1]
        gained = {g for g in set(now) | set(then)
                  if now.get(g, ('', []))[1] != then.get(g, ('', []))[1]}
        check('the protocols that gain members are the two measured',
              gained == {'gEfiEapManagement2ProtocolGuid',
                         'gEdkiiFormBrowserEx2ProtocolGuid'}, f'{sorted(gained)}')
        eap, fbx = 'gEfiEapManagement2ProtocolGuid', 'gEdkiiFormBrowserEx2ProtocolGuid'
        check('EFI_EAP_MANAGEMENT2_PROTOCOL gains its other eight members',
              sorted(set(now.get(eap, ('', []))[1]) - set(then.get(eap, ('', []))[1]))
              == ['GetSupplicantStatistics', 'GetSupplicantStatus',
                  'GetSystemConfiguration', 'InitializePort',
                  'SetSupplicantConfiguration', 'SetSystemConfiguration',
                  'UserLogoff', 'UserLogon'],
              f'{now.get(eap)}')
        check('and GetKey, which it already asked for, is still there',
              then.get(eap, ('', []))[1] == ['GetKey']
              and 'GetKey' in now.get(eap, ('', []))[1], f'{now.get(eap)}')
        check('the form browser extension gains its three, through the fallback branch',
              sorted(set(now.get(fbx, ('', []))[1]) - set(then.get(fbx, ('', []))[1]))
              == ['RegiserExitHandler', 'RegisterHotKey', 'SetScope'],
              f'{now.get(fbx)}')
        check('no protocol LOSES a member it used to ask for',
              all(set(then[g][1]) <= set(now.get(g, ('', []))[1]) for g in then),
              f'{ {g: sorted(set(then[g][1]) - set(now.get(g, ("", []))[1])) for g in then if set(then[g][1]) - set(now.get(g, ("", []))[1])} }')
        # the bound's justification, asserted rather than asserted-about: the measured
        # need is one hop, so forcing the walk to one hop must give the same answer the
        # chosen bound gives. if a tree ever needs two this fails and says so
        real = gpi.resolved_fptypes
        gpi.resolved_fptypes = (lambda path, src, includes=None, depth=1:
                                real(path, src, includes, 1))
        try:
            one_hop = gpi.scan_roots(TREES)
        finally:
            gpi.resolved_fptypes = real
        check('one hop is all these trees need, which is what the bound is chosen from',
              {g: v[1] for g, v in one_hop.items()} == {g: v[1] for g, v in now.items()},
              f'{sorted(g for g in now if now[g][1] != one_hop.get(g, ("", []))[1])}')
        check('and 423e260f still holds on the same scan',
              'Read' in now.get('gEfiPciIoProtocolGuid', ('', []))[1]
              and 'Write' in now.get('gEfiPciIoProtocolGuid', ('', []))[1],
              f'{now.get("gEfiPciIoProtocolGuid")} -- the nested accessors come from the '
              f'other fix and must survive this one')
    else:
        print(f'\n  [skip] {TREES[0]} is not on this host')

    print('\nthe measurement is recorded where the next reader will look')
    check('the comment gives the size of the hole, not just that there was one',
          '11 members' in raw and '2 protocols' in raw,
          'a fix with no measurement beside it is a change nobody can re-check')
    check('it names both protocols and both included headers',
          'EapManagement.h' in raw and 'FormBrowserEx.h' in raw)
    check('it says why the bound is the number it is, and names the idiom',
          'resolves at depth 1' in raw and 'plus one hop' in raw,
          'a bound with no measurement beside it is a number the next reader will widen')
    check('it gives the cost it was measured at, in both places it matters',
          '149 ms' in raw and '341 ms' in raw and '3.15 s' in raw,
          '"negligible" is a claim; two numbers and a method are a measurement')
    check('and it says what was deliberately NOT widened, and what that would cost',
          'gEdkiiSmmVarCheckProtocolGuid' in raw and 'structs_in()' in raw,
          'the next reader will otherwise widen the gate and add targets nobody chose')

    for holder in HOLDERS:
        shutil.rmtree(holder, ignore_errors=True)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def _with_flat(gpi, call):
    """`call()` with resolution off. A function, so a mutation cannot reorder the two."""
    with flat(gpi):
        return call()


def _added_only(after, before_text):
    """True when `after` is `before_text` with lines inserted and none changed."""
    want = before_text.splitlines()
    have = after.splitlines()
    index = 0
    for line in have:
        if index < len(want) and line == want[index]:
            index += 1
    return index == len(want) and len(have) > len(want)


if __name__ == '__main__':
    sys.exit(main())
