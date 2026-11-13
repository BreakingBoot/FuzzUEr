#!/usr/bin/env python3
"""Assert one handler the harness cannot lay out costs that handler and nothing else.

The SMI generator used to decide twice whether a comm buffer could be laid out field by
field: once in the analysis, which keeps or drops the handler, and once in the template,
which emits the field fills. The two disagreed. A handler that declares its CommBuffer
`VOID *` passed the analysis -- vendor_types.resolve answered ([], ''), because `void` is
in BASE_TYPES for the sake of a VOID * FIELD and walk() says yes to a base type -- and
then reached the template, which looked for the fields of `void`, found none, looked up
its typedef, found none either, and subscripted the type map with None.

The type map was a defaultdict(list). A defaultdict mutates on read, so that subscript
did not raise KeyError: it INSERTED a list under the key None and handed the list back,
and `[].fields` raised AttributeError. The traceback reached main() and the run ended.

Reproduced from EVAL-1 run 43452927684's own inputs: RWVariableHandler is one handler of
eleven, and at firness c0f955b94 it took the other ten harnesses with it, so a
DiscoveredSmi campaign produced nothing at all. Introduced by 807351dda, which replaced
"drop a handler whose header cannot be included" with "vendor it instead" and routed the
VOID * case through resolve() on the way.

What is asserted here is that the two readers now ask one function; that a handler nobody
can lay out leaves by the same door as every other dropped handler, named with a reason
the run log prints and smi-handler-inventory.json records; that the map cannot invent an
entry for a type the analyser never saw; and that the recovery which keeps
RWVariableHandler in the set -- reading the cast its own body makes -- survives a renamed
parameter, a local alias of it, and a commented-out cast two lines below the live one.

Run: python3 scripts/payload_layout_check.py
"""
import ast
import io
import json
import os
import re
import sys
import tempfile
import textwrap
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')
sys.path.insert(0, GEN)

from common.types import TypeInfo, FieldInfo                      # noqa: E402
from common.vendor_types import resolve, BASE_TYPES              # noqa: E402
import uefi_harness.smi_harness_template as smi_template         # noqa: E402

# Imported so that DELETING them is a failing assertion rather than an ImportError at the
# top of the file. A check that dies before its first line of output has not caught
# anything, and nothing reading exit codes can tell that from a check that ran.
try:
    from common.types import TypeMap                             # noqa: E402
except ImportError:
    TypeMap = None
try:
    from common.vendor_types import payload_layout               # noqa: E402
except ImportError:
    payload_layout = None
try:
    from common.vendor_types import NO_PAYLOAD                   # noqa: E402
except ImportError:
    NO_PAYLOAD = None

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def lift(names):
    """Run the named top-level definitions out of analyze_smi.py without importing it.

    analyze_smi.py imports fuzzywuzzy at module scope, which is not installed on a runner
    and has nothing to do with whether a payload can be laid out. This compiles the real
    source of the real definitions, so the check still fails when they change.
    """
    path = os.path.join(GEN, 'data_analysis', 'analyze_smi.py')
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
        raise SystemExit(f'analyze_smi.py no longer defines: {", ".join(missing)}')
    # defaultdict is here so that REMOVING the fix is a failing assertion rather than a
    # NameError. A check that dies inside the code it is testing has reported nothing, and
    # a mutation run cannot tell that from a catch.
    space = {'os': os, 're': re, 'json': json, 'print': print, 'Dict': dict,
             'List': list, 'open': open, 'defaultdict': defaultdict,
             'NO_PAYLOAD': NO_PAYLOAD,
             'TypeInfo': TypeInfo, 'TypeMap': TypeMap, 'FieldInfo': FieldInfo}
    exec(compile(ast.Module(body=want, type_ignores=[]), 'analyze_smi.py', 'exec'), space)
    return space


def code(text):
    """A definition with its prose removed -- docstring and comments both.

    Every comment in the code under test explains this defect by name, so a source
    assertion made against the raw text finds `payload_layout` in the paragraph that says
    why it exists and passes with the call deleted. That mutation is the one this project
    has let through before.
    """
    found = re.search(r'"""', text)
    if found:
        closing = text.index('"""', found.end())
        text = text[:found.start()] + text[closing + 3:]
    return '\n'.join(line for line in text.splitlines()
                     if not line.strip().startswith('#'))


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not.

    A bare .index() on an anchor a mutation deleted raises, and a check that dies on its
    own traceback has not caught anything -- it has stopped reporting. This project has
    credited that as a catch before.
    """
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def body(src, marker):
    """One definition's text, from its `def` to the next top-level one."""
    start = src.index(marker)
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Za-z_]+ = |@)', rest)
    return src[start:start + len(marker) + (end.start() if end else len(rest))]


class Handler:
    """A SmiInfo, as analyze_smi holds one while it decides the harness set."""

    def __init__(self, name, type, guid='', file=''):
        self.name = name
        self.type = type
        self.guid = guid
        self.file = file
        self.buffer_protocol = ''
        self.field_constants = {}


# A private block, its public twin, and a block the analyser recorded by name with nothing
# in it -- which is the second way into the crash and the one no amount of include
# resolution catches.
BLOCK = TypeInfo('RW_VARIABLE_INFO',
                 [FieldInfo('Status', 'EFI_STATUS'),
                  FieldInfo('VariableNameSize', 'UINTN'),
                  FieldInfo('Data', 'UINT8[1024]')],
                 '/w/edk2/OvmfPkg/RWVariable/RWVariable.h')
PUBLIC = TypeInfo('SMM_VARIABLE_COMMUNICATE_HEADER',
                  [FieldInfo('Function', 'UINTN'), FieldInfo('Status', 'EFI_STATUS')],
                  '/w/edk2/MdePkg/Include/Guid/Public.h')
HOLLOW = TypeInfo('OPAQUE_BLOCK', [], '/w/edk2/MdePkg/Include/Guid/Opaque.h')
WRAPPER = TypeInfo('_RW_VARIABLE_TAG', list(BLOCK.fields), BLOCK.file)


def recorded():
    """The type map as load_types builds one, with the three blocks above in it."""
    types = TypeMap()
    for info in (BLOCK, PUBLIC, HOLLOW, WRAPPER):
        types[info.name] = info
    return types


# A Checked-C handler, which is how the EVAL-1 tree spells RWVariableHandler: the comm
# buffer parameter is renamed, carries a parenthesised annotation with a comma in it, and
# every cast in the body is applied to a LOCAL declared from it. Three of the four lines
# in the body are that file's own -- the alias declaration, the nested cast at line 73 and
# the live `(void *)` at line 102. The commented-out cast is this check's, and names a
# type nothing else here does, so the assertion about it cannot pass for any other reason.
CHECKED_C = '''
    /**
      RWVariableHandler (CommBuffer) is the read/write variable handler.
    **/
    EFI_STATUS
    EFIAPI
    RWVariableHandler (
      IN     EFI_HANDLE    DispatchHandle,
      IN     CONST VOID    *Context,
      IN OUT VOID          *CommBuffer1 : itype(_Array_ptr<VOID>) bounds(KERN_HIGH, KERN_LOW),
      IN OUT UINTN         *CommBufferSize
      )
    {
      _Array_ptr<VOID> CommBuffer : bounds(KERN_HIGH, KERN_LOW) = _Dynamic_bounds_cast<_Array_ptr<VOID>>(CommBuffer1, bounds(KERN_HIGH, KERN_LOW));
      RW_VARIABLE_INFO *CommData = NULL;
      DestBuffer = (VOID *)((CHAR16 *)((RW_VARIABLE_INFO *)CommBuffer)->Data + CommData->Offset);
      //     DuplicateMemory ((RW_LEGACY_INFO *) CommBuffer, CommData, DataSize);
      DuplicateMemory ((void *) CommBuffer, CommData, DataSize);
      return EFI_SUCCESS;
    }
'''

PLAIN_C = '''
    EFI_STATUS
    EFIAPI
    SmmSpiHandler (
      IN     EFI_HANDLE    DispatchHandle,
      IN     CONST VOID    *Context,
      IN OUT VOID          *CommBuffer,
      IN OUT UINTN         *CommBufferSize
      )
    {
      SPI_COMM_HEADER *ReturnComms = (SPI_COMM_HEADER *)CommBuffer;
      return EFI_SUCCESS;
    }
'''


def tree_with(where, name, text):
    os.makedirs(os.path.join(where, 'Drv'), exist_ok=True)
    open(os.path.join(where, 'Drv', name), 'w').write(textwrap.dedent(text))
    return where


def emitted_by(call, *args, **kwargs):
    """What a template function emitted, or the exception it raised instead.

    The property under test is that it does NOT raise, so an exception has to arrive as a
    failed assertion. Letting it propagate ends the run with a traceback and no summary
    line -- which is what the defect itself did, and is indistinguishable from it.
    """
    try:
        return '\n'.join(call(*args, **kwargs)), ''
    except Exception as exc:                                     # noqa: BLE001
        return '', f'{type(exc).__name__}: {exc}'


def main():
    includable = lambda info: bool(info and info.file and '/Include/' in info.file)

    print('the generator still has the pieces this check is about')
    absent = [name for name, value in (('common.types.TypeMap', TypeMap),
                                       ('common.vendor_types.payload_layout',
                                        payload_layout),
                                       ('common.vendor_types.NO_PAYLOAD',
                                        NO_PAYLOAD)) if value is None]
    check('the layout gate and its type map are both defined', not absent,
          f'{absent} -- reverted, so nothing below could be asserted')
    try:
        space = lift(['_DEFN', '_COMMENT', '_IDENTIFIER', '_handler_source',
                      '_buffer_body', '_buffer_names', '_payload_casts',
                      'payload_from_source', '_no_payload_reason', 'load_types'])
    except SystemExit as exc:
        check('analyze_smi still defines the gate and the helpers it reads', False,
              str(exc))
        space = None
    if absent or space is None:
        print(f'\n{PASSED} passed, {FAILED} failed')
        return 1
    check('analyze_smi still defines the gate and the helpers it reads', True)

    print('the type map cannot invent an entry for a type nobody recorded')
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, 'types.json')
        open(path, 'w').write(json.dumps(
            [{'TypeName': 'RW_VARIABLE_INFO', 'File': BLOCK.file,
              'Fields': [{'Name': f.name, 'Type': f.type} for f in BLOCK.fields]}]))
        loaded = space['load_types'](path)
    check('load_types really returns this map, not a defaultdict',
          isinstance(loaded, TypeMap) and not isinstance(loaded, defaultdict),
          f'{type(loaded).__name__} -- a defaultdict(list) answers a miss with a list '
          f'of another type and keeps it')
    check('and what it loaded reads back as the analyser recorded it',
          [f.name for f in loaded['RW_VARIABLE_INFO'].fields]
          == ['Status', 'VariableNameSize', 'Data']
          and loaded['RW_VARIABLE_INFO'].file == BLOCK.file)
    # The subscript, and nothing done to what comes back. Reading .fields off it here is
    # the very operation that raised in the generator, so a check that does it dies with
    # the defect instead of reporting it -- and a dead check looks like a passing one to
    # anything counting exit codes.
    miss = loaded['NOT_A_TYPE']
    check('a miss on the map it really builds answers with a TypeInfo',
          isinstance(miss, TypeInfo), f'{type(miss).__name__}')
    check('a miss on the map it really builds leaves nothing behind',
          list(loaded) == ['RW_VARIABLE_INFO'], f'{sorted(loaded)}')

    types = recorded()
    missed = types['NO_SUCH_BLOCK']
    check('a miss answers with a TypeInfo, not a list of another type',
          isinstance(missed, TypeInfo), f'{type(missed).__name__}')
    check('so .fields on a miss reads as empty instead of raising',
          missed.fields == [], f'{missed.fields!r}')
    check('and the lookup leaves no entry behind it',
          'NO_SUCH_BLOCK' not in types,
          f'{sorted(types)} -- a map that grows on read claims types it has never seen')
    check('the map is the size the analyser made it', len(types) == 4, f'{len(types)}')
    check('a miss is still None through .get, so callers that branch still branch',
          types.get('NO_SUCH_BLOCK') is None)
    check('a recorded block still answers with its own fields',
          [f.name for f in types['RW_VARIABLE_INFO'].fields]
          == ['Status', 'VariableNameSize', 'Data'])
    dxe = io.open(os.path.join(GEN, 'data_analysis', 'analyze.py'),
                  encoding='utf-8').read()
    check('the DXE loader builds the same map, so the trap is gone from both',
          'TypeMap()' in code(body(dxe, 'def load_types(')),
          'analyze.py:load_types kept the construction that cost the SMI run')

    print('\na comm buffer with no type is not a payload')
    order, reason = resolve('void', types, {}, includable)
    check('resolve refuses a void root', order is None, f'{order!r}')
    check('and says why, in words a reader can act on',
          bool(reason) and 'VOID' in reason.upper(), repr(reason))
    check('VOID and an empty name are refused the same way',
          resolve('VOID', types, {}, includable)[0] is None
          and resolve('', types, {}, includable)[0] is None
          and resolve('VOID *', types, {}, includable)[0] is None)
    check('void stays a legal FIELD type, which is why it is in BASE_TYPES',
          'void' in BASE_TYPES and 'VOID' in BASE_TYPES)
    with_void_field = dict(types)
    with_void_field['HAS_VOID_FIELD'] = TypeInfo(
        'HAS_VOID_FIELD', [FieldInfo('Buffer', 'VOID *'), FieldInfo('Size', 'UINTN')],
        '/w/edk2/OvmfPkg/Thing/Private.h')
    check('a block with a VOID * field is still vendored',
          resolve('HAS_VOID_FIELD', with_void_field, {}, includable)[0]
          == ['HAS_VOID_FIELD'],
          'refusing void at the root must not refuse it inside a block')
    check('a private block is still vendored rather than dropped',
          resolve('RW_VARIABLE_INFO', types, {}, includable)[0] == ['RW_VARIABLE_INFO'])
    check('an includable block is still left to its own header',
          resolve('SMM_VARIABLE_COMMUNICATE_HEADER', types, {}, includable)[0] == [])

    print('\none function answers "can the harness lay this out", for both readers')
    check('it finds the block by name',
          payload_layout('RW_VARIABLE_INFO *', types, {})
          == ('RW_VARIABLE_INFO', BLOCK.fields))
    check('it follows one typedef to where the fields were recorded',
          payload_layout('RW_VARIABLE_INFO_T *', types,
                         {'RW_VARIABLE_INFO_T': '_RW_VARIABLE_TAG'})[0]
          == '_RW_VARIABLE_TAG')
    check('a void buffer lays out as nothing, and does not raise',
          payload_layout('void *', types, {}) == ('', []))
    check('so does a name the analyser never recorded',
          payload_layout('NO_SUCH_BLOCK *', types, {}) == ('', []))
    check('and so does a block recorded with no fields',
          payload_layout('OPAQUE_BLOCK *', types, {})[1] == [],
          'an includable header is not the same thing as a block with fields')

    print('\nthe template asks that function and never subscripts the map')
    template = io.open(os.path.join(GEN, 'uefi_harness', 'smi_harness_template.py'),
                       encoding='utf-8').read()
    struct_args = code(body(template, 'def generator_struct_args('))
    check('generator_struct_args calls payload_layout',
          'payload_layout(' in struct_args, struct_args)
    check('and holds no bare subscript of the type map',
          not re.search(r'\btypes\s*\[', struct_args),
          'types[struct_type] is the line that raised and ended the run')
    emitted, raised = emitted_by(smi_template.generator_struct_args,
                                 'void *', 'HandlerData', {}, types, indent=False)
    check('handed a void block directly it degrades instead of raising',
          not raised and 'ReadBytes' not in emitted, raised or emitted)

    print('\none handler nobody can lay out does not cost the others their harness')
    smi_template.aliases_map.clear()
    harnesses, raised = emitted_by(
        smi_template.harness_generator,
        {'GoodOne': Handler('GoodOne', 'RW_VARIABLE_INFO *', 'gOneGuid'),
         'Unlayoutable': Handler('Unlayoutable', 'void *', 'gTwoGuid'),
         'GoodTwo': Handler('GoodTwo', 'SMM_VARIABLE_COMMUNICATE_HEADER *', 'gThreeGuid')},
        types, {}, {})
    check('the whole set still generates',
          not raised and 'FuzzGoodOne' in harnesses and 'FuzzGoodTwo' in harnesses,
          raised or harnesses[:400])
    check('and the handlers that CAN be laid out still get their field fills',
          'HandlerData->VariableNameSize' in harnesses
          and 'HandlerData->Function' in harnesses)

    print('\nwhat is skipped is named, with the reason the run already prints')
    check('a void buffer with no cast anywhere says exactly that',
          'nothing in its body casts' in space['_no_payload_reason'](
              Handler('RWVariableHandler', 'void *'), 'void', types, ''))
    check('and names the type it was declared as', 'void *' in space['_no_payload_reason'](
        Handler('RWVariableHandler', 'void *'), 'void', types, ''))
    with tempfile.TemporaryDirectory() as tree:
        tree_with(tree, 'Spi.c', PLAIN_C)
        why = space['_no_payload_reason'](Handler('SmmSpiHandler', 'void *'), 'void',
                                          types, tree)
        check('a cast to a type nobody parsed names that type instead',
              'SPI_COMM_HEADER' in why, why)
        check('and does not claim there is no cast',
              'nothing in its body casts' not in why, why)
    hollow = space['_no_payload_reason'](Handler('Opaque', 'OPAQUE_BLOCK *'),
                                         'OPAQUE_BLOCK', types, '')
    check('a block recorded with no fields says that, not "no cast"',
          'no fields' in hollow and 'OPAQUE_BLOCK' in hollow, hollow)
    check('a block that resolves normally has nothing to add',
          space['_no_payload_reason'](Handler('Good', 'RW_VARIABLE_INFO *'),
                                      'RW_VARIABLE_INFO', types, '') == '',
          'resolve_payload names the type it could not reach; do not overwrite that')

    print('\nthe analysis drops it there, by the same door as every other handler')
    analysis = code(body(io.open(os.path.join(GEN, 'data_analysis', 'analyze_smi.py'),
                                 encoding='utf-8').read(), 'def analyze_smi('))
    check('analyze_smi asks payload_layout before it keeps a handler',
          'payload_layout(' in analysis,
          'without it the template is the first thing to find out, and it raises')
    check('a handler it cannot lay out goes into unusable, by name',
          bool(re.search(r'if order is None or not fields:', analysis))
          and 'unusable[smi.name] = why' in analysis,
          'without it the run ends on the first handler it cannot lay out')
    check('the drop is printed, so the run log names it too',
          "print(f'INFO: dropping smi handler {smi.name} -- {why}')" in analysis)
    check('and the reason is the specific one where there is one',
          before(analysis, '_no_payload_reason(', 'unusable[smi.name]'),
          'resolve_payload cannot name a block for a buffer that has no type')
    check('unusable is what the inventory and the coverage report both read',
          before(analysis, 'unusable[smi.name]', 'smi_data.pop(')
          and before(analysis, 'smi_data.pop(', 'write_smi_inventory('),
          'a handler dropped after the file is written is a false Harnessable true')

    print('\nthe recovery that keeps RWVariableHandler rather than skipping it')
    with tempfile.TemporaryDirectory() as tree:
        tree_with(tree, 'RWVariable.c', CHECKED_C)
        names = space['_buffer_names'](
            space['_buffer_body'](space['_handler_source']('RWVariableHandler', tree)[1]))
        check('a renamed comm buffer parameter is still found',
              'CommBuffer1' in names, f'{names}')
        check('and so is the local the body actually casts', 'CommBuffer' in names,
              f'{names} -- matching only the parameter finds none of the casts')
        check('the length beside it is not mistaken for the buffer',
              'CommBufferSize' not in names, f'{names}')
        casts = space['_payload_casts']('RWVariableHandler', tree)
        check('the cast nested inside another cast is read',
              casts[:1] == ['RW_VARIABLE_INFO'], f'{casts}')
        check('a commented-out cast is not reported as one',
              'RW_LEGACY_INFO' not in casts,
              f'{casts} -- prose quoting the thing being matched is how this pass was '
              f'fooled before')
        check('and a live cast to void is not reported as a block',
              'void' not in casts and 'VOID' not in casts,
              f'{casts} -- this answer is quoted into the reason a dropped handler '
              f'carries, and there is no struct called void to go and look for')
        check('so the handler is harnessed on the block its body names',
              space['payload_from_source']('RWVariableHandler', tree, types)
              == 'RW_VARIABLE_INFO')
    with tempfile.TemporaryDirectory() as tree:
        tree_with(tree, 'Spi.c', PLAIN_C)
        check('the plain-C form still reads the same way',
              space['_payload_casts']('SmmSpiHandler', tree) == ['SPI_COMM_HEADER'])
        check('and an unrecorded cast target is still no answer',
              space['payload_from_source']('SmmSpiHandler', tree, types) is None,
              'payload_from_source answers only with a block it can build fields for')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
