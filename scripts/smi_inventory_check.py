#!/usr/bin/env python3
"""Assert smi-handler-inventory.json says what was harnessed, not what was predicted.

The inventory is the file this project quotes when asked how much of a tree's SMI surface
is covered. The C++ analyzer writes it, and it writes it before harness_generator runs --
so the field it put there was a prediction made by the pass that knows least about the
answer. The generator then changes the set in both directions: recover_missing_handlers
re-derives a GUID and a payload type from the source for handlers the analyzer recorded
without one, and the unusable loop drops handlers whose payload cannot be carried into the
harness. Nothing wrote that back.

Measured on EVAL-1 run 43452927684. The file recorded SmmSpiHandler as not drivable, in a
run that built FuzzSmmSpiHandler from it, dispatched it 5183 times and filed issues #68 and
#69 out of what it found. It claimed 10 harnessable where the run harnessed 11, and listed
25 handlers where the coverage report built from the same sets named 32 -- so the file was
both wrong about the one handler a reader would have checked and narrower than the run's
own narration.

What is asserted here is that the file is written where the generator's sets are final,
that it names every handler either set knows about, and that a handler kept out carries the
reason the run already prints for it rather than a second wording of it. The analyzer's own
field survives under its own name, AnalyzerTyped, because the recovery pass reads it as an
input -- it is a legitimate statement about what the C++ parsed, and only its old name
claimed more than that.

Run: python3 scripts/smi_inventory_check.py
"""
import ast
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile

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


def lift(names):
    """Run the named top-level definitions out of analyze_smi.py without importing it.

    analyze_smi.py imports fuzzywuzzy at module scope, which is not installed on a runner
    and has nothing to do with what the inventory says. This compiles the real source of
    the real definitions, so the check still fails when they change.
    """
    path = os.path.join(GEN, 'data_analysis', 'analyze_smi.py')
    tree = ast.parse(io.open(path, encoding='utf-8').read())

    def named(node):
        if isinstance(node, ast.FunctionDef):
            return node.name
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, 'id', None):
                    return target.id
        return None

    want = [node for node in tree.body if named(node) in names]
    missing = [n for n in names if n not in [named(node) for node in want]]
    if missing:
        raise SystemExit(f'analyze_smi.py no longer defines: {", ".join(missing)}')
    space = {'os': os, 'json': json, 'print': print, 'Dict': dict, 'List': list,
             'SmiInfo': Handler,
             # report_smi_coverage reports the lifecycle gate of each harnessed handler by
             # reading the tree. There is no tree here and the gate is not what this
             # checks, so it is answered rather than lifted.
             'lifecycle_gate': lambda name, edk2_dir: (None, None)}
    exec(compile(ast.Module(body=want, type_ignores=[]), 'analyze_smi.py', 'exec'), space)
    return space


def code(text):
    """A definition with its prose removed -- docstring and comments both.

    Asserting on the raw text of a function whose prose explains the defect finds the
    defect's name in the explanation. The comment on the call site below names both
    write_smi_inventory and report_smi_coverage, so an ordering assertion made against the
    raw text passes on the comment whatever order the statements are in.
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


def c_code(text):
    """C++ with its comments removed, for the same reason `code` exists.

    The comment that explains why the analyzer's field is not the coverage answer has to
    be able to say so without the assertion below reading the explanation as the thing it
    forbids.
    """
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


class Handler:
    """A SmiInfo, as analyze_smi holds one by the time the harness set is final."""

    def __init__(self, name, type, guid, file='', buffer_protocol='',
                 field_constants=None):
        self.name = name
        self.type = type
        self.guid = guid
        self.file = file
        self.buffer_protocol = buffer_protocol
        self.field_constants = dict(field_constants or {})


# One EVAL-1 run, reduced to the six handlers that each stand for one way in or out of the
# harness set. The strings are the run's own: the Dispatch kinds and GUIDs are from
# smi-handler-inventory.json on 43452927684, and the two notes are the ones run.log prints.
SPI = 'SmmSpiHandler'
VARIABLE = 'SmmVariableHandler'
RWVARIABLE = 'RWVariableHandler'
SWDISPATCH = 'B2SmiDispatchHandle'
UNTYPED = 'SmmReadyToLockHandler'
DROPPED = 'TpmNvsCommunciate'
STUCK = 'MemoryClearCallback'
ROOTMMI = 'CpuHotplugMmi'

VARIABLE_SOURCE = '/w/edk2/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.c'
SPI_SOURCE = '/w/edk2/OvmfPkg/Spi/SmmSpi.c'

DROPPED_NOTE = ('it casts its comm buffer to TPM_NVS_MM_COMM_BUFFER, which no module in '
                'this build declares')
STUCK_NOTE = ('registered through a dispatch protocol, not a comm-buffer GUID, so '
              'SmmCommunication cannot reach it')
# A root handler is in both sets at once: the recovery pass looks for the GUID it is
# registered under, finds none, and leaves a note about the GUID -- which is the one thing
# a root handler is defined by not having. The dispatch kind is the answer and the note is
# a distraction, so which of the two the row carries is a decision, not an accident.
ROOTMMI_NOTE = 'no GUID-keyed registration call found'


def analyzer_inventory():
    """smi-handler-inventory.json as the C++ leaves it, before the generator runs."""
    return {
        VARIABLE: {'Guid': 'gEfiSmmVariableProtocolGuid',
                   'Type': 'SMM_VARIABLE_COMMUNICATE_HEADER *',
                   'File': VARIABLE_SOURCE, 'Dispatch': 'SmiHandlerRegister',
                   'BufferProtocol': '', 'AnalyzerTyped': True},
        RWVARIABLE: {'Guid': 'gEfiRWVariableCommGuid', 'Type': 'void *', 'File': '',
                     'Dispatch': 'SmiHandlerRegister', 'BufferProtocol': '',
                     'AnalyzerTyped': True},
        # Recorded, and recorded without a type: the cast is made in the declaration and
        # the analyzer reads only the assignment spelling. This is the row the run was
        # wrong about.
        SPI: {'Guid': 'gEfiDxeSmmSpiProtocolGuid', 'Type': '', 'File': '',
              'Dispatch': 'SmiHandlerRegister', 'BufferProtocol': '',
              'AnalyzerTyped': False},
        SWDISPATCH: {'Guid': '', 'Type': '', 'File': '', 'Dispatch': 'SwDispatch',
                     'BufferProtocol': '', 'AnalyzerTyped': False},
        UNTYPED: {'Guid': 'gEfiSmmReadyToLockProtocolGuid', 'Type': '', 'File': '',
                  'Dispatch': 'SmiHandlerRegister', 'BufferProtocol': '',
                  'AnalyzerTyped': False},
        ROOTMMI: {'Guid': '', 'Type': '', 'File': '', 'Dispatch': 'RootHandler',
                  'BufferProtocol': '', 'AnalyzerTyped': False},
    }


def generator_sets():
    """What analyze_smi holds at the point the inventory is written.

    smi_data is final here: SPI has been recovered from source, DROPPED has been popped by
    the unusable loop, and STUCK never made it in. RWVARIABLE is in on the type its body
    casts to rather than the `void *` the analyzer recorded for it.
    """
    smi_data = {
        VARIABLE: Handler(VARIABLE, 'SMM_VARIABLE_COMMUNICATE_HEADER *',
                          'gEfiSmmVariableProtocolGuid'),
        RWVARIABLE: Handler(RWVARIABLE, 'RW_VARIABLE_INFO *', 'gEfiRWVariableCommGuid'),
        SPI: Handler(SPI, 'SPI_COMM_HEADER *', 'gEfiDxeSmmSpiProtocolGuid', SPI_SOURCE),
    }
    discovered = [VARIABLE, RWVARIABLE, SPI, SWDISPATCH, DROPPED, STUCK, ROOTMMI]
    return (smi_data, discovered, {STUCK: STUCK_NOTE, ROOTMMI: ROOTMMI_NOTE},
            {DROPPED: DROPPED_NOTE})


def written(space):
    """Drive the writer over those sets and read back the file it leaves on disk.

    Through write_smi_inventory and the path it derives, not through the dict, because
    where the file lands is half of what is asserted: a rewrite beside the guid map
    replaces the analyzer's answer, and a rewrite anywhere else leaves it being read.
    """
    work = tempfile.mkdtemp(prefix='smi-inventory-')
    smi_file = os.path.join(work, 'smi-function-guid-map.json')
    io.open(smi_file, 'w', encoding='utf-8').write('{}')
    path = os.path.join(work, 'smi-handler-inventory.json')
    io.open(path, 'w', encoding='utf-8').write(json.dumps(analyzer_inventory(), indent=4))

    smi_data, discovered, recovered, unusable = generator_sets()
    entries = space['smi_inventory'](smi_data, discovered, recovered, unusable,
                                     space['load_smi_inventory'](smi_file))
    space['write_smi_inventory'](smi_file, entries)
    text = io.open(path, encoding='utf-8').read()
    return json.loads(text), text, work


def reported(space):
    """The `not harnessed:` lines the coverage report prints for the same sets."""
    smi_data, discovered, recovered, unusable = generator_sets()
    spoken = io.StringIO()
    with contextlib.redirect_stdout(spoken):
        space['report_smi_coverage'](smi_data, discovered, recovered, unusable, '',
                                     analyzer_inventory())
    lines = {}
    for line in spoken.getvalue().splitlines():
        found = re.match(r'\s*not harnessed: (\w+) -- (.*)$', line)
        if found:
            lines[found.group(1)] = found.group(2)
    return lines


def main():
    space = lift(['smi_inventory', 'write_smi_inventory', 'not_harnessed_reason',
                  'load_smi_inventory', 'report_smi_coverage', 'DEFINITE_DISPATCH',
                  '_dispatch_reason', 'DISPATCH_REASON',
                  # The channel fields. Lifted even though this check drives the writer
                  # with no sw_commands: smi_inventory names them unconditionally, so
                  # leaving them out is a NameError rather than a different answer.
                  'DISPATCH_CHANNEL', 'SW_COMMAND_PORT', 'SW_DATA_PORT',
                  '_channel_of', '_sw_smi_reason'])
    entries, text, work = written(space)
    harnessable = sorted(n for n, e in entries.items() if e.get('Harnessable'))

    print('the file is the generator\'s answer, in the analyzer\'s place')
    check('it is written beside the guid map, under the name already read',
          os.path.isfile(os.path.join(work, 'smi-handler-inventory.json')),
          f'{sorted(os.listdir(work))} -- a second file leaves the first one being read')
    check('it parses, four-space and sorted as the analyzer writes it',
          text.startswith('{\n    "') and list(entries) == sorted(entries),
          'the two writers must not make a diff out of the formatting')

    print('\nit names every handler either pass knows about')
    smi_data, discovered, recovered, unusable = generator_sets()
    union = set(discovered) | set(smi_data) | set(unusable) | set(recovered) \
        | set(analyzer_inventory())
    check('the names are the union, not the analyzer\'s own keys',
          set(entries) == union,
          f'missing {sorted(union - set(entries))}, extra '
          f'{sorted(set(entries) - union)} -- on 43452927684 the file held 25 names and '
          f'the report built from the same sets named 32')
    check('a handler only the source registers is in the file',
          STUCK in entries and DROPPED in entries,
          f'{STUCK} and {DROPPED} are in no analysis output, so a file keyed on the '
          f'analyzer reads as a tree that has no such handler')
    check('a handler only the analyzer recorded is still in the file',
          UNTYPED in entries,
          'rewriting from the generator\'s sets alone drops the handlers the analyzer '
          'resolved out of a registration table')

    print('\na handler recovered from source is harnessed, and says so')
    check(f'{SPI} is harnessable', entries[SPI]['Harnessable'],
          'this is the row the run was wrong about: FuzzSmmSpiHandler was built from it, '
          'dispatched 5183 times, and filed issues #68 and #69')
    check('and carries no reason to be absent', entries[SPI]['Reason'] == '',
          repr(entries[SPI]['Reason']))
    check('the GUID it was recovered under is in the file',
          entries[SPI]['Guid'] == 'gEfiDxeSmmSpiProtocolGuid', entries[SPI]['Guid'])
    check('so is the payload type its body casts to',
          entries[SPI]['Type'] == 'SPI_COMM_HEADER *', entries[SPI]['Type'])
    check('and the source file the recovery read it out of',
          entries[SPI]['File'] == SPI_SOURCE,
          f'{entries[SPI]["File"]!r} -- every row on 43452927684 had File "", including '
          f'the ones resolved from a path the generator was holding')
    check('the analyzer\'s own field is kept, and disagrees with this row',
          entries[SPI]['AnalyzerTyped'] is False,
          'AnalyzerTyped is an input the recovery pass keys off -- the defect was the '
          'name claiming it was the coverage answer, not the field')
    check('the generator\'s better type wins over the analyzer\'s void *',
          entries[RWVARIABLE]['Type'] == 'RW_VARIABLE_INFO *',
          f'{entries[RWVARIABLE]["Type"]!r} -- the harness is built against the struct '
          f'the body casts to, so that is what the file has to name')
    check('and an empty generator value never erases a recorded one',
          entries[VARIABLE]['File'] == VARIABLE_SOURCE,
          f'{entries[VARIABLE]["File"]!r}')

    print('\na handler kept out is false, with the reason the run gives for it')
    check(f'{DROPPED} is not harnessable', entries[DROPPED]['Harnessable'] is False)
    check('and its reason is the generator\'s own note',
          entries[DROPPED]['Reason'] == DROPPED_NOTE, entries[DROPPED]['Reason'])
    check(f'{STUCK} carries the note the recovery pass left',
          entries[STUCK]['Reason'] == STUCK_NOTE, entries[STUCK]['Reason'])
    check('a dispatch kind that settles it is said instead of the buffer',
          'dispatcher' in entries[SWDISPATCH]['Reason']
          and 'port' in entries[SWDISPATCH]['Reason'],
          f'{entries[SWDISPATCH]["Reason"][:80]!r} -- a software MMI handler has no '
          f'caller buffer to cast, so a note about its cast sends a reader looking for '
          f'something that cannot exist')
    check('an unresolved payload type is distinguished from a different channel',
          'not resolved' in entries[UNTYPED]['Reason'], entries[UNTYPED]['Reason'][:80])
    check('and a definite kind beats a note the recovery pass left on the same handler',
          'ignored by contract' in entries[ROOTMMI]['Reason']
          and ROOTMMI_NOTE not in entries[ROOTMMI]['Reason'],
          f'{entries[ROOTMMI]["Reason"][:80]!r} -- a root handler has no GUID by '
          f'definition, so reporting that none was found tells a reader to look for '
          f'something the handler is defined by not having')
    silent = sorted(n for n, e in entries.items()
                    if not e['Harnessable'] and not e['Reason'])
    check('no handler is false without saying why', not silent,
          f'{silent} -- false with no reason is the claim that reads as a gap in the '
          f'generator whatever the real channel is')

    print('\nthe file and the run say the same thing in the same words')
    lines = reported(space)
    disagree = sorted(n for n, why in lines.items() if entries[n]['Reason'] != why)
    check('every not-harnessed line matches the row it is about', not disagree,
          '\n         '.join(f'{n}: report {lines[n]!r} != file '
                             f'{entries[n]["Reason"]!r}' for n in disagree))
    check('and the two agree on which handlers those are',
          sorted(lines) == sorted(set(entries) - set(harnessable)),
          f'report {sorted(lines)}\n         file {sorted(set(entries) - set(harnessable))}')
    check('the run harnessed one more than the analyzer could type',
          len(harnessable) == sum(1 for e in analyzer_inventory().values()
                                  if e['AnalyzerTyped']) + 1,
          f'{harnessable} against the analyzer\'s prediction -- 11 against 10 on '
          f'43452927684, and the file reported the prediction')

    print('\nit is written where the harness set is final, and only there')
    src = io.open(os.path.join(GEN, 'data_analysis', 'analyze_smi.py'),
                  encoding='utf-8').read()
    pipeline = code(body(src, 'def analyze_smi('))
    check('analyze_smi writes the inventory', 'write_smi_inventory(' in pipeline,
          'the analyzer\'s prediction is then what the file keeps')
    check('after the handlers it cannot carry are dropped',
          'smi_data.pop(' in pipeline
          and pipeline.index('smi_data.pop(') < pipeline.index('write_smi_inventory('),
          'written before the pops, the file calls a dropped handler harnessable')
    check('and before the coverage report, off the same sets',
          pipeline.index('write_smi_inventory(')
          < pipeline.index('report_smi_coverage('),
          'the report is the thing a reader compares the file against')
    empty = os.path.join(work, 'nothing-was-passed')
    os.makedirs(empty)
    saved = os.getcwd()
    try:
        os.chdir(empty)
        space['write_smi_inventory']('', entries)
        stray = sorted(os.listdir(empty))
    finally:
        os.chdir(saved)
    check('a caller that passed no analyzer output gets no file',
          stray == [], f'{stray} -- written relative to the working directory')

    print('\nthe analyzer does not claim the coverage answer')
    cpp = c_code(io.open(os.path.join(ROOT, 'firness', 'firness',
                                      'FileOperationHelpers.h'), encoding='utf-8').read())
    check('the C++ field is named for what the C++ knows',
          '"AnalyzerTyped"' in cpp,
          'the recovery pass reads it, so it is kept -- under a name that is true')
    check('and nothing in the C++ writes the coverage field',
          '"Harnessable"' not in cpp,
          'two writers for one field, and the one that runs first is the one that knows '
          'least about the answer')

    shutil.rmtree(work, ignore_errors=True)

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
