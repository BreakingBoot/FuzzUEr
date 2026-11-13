#!/usr/bin/env python3
"""Assert the software SMI channel aims at the command bytes the tree registers, and no others.

An SMI handler on the software dispatch protocol has no GUID and takes no caller buffer.
It is reached by writing a command byte to port 0xB2 -- one `out` from ring 0 -- and the
dispatcher builds its EFI_MM_SW_CONTEXT out of that byte and the data byte at 0xB3. The
comm-buffer harness cannot produce that input, which is why the SMI inventory reported
nine handlers as undrivable: true of the channel it was talking about, and read as a
statement about the firmware. On the EVAL-1 tree B2SmiDispatch was the only challenge-added
OvmfPkg driver with no coverage at all because of it.

Two things have to hold and neither is visible by reading the harness.

**The command byte comes from discovery, not from a constant.** 0xB4 is the value the
EVAL-1 tree happens to register; a hardcoded 0xB4 is a harness that works on one tree and
silently addresses nothing on the next. So discovery has to find a value a fixture really
registers, through the #define the tree spells it with, and it has to resolve the right
assignment when one context variable serves two registrations.

**And it must not invent one.** Every software SMI registration in edk2 proper is written
`SwContext.SwSmiInputValue = (UINTN)-1`, which asks the dispatcher for the next free byte
at registration time. There is no static answer to that, and a guess is worse than a gap:
port 0xB2 is shared with the platform. ICH9_APM_CNT_CPU_HOTPLUG (0x04) reaches
CpuHotplugSmm, whose error paths CpuDeadLoop() inside SMM; command 0 is what OVMF's own
SmmControl2 Trigger writes for every SmmCommunicate. A byte nothing registered reaches no
handler either way, so a sweep of 0..255 buys no coverage and can forfeit a campaign's
whole budget on a guest that never comes back.

The rest is the wiring a harness needs to survive the pipeline: the data byte written
before the command byte, because writing 0xB2 is what raises the SMI and the other order
sends the previous iteration's data; the sanitizer armed across the write, or a fault
inside the handler is logged and dropped; and IoLib surviving used_libraries, which drops
every class the emitted sources never call and would otherwise leave IoWrite8 unresolved
at link time.

Everything here is driven rather than read. The generated C is produced by the real
template, the discovery by both real passes, the library decision by the real
used_libraries and the inventory by the real writer -- and every source assertion is made
against text with its comments stripped, because the prose in all of these names the
thing it is explaining.

Run: python3 scripts/sw_smi_check.py
"""
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

FAILED = PASSED = 0

# The fixture's registered byte. Deliberately not 0xB4: a check written against the value
# the EVAL-1 tree uses passes just as well on a harness that hardcodes it.
PAIR_VALUE = 0x70
PAIR_SPELLING = 'PAIR_ONE_SWSMI'
# A second driver whose command byte lives in its own header rather than in the .c that
# registers it. The file-local lookup both passes try first cannot see it, so this is what
# makes the whole-tree fallback a tested path rather than dead code.
FAR_VALUE = 0x55


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def c_code(text):
    """C with its comments removed.

    Not optional here. The generated harness explains, in comments, that the command byte
    never leaves the discovered set and that 0x04 reaches CpuHotplugSmm -- so an assertion
    that 0x04 is absent, or that mFirnessSwSmiCommands is what the command port is written
    from, passes on the explanation whatever the statements do.
    """
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def py_code(text):
    """Python with its docstring and comments removed, for the same reason."""
    found = re.search(r'"""', text)
    while found:
        closing = text.index('"""', found.end())
        text = text[:found.start()] + text[closing + 3:]
        found = re.search(r'"""', text)
    return '\n'.join(line for line in text.splitlines()
                     if not line.strip().startswith('#'))


class Handler:
    """A SmiInfo as the software SMI path holds one: an address, and no payload."""

    def __init__(self, name, type='', guid='', file='', buffer_protocol='',
                 field_constants=None, sw_smi_value=None, sw_smi_spelling=''):
        self.name = name
        self.type = type
        self.guid = guid
        self.file = file
        self.buffer_protocol = buffer_protocol
        self.field_constants = dict(field_constants or {})
        self.sw_smi_value = sw_smi_value
        self.sw_smi_spelling = sw_smi_spelling


def lift(path, names, extra=None):
    """Run the named top-level definitions out of a module without importing it.

    analyze_smi.py imports fuzzywuzzy at module scope and main.py imports analyze_smi, and
    neither is installed on a runner nor has anything to do with a port write. This
    compiles the real source of the real definitions, so these assertions still fail when
    they change.
    """
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
        raise SystemExit(f'{os.path.basename(path)} no longer defines: '
                         f'{", ".join(missing)}')
    space = {'os': os, 're': re, 'json': json, 'io': io, 'print': print,
             'Dict': dict, 'List': list, 'Tuple': tuple, 'Set': set,
             'SmiInfo': Handler,
             # report_smi_coverage reports each harnessed handler's lifecycle gate by
             # reading the tree. The fixture has no gates and they are not what this
             # checks, so it is answered rather than lifted.
             'lifecycle_gate': lambda name, edk2_dir: (None, None)}
    space.update(extra or {})
    exec(compile(ast.Module(body=want, type_ignores=[]), os.path.basename(path), 'exec'),
         space)
    return space


#
# One fixture file, two handlers, and exactly ONE attribute between them: the initialiser.
# Same context variable, same call shape, same signature, adjacent in the same function.
# So "PairOne resolves and PairTwo does not" is a statement about the initialiser and
# nothing else -- and because PairOne's assignment comes FIRST, a pass that takes the
# first assignment on a reused context gives PairTwo 0x70 instead of leaving it out.
#
PAIR_C = f'''\
#include <PiSmm.h>
#include <Protocol/SmmSwDispatch2.h>

#define {PAIR_SPELLING}  0x{PAIR_VALUE:02X}

EFI_STATUS
EFIAPI
PairOne (
  IN EFI_HANDLE DispatchHandle,
  IN CONST VOID *RegisterContext OPTIONAL,
  IN OUT VOID   *CommBuffer     OPTIONAL,
  IN OUT UINTN  *CommBufferSize OPTIONAL
  )
{{
  return EFI_SUCCESS;
}}

EFI_STATUS
EFIAPI
PairTwo (
  IN EFI_HANDLE DispatchHandle,
  IN CONST VOID *RegisterContext OPTIONAL,
  IN OUT VOID   *CommBuffer     OPTIONAL,
  IN OUT UINTN  *CommBufferSize OPTIONAL
  )
{{
  return EFI_SUCCESS;
}}

EFI_STATUS
EFIAPI
PairEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{{
  EFI_SMM_SW_REGISTER_CONTEXT  SwContext;
  EFI_HANDLE                   SwHandle;

  SwContext.SwSmiInputValue = {PAIR_SPELLING};
  Status = mSwDispatch->Register (mSwDispatch, PairOne, &SwContext, &SwHandle);

  SwContext.SwSmiInputValue = (UINTN)-1;
  Status = mSwDispatch->Register (mSwDispatch, PairTwo, &SwContext, &SwHandle);

  return EFI_SUCCESS;
}}
'''

#
# The two values the dispatcher itself refuses: 0, which every handler in the tree reads
# as "not a software SMI" and returns on, and anything above MAXIMUM_SWI_VALUE. Written
# exactly like PairOne so a rejection here is about the range and not about the shape.
#
EDGE_C = '''\
#include <Protocol/SmmSwDispatch2.h>

#define EDGE_ZERO_SWSMI  0x00
#define EDGE_HIGH_SWSMI  0x100

EFI_STATUS
EFIAPI
EdgeZero (
  IN EFI_HANDLE DispatchHandle,
  IN CONST VOID *RegisterContext OPTIONAL,
  IN OUT VOID   *CommBuffer     OPTIONAL,
  IN OUT UINTN  *CommBufferSize OPTIONAL
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EdgeHigh (
  IN EFI_HANDLE DispatchHandle,
  IN CONST VOID *RegisterContext OPTIONAL,
  IN OUT VOID   *CommBuffer     OPTIONAL,
  IN OUT UINTN  *CommBufferSize OPTIONAL
  )
{
  EFI_SMM_SW_REGISTER_CONTEXT  ZeroContext;
  EFI_SMM_SW_REGISTER_CONTEXT  HighContext;

  ZeroContext.SwSmiInputValue = EDGE_ZERO_SWSMI;
  Status = mSwDispatch->Register (mSwDispatch, EdgeZero, &ZeroContext, &ZeroHandle);

  HighContext.SwSmiInputValue = EDGE_HIGH_SWSMI;
  Status = mSwDispatch->Register (mSwDispatch, EdgeHigh, &HighContext, &HighHandle);

  return EFI_SUCCESS;
}
'''

# IoLib's real declaration, reduced to the one function the harness calls. used_libraries
# keeps a class when the emitted sources name something its header declares, so the header
# has to be here for that decision to be the real one.
IOLIB_H = '''\
#ifndef __IO_LIB_H__
#define __IO_LIB_H__
UINT8 EFIAPI IoRead8 (IN UINTN Port);
UINT8 EFIAPI IoWrite8 (IN UINTN Port, IN UINT8 Value);
#endif
'''

# A library class whose header the harness names nothing from. Present so "IoLib is kept"
# is a decision and not the pruning being off.
S3LIB_H = '''\
#ifndef __S3_BOOT_SCRIPT_LIB_H__
#define __S3_BOOT_SCRIPT_LIB_H__
RETURN_STATUS EFIAPI S3BootScriptSaveIoWrite (IN UINTN Width, IN UINT64 Address);
#endif
'''


FAR_H = f'''\
#ifndef __FAR_H__
#define __FAR_H__
#define FAR_SWSMI  0x{FAR_VALUE:02X}
#endif
'''

FAR_C = '''\
#include <Protocol/SmmSwDispatch2.h>
#include "Far.h"

EFI_STATUS
EFIAPI
FarHandler (
  IN EFI_HANDLE DispatchHandle,
  IN CONST VOID *RegisterContext OPTIONAL,
  IN OUT VOID   *CommBuffer     OPTIONAL,
  IN OUT UINTN  *CommBufferSize OPTIONAL
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FarEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_SMM_SW_REGISTER_CONTEXT  FarContext;

  FarContext.SwSmiInputValue = FAR_SWSMI;
  Status = mSwDispatch->Register (mSwDispatch, FarHandler, &FarContext, &FarHandle);

  return EFI_SUCCESS;
}
'''


def fixture_tree():
    """A tree shaped like edk2, with the two fixture drivers and IoLib's header in it."""
    root = tempfile.mkdtemp(prefix='swsmi-tree-')
    for where, text in (
            (os.path.join('OvmfPkg', 'Pair', 'Pair.c'), PAIR_C),
            (os.path.join('OvmfPkg', 'Edge', 'Edge.c'), EDGE_C),
            (os.path.join('OvmfPkg', 'Far', 'Far.c'), FAR_C),
            (os.path.join('OvmfPkg', 'Far', 'Far.h'), FAR_H),
            (os.path.join('MdePkg', 'Include', 'Library', 'IoLib.h'), IOLIB_H),
            (os.path.join('MdePkg', 'Include', 'Library', 'S3BootScriptLib.h'), S3LIB_H)):
        path = os.path.join(root, where)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        io.open(path, 'w', encoding='utf-8').write(text)
    return root


def generated(handlers):
    """FirnessHarnesses.c for these handlers, from the real template."""
    template = load(os.path.join(GEN, 'uefi_harness', 'sw_smi_harness_template.py'),
                    'sw_smi_harness_template')
    return '\n'.join(template.harness_generator(handlers)), template


def macros(text):
    """{FIRNESS_SWSMI_X: value} from the generated C's own #defines."""
    return {name: int(value, 0) for name, value
            in re.findall(r'#define\s+(FIRNESS_SWSMI_\w+)\s+(0[xX][0-9A-Fa-f]+)', text)}


def table(text):
    """The entries of mFirnessSwSmiCommands, in order, as written."""
    found = re.search(r'mFirnessSwSmiCommands\[\]\s*=\s*\{(.*?)\}', text, re.S)
    if not found:
        return []
    return [e.strip() for e in found.group(1).split(',') if e.strip()]


def assignments(text, variable):
    """Every right-hand side a STATEMENT assigns to `variable` in comment-stripped C.

    Anchored on the end of the previous statement so a declaration -- `UINT8 CommandPort
    = 0;` -- is not one of them. The declaration's initialiser is not a value the port can
    be written with: the selection below it is an if/else with no fall-through, and that
    exhaustiveness is asserted on its own rather than assumed here.
    """
    return [v.strip() for v in
            re.findall(rf'(?:^|[;{{}})])\s*{re.escape(variable)}\s*=\s*([^;]+);',
                       text, re.M)]


def main():
    tree = fixture_tree()
    work = tempfile.mkdtemp(prefix='swsmi-work-')
    discover = load(os.path.join(HERE, 'discover_smi.py'), 'discover_smi')
    space = lift(os.path.join(GEN, 'data_analysis', 'analyze_smi.py'), [
        'load_discovered', 'load_sw_discovered', 'load_smi_inventory',
        'write_smi_inventory', 'smi_inventory', 'report_smi_coverage',
        'not_harnessed_reason', '_channel_of', '_sw_smi_reason', '_dispatch_reason',
        'DEFINITE_DISPATCH', 'DISPATCH_REASON', 'DISPATCH_CHANNEL',
        'SW_COMMAND_PORT', 'SW_DATA_PORT', 'SW_VALUE_MIN', 'SW_VALUE_MAX',
        '_SW_REGISTER', '_SW_VALUE', '_SW_CAST', '_SW_DEFINE',
        '_sw_unwrap', '_sw_constant', '_sw_define_index', 'sw_smi_commands',
        'analyze_sw_smi'])

    print('discovery finds the value the tree registers, through the name it spells it with')
    found, unresolved = discover.discover_sw_smi(tree)
    check('the handler with a constant registration is found',
          'PairOne' in found, f'{sorted(found)}')
    check('at the value its #define carries, not at a value the harness knows',
          found.get('PairOne', (None,))[0] == PAIR_VALUE,
          f'{found.get("PairOne")} -- the fixture registers 0x{PAIR_VALUE:02X} and '
          f'nothing in the pipeline may assume the 0xB4 EVAL-1 happens to use')
    check('resolved through the #define rather than off a literal',
          found.get('PairOne', (None, None, None))[2] == PAIR_SPELLING,
          f'{found.get("PairOne")} -- the registration names {PAIR_SPELLING}, so a pass '
          f'that only reads integer literals finds nothing here')
    cited = 1 + PAIR_C[:PAIR_C.index(f'SwContext.SwSmiInputValue = {PAIR_SPELLING}')] \
        .count('\n')
    check('and cited to the registration it was read out of',
          found.get('PairOne', (None, ''))[1].endswith(f'Pair.c:{cited}'),
          f'{found.get("PairOne")} -- a command byte is an arbitrary number whose only '
          f'justification is the line that asked for it')

    print('\nand does not invent one for a registration that has none')
    check('a handler registered for (UINTN)-1 is not a target',
          'PairTwo' not in found,
          f'{found.get("PairTwo")} -- the dispatcher picks that byte at registration '
          f'time, so any value here addresses whichever handler landed in the slot')
    check('it is counted and named rather than dropped silently',
          'PairTwo' in unresolved and unresolved['PairTwo'][0] == '-1',
          f'{unresolved} -- a handler absent from both lists reads as a tree that has no '
          f'such handler')
    check('and it did not inherit the value of the registration above it',
          found.get('PairTwo') is None
          and all(v[0] != PAIR_VALUE for k, v in found.items() if k != 'PairOne'),
          f'{found} -- one SwContext serves both registrations, so a pass that takes the '
          f'first assignment gives PairTwo 0x{PAIR_VALUE:02X}')
    check('a constant defined in another file resolves too',
          found.get('FarHandler', (None,))[0] == FAR_VALUE
          and seen_far(space, tree) == FAR_VALUE,
          f'{found.get("FarHandler")} / {seen_far(space, tree)} -- a driver that keeps its '
          f'command byte in its own header is the shape a file-local lookup misses, and '
          f'the two passes have to miss or find it together')
    check('a value the dispatcher refuses is not a target either',
          'EdgeZero' not in found and 'EdgeHigh' not in found,
          f'{sorted(found)} -- 0 is read as "not a software SMI" by every handler in the '
          f'tree and MAXIMUM_SWI_VALUE is 0xFF, so neither addresses anything')

    print('\nthe generator and the request file agree, being two passes over one tree')
    seen, stuck = space['sw_smi_commands'](tree)
    check('the generator\'s own scan finds the same handler',
          sorted(seen) == sorted(found), f'{sorted(seen)} != {sorted(found)}')
    check('at the same value', seen.get('PairOne', {}).get('value') == PAIR_VALUE,
          f'{seen.get("PairOne")} -- these are the same discovery written twice, in two '
          f'repositories, and a disagreement is drift no campaign can see')
    check('and leaves the same one unaddressable',
          sorted(stuck) == sorted(unresolved), f'{sorted(stuck)} != {sorted(unresolved)}')

    request = os.path.join(work, 'DiscoveredSwSmi.txt')
    discover.write_sw_smi(tree, request)
    asked = space['load_sw_discovered'](request)
    check('the request file round-trips the value',
          asked.get('PairOne', {}).get('value') == PAIR_VALUE, f'{asked}')
    check('and its first field is still a handler name the old loader reads',
          space['load_discovered'](request) == ['FarHandler', 'PairOne'],
          f'{space["load_discovered"](request)} -- the comm-buffer loader reads this '
          f'directory too')

    print('\nthe harness writes the two ports, data first')
    smi_data = space['analyze_sw_smi'](asked, tree, space['load_discovered'](request),
                                       os.path.join(work, 'smi-function-guid-map.json'))
    check('the target set is the addressable handlers',
          sorted(smi_data) == ['FarHandler', 'PairOne'], f'{sorted(smi_data)}')
    text, template = generated(smi_data)
    body = c_code(text)
    ports = {name: int(value, 0) for name, value in
             re.findall(r'#define\s+(FIRNESS_SW_SMI_\w+_PORT)\s+(0[xX][0-9A-Fa-f]+)', body)}
    check('the command port is 0xB2 and the data port 0xB3',
          ports.get('FIRNESS_SW_SMI_COMMAND_PORT') == 0xB2
          and ports.get('FIRNESS_SW_SMI_DATA_PORT') == 0xB3, f'{ports}')
    writes = re.findall(r'IoWrite8\s*\(\s*(FIRNESS_SW_SMI_\w+_PORT)\s*,\s*(\w+)\s*\)', body)
    check('both ports are written, data first, once per target',
          [w[0] for w in writes] == ['FIRNESS_SW_SMI_DATA_PORT',
                                     'FIRNESS_SW_SMI_COMMAND_PORT'] * len(smi_data),
          f'{writes} -- the data port is a scratchpad and the command port is what raises '
          f'the SMI, so the other order raises it on the previous iteration\'s data byte')
    check('nothing else in the harness touches IO',
          len(re.findall(r'\bIo(?:Write|Read|Or|And)\w*\s*\(', body)) == len(writes),
          re.findall(r'\bIo\w+\s*\(', body))
    check('the sanitizer is armed across the write and closed after it',
          re.search(r'FirnessSanitizer\(TRUE\);(?:[^;]*;){2}\s*FirnessSanitizer\(FALSE\);',
                    body) is not None,
          'without the arming a fault inside the handler is logged and then dropped, and '
          'the campaign is not credited with it')

    print('\nthe command byte cannot leave the discovered set')
    declared = macros(body)
    check('each handler\'s registered byte is a macro of its own',
          declared == {template.command_macro('PairOne'): PAIR_VALUE,
                       template.command_macro('FarHandler'): FAR_VALUE}, f'{declared}')
    check('and a target can be sent a sibling\'s byte as well as its own',
          len(set(declared.values())) > 1
          and any(v.startswith('mFirnessSwSmiCommands[')
                  for v in assignments(body, 'CommandPort')),
          f'{declared} -- a dispatcher that confuses two registered commands is only '
          f'visible if both are sent')
    check('the table is built from those macros, not from a second list of numbers',
          table(body) == sorted(declared),
          f'{table(body)} -- two spellings of one value is how the confinement drifts')
    written = assignments(body, 'CommandPort')
    arms = re.search(r'if\s*\(.*?\)\s*\{\s*CommandPort\s*=\s*([^;]+);\s*\}'
                     r'\s*else\s*\{\s*CommandPort\s*=\s*([^;]+);\s*\}', body, re.S)
    check('the command byte is chosen by an if/else with no fall-through',
          arms is not None,
          f'{body[body.index("CommandPort"):][:200]!r} -- with an arm missing, the '
          f'declaration\'s 0 reaches the port, and 0 is the byte OVMF\'s own '
          f'SmmControl2 Trigger writes')
    check('every value the command port is given comes from the set',
          written and all(v in declared
                          or v.startswith('mFirnessSwSmiCommands[') for v in written),
          f'{written}')
    check('and none of them is a literal',
          not any(re.match(r'^[\d(]', v) for v in written),
          f'{written} -- a literal here is a byte discovery never found, and on port '
          f'0xB2 that can be the platform\'s own')
    check('the index into the set is taken modulo its length',
          all('% FIRNESS_SW_SMI_COMMAND_COUNT' in v
              for v in written if v.startswith('mFirnessSwSmiCommands[')),
          f'{written} -- an unbounded index reads past the table and writes whatever '
          f'follows it to the port')
    check('the platform\'s own command bytes are nowhere in the harness',
          0x00 not in declared.values() and 0x04 not in declared.values()
          and '0x04' not in body,
          f'{declared} -- 0x04 is ICH9_APM_CNT_CPU_HOTPLUG, whose error paths '
          f'CpuDeadLoop() inside SMM, and 0 is what SmmControl2 Trigger writes')
    check('and the data byte is fuzzed, which is the rest of what the channel carries',
          'ReadBytes(Input, sizeof(DataPort)' in body,
          'without it the channel has one input and every iteration is the same one')

    print('\nIoLib survives the pruning that drops what the harness never calls')
    main_space = lift(os.path.join(GEN, 'main.py'), ['used_libraries', 'CORE_LIBRARIES'])
    folder = os.path.join(work, 'harness')
    os.makedirs(folder, exist_ok=True)
    io.open(os.path.join(folder, 'FirnessHarnesses.c'), 'w', encoding='utf-8').write(text)
    libraries = {'IoLib': 'MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf',
                 'S3BootScriptLib': 'MdeModulePkg/Library/PiDxeS3BootScriptLib.inf'}
    with contextlib.redirect_stdout(io.StringIO()):
        kept = main_space['used_libraries'](libraries, folder, [], tree)
    check('IoLib is linked because the harness calls IoWrite8', 'IoLib' in kept,
          f'{sorted(kept)} -- the INF is what edk2 links, and without the class the '
          f'build fails at link time on an unresolved IoWrite8')
    check('and the pruning is still doing its job beside it',
          'S3BootScriptLib' not in kept,
          f'{sorted(kept)} -- a library nothing calls still runs its constructor, and '
          f'PiDxeS3BootScriptLib alone accounted for 545 reports attributed to the '
          f'harness. "IoLib is kept" has to be a decision, not the pruning being off')
    comm = '#include "FirnessHarnesses.h"\nEFI_STATUS Fuzz(VOID) { return Communicate(); }'
    io.open(os.path.join(folder, 'FirnessHarnesses.c'), 'w', encoding='utf-8').write(comm)
    with contextlib.redirect_stdout(io.StringIO()):
        without = main_space['used_libraries'](libraries, folder, [], tree)
    check('a harness that does not call it does not get it', 'IoLib' not in without,
          f'{sorted(without)} -- this is the comm-buffer harness, which is why IoLib was '
          f'absent from its INF and why adding the call is what keeps it')

    print('\nthe inventory names the channel that reaches each handler')
    inventory = json.loads(io.open(os.path.join(work, 'smi-handler-inventory.json'),
                                   encoding='utf-8').read())
    port = space['DISPATCH_CHANNEL']['SwDispatch']
    check('a handler on this channel says so', inventory['PairOne']['Channel'] == port,
          f'{inventory["PairOne"]}')
    check('and carries the command byte that addresses it',
          inventory['PairOne']['SwSmiInputValue'] == f'0x{PAIR_VALUE:02X}',
          f'{inventory["PairOne"]}')
    check('it is harnessable in the run that drives the channel',
          inventory['PairOne']['Harnessable'] is True
          and inventory['PairOne']['Reason'] == '', f'{inventory["PairOne"]}')
    # .get, not [] -- a handler missing from the file altogether is the failure mode
    # this row exists to catch, and it must read as a failed assertion rather than as a
    # check that crashed.
    absent = inventory.get('PairTwo', {})
    check('the one with no static address is in the file and names the channel anyway',
          absent.get('Channel') == port and not absent.get('Harnessable'),
          f'{absent or "no row at all"} -- it IS reached by a port write; what it has '
          f'not got is a byte a static pass can name, and a handler with no row reads as '
          f'a tree that has no such handler')
    check('and says that, rather than that nothing can drive it',
          'software SMI port' in absent.get('Reason', '')
          and 'no static pass' in absent.get('Reason', ''),
          f'{absent.get("Reason")!r} -- the obstruction is the registration, '
          f'not the handler, and a reader has to be able to tell those apart')

    print('\nand a comm-buffer run points at this target instead of calling it undrivable')
    analyzer = {'PairOne': {'Guid': '', 'Type': '', 'File': '', 'Dispatch': 'SwDispatch',
                            'BufferProtocol': '', 'AnalyzerTyped': False}}
    rows = space['smi_inventory']({}, ['PairOne'], {}, {}, analyzer, (seen, stuck),
                                  space['DISPATCH_CHANNEL']['SmiHandlerRegister'])
    check('the row carries the command byte even where no harness holds it',
          rows['PairOne']['SwSmiInputValue'] == f'0x{PAIR_VALUE:02X}',
          f'{rows["PairOne"]} -- in a comm-buffer run nothing in smi_data knows this '
          f'value, so the scan is the only thing that can put it there')
    check('the row names the command byte a reader would have to go and find',
          f'0x{PAIR_VALUE:02X}' in rows['PairOne']['Reason'], rows['PairOne']['Reason'])
    check('and names the target that writes it',
          'DiscoveredSwSmi' in rows['PairOne']['Reason'], rows['PairOne']['Reason'])
    check('the old wording no longer stands alone for a handler this reaches',
          'cannot drive it' not in rows['PairOne']['Reason'],
          f'{rows["PairOne"]["Reason"]!r} -- correct about the comm buffer, and read as a '
          f'statement that nothing reaches the handler')
    spoken = io.StringIO()
    with contextlib.redirect_stdout(spoken):
        space['report_smi_coverage']({}, ['PairOne'], {}, {}, tree, analyzer,
                                     (seen, stuck),
                                     space['DISPATCH_CHANNEL']['SmiHandlerRegister'])
    said = spoken.getvalue()
    check('and the run says the same thing the file does',
          rows['PairOne']['Reason'] in said,
          f'{said!r} -- a file that explains a handler differently from the run that '
          f'wrote it is a second answer to argue with')

    print('\nthe target is a campaign, and only with the mode it needs')
    batch = py_code(io.open(os.path.join(HERE, 'fuzz_batch.py'), encoding='utf-8').read())
    check('fuzz_batch knows the request file',
          "'DiscoveredSwSmi.txt'" in batch, 'otherwise it is fuzzed as a protocol')
    commands = dry_run(['DiscoveredSwSmi', 'DiscoveredSmi', 'EfiAcpiTable'])
    check('the software SMI target is given --sw-smi',
          '--sw-smi' in commands.get('DiscoveredSwSmi', ''),
          commands.get('DiscoveredSwSmi', '(no line)'))
    check('and --smi with it, which is what carries the SMM build',
          ' --smi' in commands.get('DiscoveredSwSmi', ''),
          commands.get('DiscoveredSwSmi', '(no line)'))
    check('the comm-buffer target is not given --sw-smi',
          '--sw-smi' not in commands.get('DiscoveredSmi', ''),
          f'{commands.get("DiscoveredSmi", "(no line)")} -- one request file, one channel')
    check('and no protocol campaign is given either flag',
          '--smi' not in commands.get('EfiAcpiTable', ''),
          f'{commands.get("EfiAcpiTable", "(no line)")} -- the generator re-reads -i as a '
          f'handler list under --smi, so a protocol campaign that gets it builds the SMI '
          f'harness instead of its own')

    print('\nthe target survives a bounded run, and only when it has a file')
    edk2 = load(os.path.join(HERE, 'fuzz_edk2.py'), 'fuzz_edk2')
    evalset = os.path.join(work, 'evalset')
    os.makedirs(evalset, exist_ok=True)
    for name in ('AndroidBootImg', 'ArmScmiBase', 'DiscoveredSmi', 'DiscoveredSwSmi'):
        io.open(os.path.join(evalset, f'{name}.txt'), 'w', encoding='utf-8').write('x\n')
    picked = edk2.pick_targets(evalset, 2, True)
    check('a bounded --smi run picks the two SMI targets, not the alphabetical head',
          sorted(picked) == ['DiscoveredSmi', 'DiscoveredSwSmi'],
          f'{picked} -- AndroidBootImg and ArmScmiBase are the head of the discovered '
          f'set and OvmfPkgX64 does not build either, so a bounded run that takes them '
          f'fuzzes nothing and reports like a clean one')
    check('and neither SMI target is offered as a protocol',
          'DiscoveredSwSmi' not in edk2.pick_targets(evalset, 4, False),
          f'{edk2.pick_targets(evalset, 4, False)} -- its request file carries command '
          f'bytes, not a GUID, so a protocol campaign dies in the generator')
    os.remove(os.path.join(evalset, 'DiscoveredSwSmi.txt'))
    check('a tree whose discovery wrote no file is not given the target',
          'DiscoveredSwSmi' not in edk2.pick_targets(evalset, 4, True),
          f'{edk2.pick_targets(evalset, 4, True)} -- naming a target with no request '
          f'file costs a container, an analysis and a build to find that out')

    print('\nthe flag is refused where it would silently do nothing')
    #
    # Read as a guard, not run as a process: firness.py imports matplotlib and main.py
    # imports fuzzywuzzy, neither of which a runner has, so both die at import before
    # argparse sees anything. The AST is why this is not a grep -- every one of these
    # files explains the flag it refuses in a comment beside the refusal.
    #
    for script in ('firness.py', os.path.join(GEN, 'main.py')):
        path = script if os.path.isabs(script) else os.path.join(HERE, script)
        guard, said = refuses(path)
        check(f'{os.path.basename(script)} refuses --sw-smi without --smi', guard,
              f'without it the generator falls through to the protocol path and reads '
              f'the request file as a protocol list, which is the failure that made '
              f'44 campaigns in run 42140097717 share one harness')
        check(f'{os.path.basename(script)} says which flag is missing',
              any('needs --smi' in text for text in said),
              f'{said} -- "unrecognized arguments" is what the other wording looks like '
              f'from the outside')

    print('\na tree with nothing to aim at gets no target, not an empty one')
    empty = tempfile.mkdtemp(prefix='swsmi-empty-')
    stale = os.path.join(empty, 'DiscoveredSwSmi.txt')
    io.open(stale, 'w', encoding='utf-8').write('Carried  0xB4  // from another tree\n')
    with contextlib.redirect_stdout(io.StringIO()):
        discover.write_sw_smi(empty, stale)
    check('no request file is left behind', not os.path.exists(stale),
          'the batch makes a campaign out of every .txt, so an empty list costs a '
          'container, an analysis and a build -- and a stale one aims this tree\'s '
          'campaign at another tree\'s command bytes')

    for path in (tree, work, empty):
        shutil.rmtree(path, ignore_errors=True)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def seen_far(space, tree):
    """The generator-side scan's answer for the cross-file constant."""
    return (space['sw_smi_commands'](tree)[0].get('FarHandler') or {}).get('value')


def refuses(path):
    """Whether this module guards --sw-smi on --smi, and what it says when it refuses.

    Structural: an `if` whose test names both options and whose body returns 1. A source
    grep cannot answer it -- the comment beside each refusal quotes the flag and the
    failure it prevents, so a substring search passes on the prose whatever the code does.
    """
    tree = ast.parse(io.open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        # The shape, not the spelling: `if False and args.sw_smi and not args.smi:`
        # dumps with both names in it and refuses nothing, which is exactly what a
        # disabled guard looks like.
        test = node.test
        if not isinstance(test, ast.BoolOp) or not isinstance(test.op, ast.And):
            continue
        if len(test.values) != 2:
            continue
        first, second = test.values
        if getattr(first, 'attr', None) != 'sw_smi':
            continue
        if not isinstance(second, ast.UnaryOp) or not isinstance(second.op, ast.Not):
            continue
        if getattr(second.operand, 'attr', None) not in ('smi', 'smi_enabled'):
            continue
        refused = any(isinstance(inner, ast.Return)
                      and getattr(inner.value, 'value', None) == 1
                      for inner in ast.walk(node))
        if refused:
            return True, [inner.value for inner in ast.walk(node)
                          if isinstance(inner, ast.Constant)
                          and isinstance(inner.value, str)]
    return False, []


def dry_run(protocols):
    """fuzz_batch's own --dry-run, in its own process, with docker stubbed out on PATH.

    The command line is the real one and so is every decision on the way to it. Driven
    rather than read because launch()'s comment quotes both flags and the error it is
    avoiding, so a substring search over the source passes on the prose.
    """
    work = tempfile.mkdtemp(prefix='swsmi-dry-')
    try:
        shim = os.path.join(work, 'bin')
        os.makedirs(shim)
        docker = os.path.join(shim, 'docker')
        io.open(docker, 'w', encoding='utf-8').write('#!/bin/sh\nexit 0\n')
        os.chmod(docker, 0o755)
        env = {k: v for k, v in os.environ.items() if not k.startswith('FIRNESS_')}
        env['PATH'] = shim + os.pathsep + env.get('PATH', '')
        argv = [sys.executable, os.path.join(HERE, 'fuzz_batch.py'),
                '-o', os.path.join(work, 'out'), '-p'] + list(protocols) + [
                    '--no-discover', '--dry-run', '--backend', 'qemu', '--smi',
                    '--tree', os.path.join(work, 'empty')]
        result = subprocess.run(argv, capture_output=True, text=True, env=env)
        commands = {}
        for line in result.stdout.splitlines():
            if 'would run:' not in line:
                continue
            found = re.search(r'-i /input/\S*/(\w+)\.txt', line)
            if found:
                commands[found.group(1)] = line
        return commands
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
