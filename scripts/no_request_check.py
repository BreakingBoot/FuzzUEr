#!/usr/bin/env python3
"""Assert a protocol whose members are all typed from an included header gets a request
file at all -- and that opening that gate admits exactly one protocol and nothing else.

gen_protocol_inputs.py opened scan_header with `fptypes = set(FPTYPE_RE.findall(src))`
and then `if not fptypes: return None`, which reads "a header that declares no function-
pointer typedef of its own is not a protocol header". For a protocol whose whole callable
surface is typed from an #include that is false, and the consequence is total: no request
file, no campaign, and nothing in any log saying the protocol was skipped. The worked
example is gEdkiiSmmVarCheckProtocolGuid -- MdeModulePkg/Include/Protocol/SmmVarCheck.h
declares the GUID, declares struct _EDKII_SMM_VAR_CHECK_PROTOCOL with three members, and
declares not one typedef: all three are EDKII_VAR_CHECK_* from <Protocol/VarCheck.h>. It
is installed at MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.c:1180.

Measured, not assumed. Every protocol GUID each tree declares extern or installs at an
Install*ProtocolInterface call, against the request files the generator emits at -m 1:
eval1_edk2 390 GUIDs / 271 files / 119 with none, edk2-master 395 / 274 / 121,
eval_source/edk2 388 / 268 / 120. Six reasons, and this gate is the largest at 69 on all
three trees. 69 is NOT the size of the hole: of those 69, exactly three have any callable
member even when the typedef set is widened to every function-pointer typedef in the tree
-- gEdkiiSmmVarCheckProtocolGuid (3), gEfiSmmVariableProtocolGuid (4) and
gEfiLoadedImageProtocolGuid (1). The other 66 are GUID-only signal protocols, arch
protocols installed with a NULL interface, data-only structs, and typedef aliases whose
struct is in another header. None is hidden by the typedef scope.

Two of the three are refused, and not because of the depth bound:

  * gEfiSmmVariableProtocolGuid is typed from Uefi/UefiSpec.h, which SmmVariable.h does
    not include -- it includes nothing, because every edk2 source has UefiSpec.h in scope
    through Uefi.h -- so no include closure reaches it at any depth. Which is fortunate:
    VariableTraditionalMm.c's VariableNotifySmmReady() installs the GUID into the DXE
    handle database with a NULL interface as a readiness signal, while the real interface
    goes in through gMmst->MmInstallProtocolInterface inside SMRAM. A harness would
    LocateProtocol, get EFI_SUCCESS and NULL, and dereference it on the next line -- and
    the presence census cannot save it, because it reads the DXE install line and says
    `present`.
  * gEfiLoadedImageProtocolGuid has one member, Unload, from the same unreachable header,
    optional by spec and NULL on the image DxeCore installs first. Same NULL call.

So ADMIT_RESOLVED_ONLY runs only for a header whose LOCAL typedef set is empty -- the one
case the old code refused outright -- and admits only a GUID that owns a struct there. The
whole-header fallback is not reachable from it, which is what keeps the 66 out:
gEfiRuntimeArchProtocolGuid is the proof, since Runtime.h has no local typedef and does
have EFI_RUNTIME_EVENT_ENTRY.NotifyFunction typed EFI_EVENT_NOTIFY.

Effect at -m 1 on three trees: one file added, EdkiiSmmVarCheck.txt; none removed; every
other file byte identical. With ADMIT_RESOLVED_ONLY False, `diff -r` identical to before
on all three. Unlike the two earlier fixes the set DOES move at every --min-methods, the
argparse default of 3 included, because the new file has exactly 3 members.

Known blocker, measured and owned elsewhere. firness builds a target from a call site or,
failing that, from the protocol's own header, and data_analysis/analyze.py's
protocol_member_params() reads only the member's own header, so an include-typed member
returns None and is dropped. Run offline against the EdkiiVarCheck campaign of sweep
43454245046 -- same tree, same databases, same command, only the request file swapped --
the DXE sibling gives "Total Functions: 3" and rc 0 while EdkiiSmmVarCheck.txt gives three
"was not able to be harnessed" warnings, "Total Functions: 0" and the ValueError
fuzz_edk2.py already classifies as NO_CALL_SITES, which is named and explicitly not a
failure. With protocol_member_params() resolving the include in a scratch copy the same
command emits FuzzSmmRegisterSetVariableCheckHandler, FuzzSmmVariablePropertySet and
FuzzSmmVariablePropertyGet: 3 of 3. The request file is the prerequisite and the only part
that lives here.

Run: python3 scripts/no_request_check.py
"""

import importlib.util
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN = os.path.join(ROOT, 'firness', 'harness_generator')

# The two Include/Protocol directories the measurement was taken on. Absent on a runner,
# where the assertions that read them are skipped and said to be skipped.
TREES = [os.path.join('/home/gl055/eval-trees/eval1_edk2', pkg, 'Include', 'Protocol')
         for pkg in ('MdePkg', 'MdeModulePkg')]

HOLDERS = []
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

    The comment above this fix names every spelling under test: ADMIT_RESOLVED_ONLY, the
    two GUIDs that must NOT become request files, struct_members. A source assertion made
    against the raw text finds its string in the paragraph explaining why the statement
    exists, and passes with the statement deleted. That is the mutation this project has
    let through before.
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


def body_of(text, name):
    """One top-level definition's source, so an assertion about it cannot read another's.

    `return None` appears a hundred times in analyze.py, and a whole-file find() for it
    reports a hit from somewhere else and passes with the statement under test deleted.
    """
    start = text.find(f'def {name}(')
    if start < 0:
        return ''
    rest = text[start:]
    nxt = re.search(r'\n(?=\S)', rest[len(f'def {name}('):])
    return rest if not nxt else rest[:len(f'def {name}(') + nxt.start() + 1]


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not.

    A bare .index() on an anchor a mutation deleted raises, and a check that dies on its
    own traceback has not caught anything -- it has stopped reporting.
    """
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


# ---------------------------------------------------------------------------------------
# Fixtures. Every pair differs in exactly ONE attribute, so a pass cannot be explained by
# the other difference. SvcBase.h exists in every tree below, included or not, so that
# "the typedefs are somewhere in the tree" is never what moves.

AWAY = ('typedef EFI_STATUS (EFIAPI *EFI_SVC_FIRST)(VOID);\n'
        'typedef EFI_STATUS (EFIAPI *EFI_SVC_SECOND)(VOID);\n'
        'typedef EFI_STATUS (EFIAPI *EFI_SVC_THIRD)(VOID);\n')

INCLUDE = '#include <Protocol/SvcBase.h>'

# the SmmVarCheck.h shape: a GUID, a struct, three members, no typedef of its own
NOLOCAL = '''
%s
extern EFI_GUID  gEfiSvcProtocolGuid;
struct _EFI_SVC_PROTOCOL {
  EFI_SVC_FIRST     First;
  EFI_SVC_SECOND    Second;
  EFI_SVC_THIRD     Third;
};
'''


def tree(head, base=AWAY):
    return {'Include/Protocol/Svc.h': head, 'Include/Protocol/SvcBase.h': base}


NOLOCAL_TREE = tree(NOLOCAL % INCLUDE)
# the control: the three typedefs written into the file instead of included. SvcBase.h is
# still there and still declares them; the only thing that moves is which file the
# protocol header reads them from
LOCAL_TREE = tree(NOLOCAL % AWAY)
# the SmmVariable.h / LoadedImage.h shape: no typedef of its own AND no include, so the
# typedefs are in the tree and out of reach at every depth
UNREACHABLE_TREE = tree(NOLOCAL % '')

# the gEfiSmmReadyToLockProtocolGuid shape: a GUID and no struct at all
NOSTRUCT_TREE = tree(f'{INCLUDE}\nextern EFI_GUID  gEfiSvcProtocolGuid;\n')

# the gEfiRuntimeArchProtocolGuid shape: no local typedef, the GUID's struct is data only,
# and a DIFFERENT struct in the same header has a function-pointer member. Under the old
# whole-header fallback that member becomes the protocol's; it must not here.
CALLBACK = '''
%s
extern EFI_GUID  gEfiSvcProtocolGuid;
struct _EFI_SVC_EVENT_ENTRY {
  EFI_SVC_FIRST     NotifyFunction;
};
struct _EFI_SVC_PROTOCOL {
  UINTN             Count;
  BOOLEAN           AtRuntime;
};
'''
CALLBACK_TREE = tree(CALLBACK % INCLUDE)
# and the control that makes the assertion above non-vacuous: the same header with the
# function-pointer member moved into the protocol's own struct
CALLBACK_OWNED_TREE = tree(
    (CALLBACK % INCLUDE).replace('  UINTN             Count;',
                                 '  EFI_SVC_FIRST     NotifyFunction;'))

# the EFI_PCI_IO_PROTOCOL shape from 423e260f, in a header with no typedef of its own:
# the leaves are reached through by-value sub-structs and must still be named by the leaf
NESTED = '''
%s
extern EFI_GUID  gEfiSvcProtocolGuid;
typedef struct {
  EFI_SVC_FIRST     Read;
  EFI_SVC_SECOND    Write;
} EFI_SVC_ACCESS;
struct _EFI_SVC_PROTOCOL {
  EFI_SVC_ACCESS    Mem;
  EFI_SVC_ACCESS    Io;
  EFI_SVC_THIRD     Flush;
};
'''
NESTED_TREE = tree(NESTED % INCLUDE)
# only the declarator moves: a pointer member is a separate object the protocol may leave
# NULL, so the walk must not descend into it
POINTER_TREE = tree((NESTED % INCLUDE).replace('EFI_SVC_ACCESS    Mem;',
                                               'EFI_SVC_ACCESS    *Mem;')
                                      .replace('EFI_SVC_ACCESS    Io;',
                                               'EFI_SVC_ACCESS    *Io;'))
# and the e6dd94c6 collision, now on the new path: the included header also declares
# EFI_SVC_ACCESS as a function-pointer typedef. The local struct of that name must win, or
# Mem becomes a leaf and Read and Write are stranded.
COLLIDE_TREE = tree(NESTED % INCLUDE,
                    AWAY + 'typedef EFI_STATUS (EFIAPI *EFI_SVC_ACCESS)(VOID);\n')

# the NOT_TARGETS shape: the same admissible header under a name discovery must skip
SKIPPED_TREE = {'Include/Protocol/AsanFault.h': NOLOCAL % INCLUDE,
                'Include/Protocol/SvcBase.h': AWAY}


def lay(files):
    """Write {relative path: text} into a fresh directory, return its Protocol root."""
    holder = tempfile.mkdtemp()
    HOLDERS.append(holder)
    for rel, text in files.items():
        path = os.path.join(holder, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        io.open(path, 'w').write(text)
    return os.path.join(holder, 'Include', 'Protocol')


def found(gpi, files, skip=None):
    """{guid: (header, members)} for a fixture tree, as scan_roots reports it."""
    root = lay(files)
    return (gpi.scan_roots([root], skip) if skip is not None
            else gpi.scan_roots([root]))


def members(gpi, files, guid='gEfiSvcProtocolGuid'):
    return found(gpi, files).get(guid, ('', []))[1]


def written(gpi, files, min_methods=1):
    """The request file NAMES write_inputs produces for a fixture tree."""
    out = tempfile.mkdtemp()
    HOLDERS.append(out)
    stdout, sys.stdout = sys.stdout, io.StringIO()
    try:
        gpi.write_inputs(found(gpi, files), out, min_methods, 0)
    finally:
        sys.stdout = stdout
    return sorted(os.listdir(out))


def file_of(gpi, files, guid='gEfiSvcProtocolGuid'):
    """The request file for one protocol of a fixture tree, as text."""
    out = tempfile.mkdtemp()
    HOLDERS.append(out)
    got = found(gpi, files)
    stdout, sys.stdout = sys.stdout, io.StringIO()
    try:
        gpi.write_inputs({guid: got[guid]} if guid in got else {}, out, 1, 0)
    finally:
        sys.stdout = stdout
    names = os.listdir(out)
    return io.open(os.path.join(out, names[0]), encoding='utf-8').read() if names else ''


class shut:
    """ADMIT_RESOLVED_ONLY forced off: the pre-change decision, new code still running.

    scan_header reads the constant as a module global at call time, so setting it on the
    loaded module is the whole switch -- which is also why it can be the inert-in-isolation
    proof rather than a separate copy of the file.
    """

    def __init__(self, gpi):
        self.gpi = gpi

    def __enter__(self):
        self.real = self.gpi.ADMIT_RESOLVED_ONLY
        self.gpi.ADMIT_RESOLVED_ONLY = False

    def __exit__(self, *_):
        self.gpi.ADMIT_RESOLVED_ONLY = self.real


class flat:
    """INCLUDE_DEPTH forced to 0, so resolution reaches nothing it did not before."""

    def __init__(self, gpi):
        self.gpi = gpi

    def __enter__(self):
        self.real = self.gpi.resolved_fptypes
        self.gpi.resolved_fptypes = (lambda path, src, includes=None, depth=0:
                                     self.real(path, src, includes, 0))

    def __exit__(self, *_):
        self.gpi.resolved_fptypes = self.real


def _shut(gpi, call):
    """`call()` with the gate off. A function, so a mutation cannot reorder the two."""
    with shut(gpi):
        return call()


def main():
    gpi = load('gen_protocol_inputs')
    gsrc = code(source('gen_protocol_inputs'))
    raw = source('gen_protocol_inputs')

    print('a protocol whose members are all typed from an include gets a request file')
    check('the GUID is reported at all, which it was not before',
          list(found(gpi, NOLOCAL_TREE)) == ['gEfiSvcProtocolGuid'],
          f'{found(gpi, NOLOCAL_TREE)} -- this is the SmmVarCheck.h shape')
    check('and it asks for all three members, in declaration order',
          members(gpi, NOLOCAL_TREE) == ['First', 'Second', 'Third'],
          f'{members(gpi, NOLOCAL_TREE)}')
    check('the request file is named from the GUID, not the header',
          written(gpi, NOLOCAL_TREE) == ['EfiSvc.txt'],
          f'{written(gpi, NOLOCAL_TREE)}')
    control = members(gpi, LOCAL_TREE)
    check('the control -- the same header with those typedefs written into it -- agrees',
          control == members(gpi, NOLOCAL_TREE),
          f'{control} vs {members(gpi, NOLOCAL_TREE)} -- if these differ the fixture is '
          f'measuring something other than which file the typedefs are in')
    body = file_of(gpi, NOLOCAL_TREE)
    check('every member line is guid:leaf, as 423e260f established',
          [l.strip() for l in body.splitlines() if ':' in l and '//' not in l]
          == ['gEfiSvcProtocolGuid:First', 'gEfiSvcProtocolGuid:Second',
              'gEfiSvcProtocolGuid:Third'], f'{body!r}')
    check('and no line carries a dotted path or a typedef name',
          all('.' not in l.split(':')[-1] and not l.split(':')[-1].strip().isupper()
              for l in body.splitlines() if ':' in l and '//' not in l), f'{body!r}')

    print('\nthe gate is bounded by a constant that names itself')
    check('ADMIT_RESOLVED_ONLY exists and is a module-level assignment',
          hasattr(gpi, 'ADMIT_RESOLVED_ONLY')
          and re.search(r'^ADMIT_RESOLVED_ONLY = (True|False)$', gsrc, re.M) is not None,
          'a gate with no switch cannot be proved inert')
    check('it is on by default', gpi.ADMIT_RESOLVED_ONLY is True)
    check('with it off the admissible header yields nothing again',
          _shut(gpi, lambda: written(gpi, NOLOCAL_TREE)) == [],
          f'{_shut(gpi, lambda: written(gpi, NOLOCAL_TREE))}')
    check('with it off the control is still a protocol, so the switch is not a mute',
          _shut(gpi, lambda: written(gpi, LOCAL_TREE)) == ['EfiSvc.txt'],
          f'{_shut(gpi, lambda: written(gpi, LOCAL_TREE))} -- if this were empty the '
          f'assertion above would be measuring the switch turning everything off')
    check('the new path runs only where the local typedef set is empty',
          before(gsrc, 'if not fptypes:', 'if not ADMIT_RESOLVED_ONLY:')
          and before(gsrc, 'if not ADMIT_RESOLVED_ONLY:', 'return admitted or None'),
          'moved above the local gate it would decide every header')
    check('and it admits only a guid that owns a struct, by struct_members',
          'struct_members(src, guid, wider)' in gsrc,
          'the admission rule is the guid_struct_key match and nothing wider')
    # scan_roots keys on the GUID and so collapses a duplicate before anyone can see it.
    # scan_header is where the dedup has to hold, and the only place it is observable.
    twice = lay(tree((NOLOCAL % INCLUDE).replace(
        'extern EFI_GUID  gEfiSvcProtocolGuid;',
        'extern EFI_GUID  gEfiSvcProtocolGuid;\n'
        'extern EFI_GUID  gEfiSvcProtocolGuid;')))
    hit = gpi.scan_header(os.path.join(twice, 'Svc.h'),
                          gpi.include_index([twice])) or []
    check('a GUID declared twice in the header is reported once',
          [g for g, _ in hit] == ['gEfiSvcProtocolGuid'], f'{hit}')

    print('\nwhat still keeps the gate closed')
    check('a GUID whose struct this header does not hold gets nothing',
          written(gpi, NOSTRUCT_TREE) == [],
          f'{written(gpi, NOSTRUCT_TREE)} -- this is gEfiSmmReadyToLockProtocolGuid, and '
          f'56 of the 69 look like it -- no struct the GUID names, at all')
    check('a function-pointer member of ANOTHER struct is not the protocol\'s',
          written(gpi, CALLBACK_TREE) == [],
          f'{written(gpi, CALLBACK_TREE)} -- this is gEfiRuntimeArchProtocolGuid; the '
          f'whole-header fallback must not be reachable from the new path')
    check('while the same member inside the protocol\'s own struct is requested',
          members(gpi, CALLBACK_OWNED_TREE) == ['NotifyFunction'],
          f'{members(gpi, CALLBACK_OWNED_TREE)} -- without this the assertion above is '
          f'measuring the fixture rather than the fallback')
    check('a typedef the header cannot reach by #include does not admit it',
          written(gpi, UNREACHABLE_TREE) == [],
          f'{written(gpi, UNREACHABLE_TREE)} -- this is SmmVariable.h and LoadedImage.h, '
          f'whose typedefs are in Uefi/UefiSpec.h and included by nothing')
    check('and the bound that refuses it is the include depth, not the gate',
          _shut(gpi, lambda: written(gpi, UNREACHABLE_TREE)) == []
          and written(gpi, NOLOCAL_TREE) == ['EfiSvc.txt'],
          'the two fixtures differ only in whether the include line is there')
    check('a header with no extern protocol GUID is still not a protocol header',
          found(gpi, tree(NOLOCAL.replace('extern EFI_GUID  gEfiSvcProtocolGuid;\n', '')
                          % INCLUDE)) == {},
          'the GUID gate is above this one and must stay above it')
    check('NOT_TARGETS still skips a header by name on the new path',
          found(gpi, SKIPPED_TREE, gpi.NOT_TARGETS) == {},
          f'{found(gpi, SKIPPED_TREE, gpi.NOT_TARGETS)} -- AsanFaultDxe is built only '
          f'under a define no sweep passes')
    check('and without that skip the same header would be admitted',
          list(found(gpi, SKIPPED_TREE, set())) == ['gEfiSvcProtocolGuid'],
          f'{found(gpi, SKIPPED_TREE, set())} -- otherwise the skip assertion is vacuous')
    check('a NULL interface is still not an install the second pass believes',
          gpi.installed_pairs('gBS->InstallProtocolInterface (&Handle, '
                              '&gEfiSvcProtocolGuid, EFI_NATIVE_INTERFACE, NULL);') == [],
          'VariableNotifySmmReady() is exactly this, and a harness would call through it')
    check('while a real interface at the same call still is',
          gpi.installed_pairs('gBS->InstallProtocolInterface (&Handle, '
                              '&gEfiSvcProtocolGuid, EFI_NATIVE_INTERFACE, &mSvc);')
          == [('gEfiSvcProtocolGuid', 'mSvc')],
          'otherwise the assertion above is measuring the parser, not NULL')
    check('an SMM-core install is still not a DXE install',
          gpi.installed_pairs('gMmst->MmInstallProtocolInterface (&Handle, '
                              '&gEfiSvcProtocolGuid, EFI_NATIVE_INTERFACE, &mSvc);') == [],
          'the interface goes into SMRAM and gBS->LocateProtocol cannot see it')
    check('a protocol no .c in the tree mentions is still dropped by consumed_guids',
          'gEfiSvcProtocolGuid' not in gpi.consumed_guids(
              os.path.dirname(os.path.dirname(lay(NOLOCAL_TREE)))),
          'a protocol with no call sites yields Total Functions: 0')
    check('and main() still applies that filter to whatever discovery produced',
          before(gsrc, 'if not args.any_protocol:',
                 'write_inputs(protocols, args.output'),
          'discovery widened without the filter behind it buys wasted analyses')

    print('\nthe behaviours the two earlier fixes bought still hold on the new path')
    check('NEST_DEPTH is still a named bound, and still the walk\'s default',
          hasattr(gpi, 'NEST_DEPTH')
          and re.search(r'^NEST_DEPTH = \d+$', gsrc, re.M) is not None
          and 'depth=NEST_DEPTH' in gsrc,
          'a bound inlined as a literal is a bound the next reader cannot find')
    check('a leaf reached through a by-value sub-struct is requested by its leaf name',
          members(gpi, NESTED_TREE) == ['Read', 'Write', 'Flush'],
          f'{members(gpi, NESTED_TREE)} -- 423e260f, now under a header with no typedef '
          f'of its own')
    check('and the two access paths collapse to one leaf, not two lines',
          [l for l in file_of(gpi, NESTED_TREE).splitlines()
           if 'Read' in l] == ['  gEfiSvcProtocolGuid:Read'],
          f'{file_of(gpi, NESTED_TREE)!r} -- a dotted name reaches harness_match() as '
          f'"Mem.Read", matches no callee and drops the member')
    check('a POINTER to the same sub-struct is still not walked into',
          members(gpi, POINTER_TREE) == ['Flush'],
          f'{members(gpi, POINTER_TREE)} -- only the declarator moved')
    check('INCLUDE_DEPTH is still a named bound, and still the walk\'s default',
          hasattr(gpi, 'INCLUDE_DEPTH')
          and re.search(r'^INCLUDE_DEPTH = \d+$', gsrc, re.M) is not None
          and 'depth=INCLUDE_DEPTH' in gsrc,
          'the gate reads whatever this resolves at, so an inlined literal moves it')
    check('an included typedef may not reclassify a struct this header defines',
          members(gpi, COLLIDE_TREE) == ['Read', 'Write', 'Flush'],
          f'{members(gpi, COLLIDE_TREE)} -- e6dd94c6; taking the include\'s word for '
          f'EFI_SVC_ACCESS makes Mem a leaf and strands Read and Write')
    check('the local typedef set is still never filtered, only the resolved names',
          'found - local' in gsrc)
    check('a header WITH a local typedef still has its per-GUID gate decided locally',
          before(gsrc, 'if not struct_members(src, guid, fptypes):',
                 'owned.append((guid, struct_members(src, guid, resolved)))'),
          'e6dd94c6\'s rule; the new gate is a separate branch, not a replacement')
    check('resolution with the depth flat still admits nothing by itself',
          _flat(gpi, lambda: written(gpi, NOLOCAL_TREE)) == [],
          'the gate uses resolution; resolution must not BE the gate')
    check('structs_in() is still gated on a DIRECT function-pointer member',
          'if any(kind in fptypes for kind, _ in members):' in gsrc,
          'the install-site index is what scan_installations recognises a struct by')

    print('\nthe one way the set moves with --min-methods is written down')
    check('the new file is there at the floor every caller passes',
          written(gpi, NOLOCAL_TREE, 1) == ['EfiSvc.txt'],
          f'{written(gpi, NOLOCAL_TREE, 1)}')
    check('and at the argparse default of 3, because it has exactly three members',
          written(gpi, NOLOCAL_TREE, 3) == ['EfiSvc.txt']
          and _shut(gpi, lambda: written(gpi, NOLOCAL_TREE, 3)) == [],
          f'{written(gpi, NOLOCAL_TREE, 3)} -- de728582 recorded the opposite property '
          f'for the member-list widening, so this one is stated rather than found')
    check('a protocol under the floor is still skipped',
          written(gpi, NOLOCAL_TREE, 4) == [],
          f'{written(gpi, NOLOCAL_TREE, 4)}')

    if all(os.path.isdir(t) for t in TREES):
        print('\nand on the real headers the measurement is reproduced')
        now = gpi.scan_roots(TREES)
        then = _shut(gpi, lambda: gpi.scan_roots(TREES))
        check('exactly one protocol is added',
              len(set(now) - set(then)) == 1,
              f'{sorted(set(now) - set(then))}')
        check('and it is the one the gate was opened for',
              set(now) - set(then) == {'gEdkiiSmmVarCheckProtocolGuid'},
              f'{sorted(set(now) - set(then))}')
        check('no protocol is lost', set(then) - set(now) == set(),
              f'{sorted(set(then) - set(now))}')
        check('no protocol that was already there changes its member list',
              all(now[g] == then[g] for g in then),
              f'{ {g: (then[g], now[g]) for g in then if now[g] != then[g]} }')
        got = now.get('gEdkiiSmmVarCheckProtocolGuid', ('', []))
        check('the added protocol asks for its three members by leaf name',
              got[1] == ['SmmRegisterSetVariableCheckHandler', 'SmmVariablePropertySet',
                         'SmmVariablePropertyGet'], f'{got}')
        check('and it is attributed to the header that declares the struct',
              got[0] == 'SmmVarCheck.h', f'{got}')
        for guid, why in (('gEfiSmmVariableProtocolGuid',
                           'installed into the DXE database with a NULL interface'),
                          ('gEfiLoadedImageProtocolGuid',
                           'its one member is optional and NULL on the located handle'),
                          ('gEfiRuntimeArchProtocolGuid',
                           'the GUID owns no struct; NotifyFunction is a callback'),
                          ('gEfiSmmReadyToLockProtocolGuid',
                           'a GUID-only readiness signal with no interface'),
                          ('gEfiEdidActiveProtocolGuid',
                           'its struct is data only')):
            check(f'{guid} is still absent -- {why}', guid not in now,
                  f'{now.get(guid)}')
        check('and the DXE sibling whose typedefs ARE local is unaffected',
              then.get('gEdkiiVarCheckProtocolGuid', ('', []))[1]
              == now.get('gEdkiiVarCheckProtocolGuid', ('', ''))[1]
              == ['RegisterSetVariableCheckHandler', 'VariablePropertySet',
                  'VariablePropertyGet'],
              f'{now.get("gEdkiiVarCheckProtocolGuid")}')
    else:
        print(f'\n  [skip] {TREES[0]} is not on this host')

    print('\nthe blocker is named where the next reader will look, and is still loud')
    asrc = code(io.open(os.path.join(GEN, 'data_analysis', 'analyze.py'),
                        encoding='utf-8').read()) if os.path.isfile(
        os.path.join(GEN, 'data_analysis', 'analyze.py')) else ''
    if asrc:
        check('a member the generator cannot harness is still named in a warning',
              'was not able to be harnessed' in asrc,
              'that message is how the blocker was found, and it is the only sign of it')
        params_body = body_of(asrc, 'protocol_member_params')
        # This used to assert the opposite -- that protocol_member_params reads one file
        # and nothing else -- and said in its own detail text that it should be retired
        # once the include resolved. It has: the submodule's protocol_member_params and
        # protocol_member_return both ask _declaring_source(), and EdkiiSmmVarCheck goes
        # from 0 of 3 targets and rc 1 to 3 of 3 and rc 0. The subject is the same, so
        # the assertion stays here rather than being deleted: the request file this check
        # owns is only worth making while the generator can consume it, and if that side
        # regresses this is the check that says which half broke. The behaviour itself is
        # asserted in scripts/member_typedef_check.py.
        check('and protocol_member_params resolves the include, so the file is consumable',
              bool(params_body) and '_declaring_source(' in params_body
              and 'open(header_path' not in params_body,
              f'{params_body[:200]!r} -- without this the three members are requested, '
              f'dropped with a warning, and the campaign exits 1 on no targets')
        check('the member path that depends on it is still there to be unblocked',
              'protocol_member_signature(header, protocol_name, name' in asrc
              and 'built from their header' in asrc,
              'that is the path the request file is a prerequisite for, and the one that '
              'turns 0 of 3 into 3 of 3 once the include is resolved')
    else:
        print('  [skip] firness/harness_generator is not checked out')

    print('\nthe measurement is recorded beside the change')
    check('the comment gives the size of the bucket and of the hole inside it',
          '69' in raw and 'exactly THREE' in raw,
          'a gate opened with no count beside it is a change nobody can re-check')
    check('it names the two it refuses and why, not just that it refuses them',
          'gEfiSmmVariableProtocolGuid' in raw and 'gEfiLoadedImageProtocolGuid' in raw
          and 'VariableNotifySmmReady' in raw and 'EFI_IMAGE_UNLOAD' in raw
          and 'Uefi/UefiSpec.h' in raw,
          'the refusals are the judgement call in this change; naming the GUIDs without '
          'the install site that justifies them is a list, not a reason')
    check('it names what proves the fallback stays shut',
          'gEfiRuntimeArchProtocolGuid' in raw and 'EFI_EVENT_NOTIFY' in raw,
          'the next reader will otherwise reach the fallback from the new path')
    check('it gives the before/after on three trees and the inert proof',
          'EdkiiSmmVarCheck.txt' in raw and 'diff -r' in raw)
    check('it says what the generator does with the new file today, with the numbers',
          'Total Functions: 0' in raw and '3 of 3' in raw
          and 'protocol_member_params()' in raw,
          'a request file the generator cannot consume has to say so where it is made')
    check('and it says the --min-methods property, which the previous fix recorded '
          'the other way round',
          'argparse default of 3' in raw and 'de728582' in raw)

    for holder in HOLDERS:
        shutil.rmtree(holder, ignore_errors=True)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def _flat(gpi, call):
    """`call()` with the include depth flat. A function, so the two cannot be reordered."""
    with flat(gpi):
        return call()


if __name__ == '__main__':
    sys.exit(main())
