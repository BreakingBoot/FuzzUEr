#!/usr/bin/env python3
"""Assert every way into SMM is discovered, and that only the drivable ones are harnessed.

There is more than one root dispatcher and they do not share an argument order. The
discovery pass matched "SmiHandlerRegister" and "MmiHandlerRegister" as substrings, which
finds the GUID-dispatched handlers and silently misses every other kind. Measured on EVAL-1
run 42186976238: 22 handler bodies registered in the tree, 10 recorded, and the 12 missed
included PiSmmCommunicationHandler -- the DXE-to-SMM bridge -- plus the two Tcg2 callbacks
that act on a UEFI variable an attacker can set. They register through
SmmSwDispatch2->Register.

Finding them is only half of it, and the other half is a restraint. A dispatcher's Register
takes `This` first, so the handler is argument 1 and reading argument 0 records the protocol
variable as the handler's name. More importantly those handlers are NOT GUID-dispatched:
a software MMI handler is raised by a write to the software MMI port and receives an
EFI_MM_SW_CONTEXT that the DISPATCHER fills in with the CPU index and the port value. There
is no caller buffer. Generating a comm-buffer harness for one would fabricate an input the
hardware cannot produce and attribute whatever it found to the wrong cause -- so the guid
map, which is what the generator consumes, must keep holding only the GUID-dispatched
handlers while the inventory accounts for all of them.
"""

import os
import re
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'firness', 'harness_generator')
sys.path.insert(0, GEN)

if 'fuzzywuzzy' not in sys.modules:
    _fw = types.ModuleType('fuzzywuzzy')
    _fw.fuzz = types.SimpleNamespace(ratio=lambda a, b: 0)
    sys.modules['fuzzywuzzy'] = _fw
    sys.modules['fuzzywuzzy.fuzz'] = _fw.fuzz

from data_analysis.analyze_smi import (  # noqa: E402
    _dispatch_reason, report_smi_coverage, DEFINITE_DISPATCH as _definite)

FAILURES = []

# Every spelling the matcher must classify, and what it must classify it as. The Mm names
# are the newer PI ones and a tree can use either, so both have to land on the same kind.
SPELLINGS = [
    ('SmiHandlerRegister', 'SmiHandlerRegister'),
    ('MmiHandlerRegister', 'SmiHandlerRegister'),
    ('gSmst->SmiHandlerRegister', 'SmiHandlerRegister'),
    ('EFI_SMM_SW_DISPATCH2_PROTOCOL', 'SwDispatch'),
    ('SmmSwDispatch2', 'SwDispatch'),
    ('mSwDispatch', 'SwDispatch'),
    ('EFI_MM_SW_DISPATCH_PROTOCOL', 'SwDispatch'),
    ('SmmSxDispatch2', 'SxDispatch'),
    ('mSxDispatch', 'SxDispatch'),
    ('SmmPeriodicTimerDispatch2', 'PeriodicTimer'),
    ('SmmUsbDispatch2', 'UsbDispatch'),
    ('SmmGpiDispatch2', 'GpiDispatch'),
    ('SmmPowerButtonDispatch2', 'PowerButton'),
    ('SmmStandbyButtonDispatch2', 'StandbyButton'),
    ('SmmIoTrapDispatch2', 'IoTrap'),
    ('CopyMem', ''),
    ('InstallProtocolInterface', ''),
    ('Register', ''),
]

# Only the GUID-dispatched kind may be handed to the generator.
DRIVABLE = 'SmiHandlerRegister'


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def cxx_kinds(src):
    """registrationKind()'s arms, in order, read out of the C++ so the two cannot drift."""
    body = src[src.index('std::string registrationKind('):]
    body = body[:body.index('\n    }\n')]
    arms = []
    for match in re.finditer(r'Name\.find\("([^"]+)"\)[^;]*?return "([^"]*)";', body, re.S):
        arms.append((match.group(1), match.group(2)))
    # a return that follows several find() tests shares them; re-scan per return block
    arms = []
    for block in re.split(r'\n        if \(', body):
        needles = re.findall(r'Name\.find\("([^"]+)"\)', block)
        ret = re.search(r'return "([^"]*)";', block)
        if needles and ret:
            for needle in needles:
                arms.append((needle, ret.group(1)))
    return arms


def normalise(name):
    """The same normalisation registrationKind() applies: no underscores, lower case.

    Mirrored here rather than skipped, because a check that compared the raw spelling
    against the C++'s lowercase needles would pass for the wrong reason.
    """
    return name.replace('_', '').lower()


def classify(arms, name):
    subject = normalise(name)
    for needle, kind in arms:
        if needle in subject:
            return kind
    return ''


def main():
    print('Every way into SMM is discovered, and only the drivable ones are harnessed')

    smi = os.path.join(ROOT, 'firness', 'firness', 'SmiFunctionAnalysis.h')
    src = open(smi, encoding='utf-8').read()
    arms = cxx_kinds(src)
    check('the matcher has arms for the root dispatchers', len(arms) >= 10,
          f'{len(arms)} arm(s) parsed out of registrationKind()')

    for name, want in SPELLINGS:
        got = classify(arms, name)
        check(f'{name or "(empty)"} classifies as {want or "not a registration"}',
              got == want, f'got {got!r}')

    check('the handler is argument 0 for SmiHandlerRegister and 1 for a dispatcher',
          'return (Kind == "SmiHandlerRegister") ? 0u : 1u;' in src,
          'handlerArgIndex does not shift past This')
    check('a dispatcher registration is not given a GUID',
          'CurrentInfo.Guid.clear();' in src,
          'argument shifting would otherwise record RegisterContext as the GUID')
    check('a registration with no handler name is not recorded',
          '!CurrentFunction.empty()' in src)
    check('the dispatch kind is recorded on the handler',
          'CurrentInfo.Dispatch = Kind;' in src)
    check('a plain Register is resolved through the object it is called on',
          'MemExpr->getBase()' in src,
          'the dispatch protocols spell the member just "Register"')

    # The arms are read out of the C++ and compared after the SAME normalisation, so a
    # check that only did that would pass whether or not the C++ normalises at all -- which
    # is exactly what the mutation case "E6 name normalisation dropped" showed. Assert the
    # call, and assert the needles are in the normalised form it produces.
    kindfn = src[src.index('std::string registrationKind('):]
    kindfn = kindfn[:kindfn.index('\n    }\n')]
    check('the dispatcher name is normalised before matching',
          'normalise(Raw)' in kindfn,
          'without it EFI_SMM_SW_DISPATCH2_PROTOCOL matches nothing')
    check('normalisation strips underscores and case',
          "if (Ch == '_')" in src and "Ch - 'A' + 'a'" in src)
    bad = [n for n, _ in arms if n != n.replace('_', '').lower()]
    check('every needle is already in normalised form', not bad, str(bad))

    out = os.path.join(ROOT, 'firness', 'firness', 'FileOperationHelpers.h')
    osrc = open(out, encoding='utf-8').read()
    check('the generator input keeps only GUID-dispatched handlers',
          'smiInfo.Dispatch != "SmiHandlerRegister"' in osrc and 'not_guid++' in osrc,
          'a port-triggered handler would get a comm-buffer harness')
    # The filename alone appears in the surrounding comment too, so match the stream that
    # actually writes it -- mutation case "E9 inventory not written" redirected the
    # ofstream to /dev/null and left the comment untouched.
    check('every handler still reaches the inventory',
          re.search(r'ofstream\s+\w+\s*\(\s*filename\s*\+\s*"/smi-handler-inventory\.json"',
                    osrc) is not None,
          'nothing writes smi-handler-inventory.json')
    check('the inventory says whether a handler can be driven',
          '"Harnessable"' in osrc)

    kinds = sorted({k for _, k in SPELLINGS if k} | {'', 'RootHandler'})
    for kind in kinds:
        reason = _dispatch_reason({'Dispatch': kind, 'Type': ''})
        check(f'{kind or "(unrecorded)"} has a reason a reader can act on',
              bool(reason) and 'None' not in reason, repr(reason))

    swr = _dispatch_reason({'Dispatch': 'SwDispatch'})
    check('the software MMI reason says the buffer is not the caller\'s',
          'dispatcher' in swr and 'port' in swr, swr[:70])
    check('an unresolved type is distinguished from a different channel',
          'not resolved' in _dispatch_reason({'Dispatch': DRIVABLE, 'Type': ''}))

    # A table-driven registration names no handler at the call site. The SMM core does
    # exactly that -- SmiHandlerRegister (mSmmCoreSmiHandlers[Index].Handler, ...) -- and
    # the walk took the deepest DeclRefExpr, so "Index" was recorded as an SMI handler and
    # appeared as one in the inventory on EVAL-1 run 42310220335.
    check('a handler slot accepts only a function',
          'if (isa<FunctionDecl>(DRE->getDecl()))' in src,
          'any identifier in the expression can land in the handler slot')
    check('a GUID slot accepts only a variable',
          'if (isa<VarDecl>(DRE->getDecl()))' in src)
    check('a table-driven registration is recognised',
          'const VarDecl *handlerTable(Expr *E)' in src)
    check('the table is reached through the subscript, not the member',
          'ArraySubscriptExpr' in src,
          'mCoreSmiHandlers[Index].Handler has to be unwrapped to the array')
    check('the table must carry an initialiser to be usable',
          '!Var->hasInit()' in src)
    check('every row of the table is expanded',
          'void expandHandlerTable(' in src and 'Rows->getNumInits()' in src)
    check('a row is read by shape, not by field index',
          'Handler.empty() && isa<FunctionDecl>' in src and 'UO_AddrOf' in src,
          'field order and trailing fields differ between tables')
    check('the NULL terminator row is skipped',
          'if (Handler.empty()) {' in src,
          'a { NULL, NULL, ... } row names no function and must not be recorded')
    check('a handler already known is not overwritten by the table',
          'SmiFunctionSet.find(Handler) != SmiFunctionSet.end()' in src)
    check('the table is only consulted when nothing named a function',
          'if (CurrentFunction.empty() && Shift < call->getNumArgs())' in src,
          'it must not override a registration that did name its handler')

    # A root handler is registered with HandlerType NULL: SmiManage calls it on every MMI
    # and its CommBuffer is ignored by contract. EVAL-1 has two, CpuHotplugMmi and
    # SmmSwDispatcher, and both were reported as "dropped for an unresolved CommBuffer
    # type" -- which sends a reader looking for a type that does not exist.
    check('a NULL HandlerType is recognised as a root handler',
          'CurrentInfo.Dispatch = "RootHandler";' in src)
    check('the NULL is tested as a null pointer constant, not by spelling',
          'isNullPointerConstant' in src,
          'NULL, 0 and (VOID *)0 all appear in-tree')
    check('only a registration with no GUID can be a root handler',
          'CurrentInfo.Guid.empty() &&' in src)
    root = _dispatch_reason({'Dispatch': 'RootHandler', 'Type': ''})
    check('the root handler reason says there is no buffer to give it',
          'ignored by contract' in root and 'not the analyser failing' in root, root[:60])
    check('a root handler is kept out of the generator input',
          'smiInfo.Dispatch != "SmiHandlerRegister"' in osrc,
          'RootHandler must fall into the not-addressable arm')
    check('the summary says not addressable rather than not dispatched',
          'not addressable by GUID' in osrc)

    # The report has to cover what the analyzer found, and say the most definite thing it
    # knows. On run 42483193618 the seven SMM core handlers were in the inventory and in
    # none of the sets the report reads, and CpuHotplugMmi was described as having a comm
    # buffer that is "never cast to a recorded type" -- a cast a root handler cannot have.
    import io, contextlib
    inv = {
        'CpuHotplugMmi': {'Dispatch': 'RootHandler', 'Type': ''},
        'SwOne': {'Dispatch': 'SwDispatch', 'Type': ''},
        'SmmReadyToLockHandler': {'Dispatch': 'SmiHandlerRegister', 'Type': ''},
        'Harnessed': {'Dispatch': 'SmiHandlerRegister', 'Type': 'FOO *'},
    }
    vague = {'CpuHotplugMmi': 'its comm buffer is never cast to a recorded type',
             'SwOne': 'its comm buffer is never cast to a recorded type'}
    # edk2_dir must be a real, small directory. report_smi_coverage calls lifecycle_gate
    # for each harnessed handler, and that reaches _handler_source, which does
    # os.walk(edk2_dir or '.') -- passing '' from the repo root walks the whole tree,
    # eval_source/edk2 included, once per handler. This check hung on exactly that.
    buf = io.StringIO()
    with tempfile.TemporaryDirectory() as empty:
        with contextlib.redirect_stdout(buf):
            report_smi_coverage({'Harnessed': object()}, ['Harnessed'], {}, vague,
                                empty, inv)
    out = buf.getvalue()

    check('a handler only the inventory knows is still reported',
          'SmmReadyToLockHandler' in out,
          'the seven SMM core handlers were found and then not mentioned')
    check('the coverage total counts the inventory',
          'of 4 registered' in out, out.splitlines()[0])
    check('a root handler is not told it lacks a cast',
          'never cast to a recorded type' not in out.split('CpuHotplugMmi')[1].split(chr(10))[0],
          'the vague reason is shadowing the definite one')
    check('a root handler gets the root reason',
          'root handler' in out.split('CpuHotplugMmi')[1].split(chr(10))[0])
    check('a dispatcher handler gets the dispatcher reason',
          'software MMI dispatch protocol' in out.split('SwOne')[1].split(chr(10))[0])
    check('a GUID handler with no type still gets the type reason',
          'not resolved' in out.split('SmmReadyToLockHandler')[1].split(chr(10))[0],
          'for a comm-buffer registration the buffer really is the reason')
    check('only a non-GUID kind overrides the generator note',
          _definite({'Dispatch': 'RootHandler'}) and _definite({'Dispatch': 'SwDispatch'})
          and not _definite({'Dispatch': 'SmiHandlerRegister'})
          and not _definite({}),
          'SmiHandlerRegister must not override: there the buffer is the reason')

    # Some handlers refuse any comm buffer but the one their DXE half published:
    #
    #   gBS->LocateProtocol (&gEfiLightStatusCodeCommunicationGuid, NULL, &mCommBuffer);
    #   if ((UINTN)CommBuffer != (UINTN)mCommBuffer + SMM_COMMUNICATE_HEADER_SIZE) return;
    #
    # An equality test on an address, so no input gets past it. On EVAL-1 run 42490347442
    # UnregisterCBFunctionLight was dispatched 37278 times and UnregisterCBFunctionHwAlarm
    # 56021 times, both with zero findings -- two of the six injected drivers, unreachable
    # for a reason no amount of fuzzing changes.
    check('a LocateProtocol is recorded as pointer -> GUID',
          'GuidForLocatedPointer[Into] = Guid;' in src)
    check('all three LocateProtocol spellings match',
          'Callee.find("LocateProtocol")' in src,
          'gBS->LocateProtocol, SmmLocateProtocol and MmLocateProtocol')
    check('the GUID and the out pointer are read through their casts',
          'std::string addressedName(const Expr *E)' in src and 'UO_AddrOf' in src,
          '(VOID **)&mCommBuffer needs the cast unwrapped')
    check('the out pointer is taken as the last argument',
          'Call->getArg(Call->getNumArgs() - 1)' in src,
          'LocateProtocol has the GUID first and the interface last')
    check('an identity test on the comm buffer is found',
          'void findBufferIdentityGate(' in src)
    check('it matches equality and inequality',
          'BO_EQ || BO->getOpcode() == BO_NE' in src)
    check('one side must mention CommBuffer and the other must not',
          '!HasCommBuffer(WithBuffer) || HasCommBuffer(WithOther)' in src,
          'a test of CommBuffer against itself is not a gate')
    check('an offset added to the expected address does not defeat it',
          'namedLocatedPointer' in src,
          'the real gate is mCommBuffer + SMM_COMMUNICATE_HEADER_SIZE')
    check('located pointers are collected from every body, not just handlers',
          'collectLocatedPointers(func->getBody());' in src,
          'the LocateProtocol sits in the entry point, not the handler')
    # Both files, named separately: the inventory line alone satisfied a bare
    # '"BufferProtocol"' search while the guid map -- which is what the generator reads --
    # had lost it, and mutation case G6 passed.
    check('the protocol reaches the generator input (guid map)',
          'smiJson["BufferProtocol"] = smiInfo.BufferProtocol;' in osrc)
    check('and the inventory records it too',
          'entry["BufferProtocol"] = smiInfo.BufferProtocol;' in osrc)

    gen = os.path.join(ROOT, 'firness', 'harness_generator')
    tmpl = open(os.path.join(gen, 'uefi_harness', 'smi_harness_template.py'),
                encoding='utf-8').read()
    check('the region entry stays as a fallback',
          'if (!EFI_ERROR(Status) && PublishedBuffer != NULL)' in tmpl,
          'a firmware that does not publish it must still get a buffer')

    # Run the template rather than grep it. 'buffer_protocol' appears in a comment and in
    # the getattr, so a textual check passed with the emission disabled -- mutation G7.
    sys.path.insert(0, gen)
    from common.types import SmiInfo as GenSmiInfo, TypeInfo, FieldInfo  # noqa: E402
    from uefi_harness.smi_harness_template import harness_generator  # noqa: E402

    # The parameter block needs at least one field: generator_struct_args resolves the
    # struct through types[...] only when .fields is non-empty, and otherwise falls to the
    # alias map and looks up None.
    gated = GenSmiInfo('MyGatedHandler', 'MY_GATED_PARAMS *', 'gMyGatedCommGuid',
                       buffer_protocol='gMyPublishedBufferGuid')
    plain = GenSmiInfo('MyPlainHandler', 'MY_PLAIN_PARAMS *', 'gMyPlainCommGuid')
    types_ = {'MY_GATED_PARAMS': TypeInfo('MY_GATED_PARAMS', [FieldInfo('Function', 'UINT32')]),
              'MY_PLAIN_PARAMS': TypeInfo('MY_PLAIN_PARAMS', [FieldInfo('Function', 'UINT32')])}
    try:
        emitted = '\n'.join(harness_generator({'MyGatedHandler': gated}, types_, {}, {}))
        clean = '\n'.join(harness_generator({'MyPlainHandler': plain}, types_, {}, {}))
    except Exception as exc:  # the template needs more than a stub: say so, do not pass
        check('the template runs against a stub handler', False, f'{type(exc).__name__}: {exc}')
        emitted = clean = ''

    if emitted or clean:
        check('a gated handler emits a LocateProtocol for its buffer',
              'gMyPublishedBufferGuid' in emitted and 'PublishedBuffer' in emitted,
              'the emission is disabled or unreachable')
        check('it assigns the located buffer over the region entry',
              'CommBuffer = (UINT8 *)PublishedBuffer;' in emitted)
        check('a handler with no gate emits none of it',
              'PublishedBuffer' not in clean,
              'every handler would declare an unused local')
    an = open(os.path.join(gen, 'data_analysis', 'analyze_smi.py'), encoding='utf-8').read()
    check('the protocol GUID is added to the INF',
          'protocol_guids.add(smi.buffer_protocol)' in an,
          'otherwise the harness references a symbol nothing declares')

    # The constants the source tests each field against have to survive the whole path:
    # analyzer JSON -> loader -> SmiInfo -> emitted C. Run it, do not grep for it.
    print('the constants the source tests a field against')
    import json as _json
    import inspect as _inspect
    from data_analysis.analyze_smi import load_smi_data  # noqa: E402
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'smi-function-guid-map.json')
        # Shaped exactly as outputSmiFunctionGuidMap writes it.
        open(path, 'w').write(_json.dumps({
            'MyGatedHandler': {
                'Guid': 'gMyGatedCommGuid',
                'Type': 'MY_GATED_PARAMS *',
                'Dispatch': 'SmiHandlerRegister',
                'BufferProtocol': 'gMyPublishedBufferGuid',
                'FieldConstants': {'Function': ['MY_CMD_ONE', 'MY_CMD_TWO']},
            }}))
        loaded = load_smi_data(path)
    got = loaded.get('MyGatedHandler')
    check('the loader reads FieldConstants out of the analyzer output',
          got is not None and getattr(got, 'field_constants', None)
          == {'Function': ['MY_CMD_ONE', 'MY_CMD_TWO']},
          str(getattr(got, 'field_constants', '<no attribute>')))
    if got is not None:
        with_consts = '\n'.join(harness_generator({'MyGatedHandler': got}, types_, {}, {}))
        check('and they reach the generated C',
              'MY_CMD_ONE' in with_consts and 'MY_CMD_TWO' in with_consts,
              'the loader parsed them and the template dropped them')
        check('through the index byte, not a slot each',
              'ConstChoice % 2' in with_consts, with_consts[-400:])

    # The analyzer half. Proved by building it and running it on a fixture mirroring
    # OvmfPkg/HwLight, which returned exactly:
    #
    #   Function     ["REGISTER_RSC", "RE_REGISTER_RSC", "UNREGISTER_FROM_RSC"]
    #   Disable      ["FALSE"]
    #   ReturnStatus ["MODE_A"]
    #
    # -- macro names kept as names, the enum constant kept, and the VARIABLE in
    # `CommunicationData->ReturnStatus == Status` correctly refused. These pin the two
    # decisions that made that true, where the suite can check them without an LLVM link.
    root = ROOT
    sfa = os.path.join(root, 'firness', 'firness', 'SmiFunctionAnalysis.h')
    sfsrc = open(sfa, encoding='utf-8').read() if os.path.exists(sfa) else ''
    check('the analyzer collects a field\'s comparison constants',
          'collectFieldConstants' in sfsrc and 'SwitchStmt' in sfsrc,
          'both a switch arm and an == comparison name one')
    check('only an ENUM constant is taken from a name',
          'isa<EnumConstantDecl>' in sfsrc,
          'a plain variable is not a constant, and emitting its name puts an undeclared '
          'identifier in the generated C -- the firmware then does not build and the '
          'campaign reports a broken port rather than a weaker harness')
    check('the field has to belong to the comm buffer',
          'if (!HasCommBuffer(ME->getBase()) && !isCommBufferLocal(ME->getBase())) {'
          in sfsrc,
          'the GUARD, not the function name: gutting the body leaves both names in place '
          'and every struct field in the body then matches, so an unrelated local struct '
          "would hand its own constants to the comm buffer's fields")
    check('and the local it was cast into is recorded where the type is resolved',
          'CommBufferLocals.insert(DRE2->getDecl()->getNameAsString());' in sfsrc,
          'HwLight gates on CommunicationData, one assignment from CommBuffer; without '
          'that name the base check rejects every field and nothing is collected')
    fops = os.path.join(root, 'firness', 'firness', 'FileOperationHelpers.h')
    fosrc = open(fops, encoding='utf-8').read() if os.path.exists(fops) else ''
    check('and the writer emits them',
          'smiJson["FieldConstants"] = constants;' in fosrc,
          'collected and then dropped on the floor')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
