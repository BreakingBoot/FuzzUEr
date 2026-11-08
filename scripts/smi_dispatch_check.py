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

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
