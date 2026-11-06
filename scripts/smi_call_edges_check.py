#!/usr/bin/env python3
"""Assert the analyzer records what an SMI handler does with the buffer it is given.

In SMI mode the analyzer's input list holds HANDLER names, and the call-site pass keys on
the CALLEE being one of them. Nothing in firmware calls an SMI handler by name -- the SMM
core dispatches a registered pointer -- so the pass matched nothing and call-database.json
was written as the four bytes "null". Measured on EVAL-1 run 42186976238: five of the
analyzer's outputs were null in SMI mode (call-database, functions, generators,
generator-database, function-aliases), and those are exactly the ones that hold
cross-module relationships.

That mattered because the two real findings in that run were cross-module. RWVariableHandler
hands mSmmVariable->SmmSetVariable a name taken straight out of the comm buffer and a
destination computed as CommBuffer->Data + an unvalidated Offset. The standard
SmmVariableHandler reaches the same services but first requires the name to be
NUL-terminated inside its declared size (VariableSmm.c:546), so the overread is reachable
through RWVariable and not through the standard path. The fuzzer needed 110255 iterations
to get there and filed both against VariableSmm.efi, the module that faulted rather than
the one that chose the arguments. The edge was in the source all along.

So this checks the inverse analysis: edges out of a handler body, the one-hop taint that
carries CommBuffer into the local almost every handler copies it into, and the shape that
makes an edge sharp -- offset arithmetic on a buffer the caller owns.
"""

import json
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'firness', 'harness_generator')
sys.path.insert(0, GEN)

# Present in the pipeline image, not on a shell host, and nothing reached from here uses it.
if 'fuzzywuzzy' not in sys.modules:
    _fw = types.ModuleType('fuzzywuzzy')
    _fw.fuzz = types.SimpleNamespace(ratio=lambda a, b: 0)
    sys.modules['fuzzywuzzy'] = _fw
    sys.modules['fuzzywuzzy.fuzz'] = _fw.fuzz

from data_analysis import cross_module  # noqa: E402

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def edge(handler, service, function, order, args, file='RWVariable.c'):
    return {
        'EnclosingFunction': handler,
        'EnclosingFile': file,
        'Service': service,
        'Function': function,
        'CallOrder': order,
        'Arguments': {f'Arg_{i}': a for i, a in enumerate(args)},
    }


def arg(variable='', assignment='', data_type='VOID *', usage=''):
    return {'variable': variable, 'assignment': assignment,
            'data_type': data_type, 'usage': usage, 'arg_dir': 'IN'}


# RWVariableHandler as the analyzer records it: the copy out of the caller's buffer, then
# the crossing into another module carrying three things derived from it.
RWVARIABLE = [
    edge('RWVariableHandler', '', 'DuplicateMemory', 0, [
        arg('CommData', '', 'RW_VARIABLE_INFO *'),
        arg('CommBuffer', '', 'VOID *'),
        arg('DataSize', '', 'UINTN'),
    ]),
    edge('RWVariableHandler', 'mSmmVariable', 'SmmSetVariable', 1, [
        arg('VarName', '(CHAR16 *)CommData->Data', 'CHAR16 *'),
        arg('VarGuid', '&CommData->VarGuid', 'EFI_GUID *'),
        arg('Attributes', 'CommData->Attributes', 'UINT32'),
        arg('DestBuffer',
            '(VOID *)((CHAR16 *)((RW_VARIABLE_INFO *)CommBuffer)->Data + CommData->Offset)',
            'VOID *'),
    ]),
]


def main():
    print('The analyzer records what a handler does with its comm buffer')

    found = cross_module.cross_module_edges(RWVARIABLE)
    check('the RWVariable crossing is found', len(found) == 1, f'{len(found)} finding(s)')
    if not found:
        print(f'{len(FAILURES)} failure(s)')
        return 1
    one = found[0]
    carried = {c['arg']: c for c in one['carries']}

    check('it names the handler, not the callee',
          one['handler'] == 'RWVariableHandler', one['handler'])
    check('it names the interface it crosses',
          one['service'] == 'mSmmVariable' and one['function'] == 'SmmSetVariable',
          f"{one['service']}->{one['function']}")

    # The taint hop: CommData is only attacker-controlled because DuplicateMemory copied
    # CommBuffer into it. Without that hop every argument here reads as a local.
    check('taint reaches a local the handler copied the buffer into',
          'Arg_0' in carried, 'VarName = (CHAR16 *)CommData->Data was not carried')
    check('the unterminated-name argument is reported (issue #47)',
          carried.get('Arg_0', {}).get('assignment', '').endswith('CommData->Data'),
          carried.get('Arg_0', {}).get('assignment', ''))
    check('the offset argument is reported (issue #48)', 'Arg_3' in carried)
    check('offset arithmetic on the caller buffer is called out',
          carried.get('Arg_3', {}).get('offset_arithmetic') is True,
          'the + on CommBuffer->Data was not flagged')
    check('a plain field copy is not called out as offset arithmetic',
          carried.get('Arg_2', {}).get('offset_arithmetic') is not True)
    check('what ran before the crossing is reported',
          one['ran_before'] == ['DuplicateMemory'], str(one['ran_before']))

    # A library call inside the same image is not an interface crossing however it is used.
    direct = cross_module.cross_module_edges([
        edge('H', '', 'StrLen', 0, [arg('Name', 'CommBuffer')]),
    ])
    check('a call with no Service is not a crossing', direct == [], str(direct))

    # Taint must not run backwards: a value is not attacker-controlled before the copy.
    backwards = cross_module.cross_module_edges([
        edge('H', 'mProto', 'Use', 0, [arg('Local', '')]),
        edge('H', '', 'CopyMem', 1, [arg('Local', ''), arg('CommBuffer', '')]),
    ])
    check('taint does not flow backwards in source order', backwards == [], str(backwards))

    # A copy-like call is the only hop. An arbitrary function taking CommBuffer does not
    # launder its other arguments into attacker control.
    nonhop = cross_module.cross_module_edges([
        edge('H', '', 'ValidateThing', 0, [arg('Clean', ''), arg('CommBuffer', '')]),
        edge('H', 'mProto', 'Use', 1, [arg('Clean', '')]),
    ])
    check('only a copy-like call propagates taint', nonhop == [], str(nonhop))

    # Identifier boundaries: a name that merely contains a tainted name is not tainted.
    boundary = cross_module.cross_module_edges([
        edge('H', 'mProto', 'Use', 0, [arg('MyCommBufferLocal', '')]),
    ])
    check('taint matches whole identifiers only', boundary == [], str(boundary))

    # CommBuffer used directly, with no copy at all, is still a crossing.
    direct_use = cross_module.cross_module_edges([
        edge('H', 'mProto', 'Use', 0, [arg('CommBuffer', '')]),
    ])
    check('the buffer passed straight through is a crossing', len(direct_use) == 1)

    # Two handlers must not be merged: taint is per body.
    two = cross_module.cross_module_edges(RWVARIABLE + [
        edge('OtherHandler', 'mProto', 'Use', 0, [arg('CommData', '')], 'Other.c'),
    ])
    check('taint does not leak between handler bodies', len(two) == 1,
          f'{len(two)} finding(s); CommData is only tainted inside RWVariableHandler')

    # The analyzer side: the writer must exist and the collection must be inverted.
    cs = os.path.join(ROOT, 'firness', 'firness', 'CallSiteAnalysis.h')
    src = open(cs, encoding='utf-8').read() if os.path.exists(cs) else ''
    check('the handler body is walked, not every call in the tree',
          'bool VisitFunctionDecl(FunctionDecl *Func)' in src and 'collectSmiCalls' in src,
          'VisitFunctionDecl/collectSmiCalls missing from CallSiteAnalysis.h')
    check('the walked-bodies set is global, not a visitor member',
          'std::set<std::string> SeenSmiHandlerBodies;' not in src,
          'a member set cannot span the two Tool.run() passes, so every edge doubles')
    glob = os.path.join(ROOT, 'firness', 'firness', 'Globals.h')
    gsrc = open(glob, encoding='utf-8').read() if os.path.exists(glob) else ''
    check('the edges and the dedup set are declared globally',
          'extern std::vector<Call> SmiCallEdges;' in gsrc
          and 'extern std::set<std::string> SeenSmiHandlerBodies;' in gsrc)
    fcp = os.path.join(ROOT, 'firness', 'firness', 'FCP.cpp')
    fsrc = open(fcp, encoding='utf-8').read() if os.path.exists(fcp) else ''
    check('the edges are written out', 'outputSmiCallEdges' in fsrc)

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
