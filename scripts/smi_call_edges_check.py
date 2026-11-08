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
import re
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


# The path the analyzer really records is the one it compiled, inside the builder
# container -- not a repo-relative one. The fixture carries that so the trimming in
# bug_report.write_source_section is exercised rather than assumed.
CONTAINER_PATH = '/workspace/tmp/edk2/OvmfPkg/RWVariable/RWVariable.c'


def edge(handler, service, function, order, args, file=CONTAINER_PATH):
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
        # An OR of attribute flags is ordinary edk2 and puts a '|' in the recorded
        # assignment, which is also a markdown column separator. Here so the escaping in
        # write_source_section is exercised rather than assumed.
        arg('Attributes', 'CommData->Attributes | EFI_VARIABLE_NON_VOLATILE', 'UINT32'),
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

    check('a peer protocol crossing is classified as one',
          one['kind'] == 'peer-protocol', one.get('kind'))

    # The core's own services are not a peer whose validation was skipped. On EVAL-1 three
    # of five crossings were SmmAllocatePool taking *CommBufferSize and SmmFreePool taking
    # back its own buffer -- both correct -- and they outnumbered the two real findings.
    core = cross_module.cross_module_edges([
        edge('RWVariableHandler', 'gSmst', 'SmmAllocatePool', 0, [
            arg('EfiRuntimeServicesData', '', 'UINTN'),
            arg('DataSize', '*CommBufferSize', 'UINTN'),
        ]),
    ])
    check('a core service call is classified, not dropped', len(core) == 1, str(len(core)))
    check('a core service call is not a peer crossing',
          core and core[0]['kind'] == 'core-service', core and core[0].get('kind'))
    for table in ('gSmst', 'gMmst', 'gBS', 'gRT', 'gDS', 'gST'):
        check(f'{table} is a core service table',
              cross_module.crossing_kind(table) == 'core-service')
    check('a protocol reached through a member is still a peer',
          cross_module.crossing_kind('mMmCpuIo->Io') == 'peer-protocol')
    check('an unnamed protocol is a peer',
          cross_module.crossing_kind('protocol') == 'peer-protocol')

    # report() must not bury the peer crossings under the core ones.
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cross_module.report(RWVARIABLE + [
            edge('RWVariableHandler', 'gSmst', 'SmmFreePool', 2, [arg('CommData', '')]),
        ])
    out = buf.getvalue()
    check('the headline counts peer crossings, not every crossing',
          'SMI cross-module: 1 peer-protocol crossing' in out,
          out.splitlines()[0] if out else '(no output)')
    check('the core service calls are still accounted for',
          'gSmst->SmmFreePool' in out and 'core services' in out)
    check('the offset finding is in the printed report',
          'offset arithmetic' in out)

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
    # The generator's real call path. analyze_smi() reads the edges, analyze_smi_data()
    # knows where the analyzer wrote them, and the value is forwarded POSITIONALLY -- so
    # both that the parameter exists and that it is in the slot the caller fills matter.
    # Run 42299962707 died at exactly this seam with "NameError: name 'smi_file' is not
    # defined" after 25 minutes of port, build, instrumentation and benchmark work,
    # because the call was added to a function that had no such parameter.
    import inspect
    from data_analysis.analyze_smi import analyze_smi, analyze_smi_data
    params = list(inspect.signature(analyze_smi).parameters)
    check('analyze_smi takes the analyzer output path', 'smi_file' in params, str(params))
    if 'smi_file' in params:
        slot = params.index('smi_file')
        caller = inspect.getsource(analyze_smi_data)
        check('analyze_smi_data forwards it',
              'edk2_dir, discovered, smi_file)' in caller,
              'the edges and the inventory are read from this path')
        check('it is forwarded into the slot that holds it',
              slot == len(params) - 1 and params[slot] == 'smi_file',
              f'smi_file is parameter {slot} of {len(params)}')

    fcp = os.path.join(ROOT, 'firness', 'firness', 'FCP.cpp')
    fsrc = open(fcp, encoding='utf-8').read() if os.path.exists(fcp) else ''
    check('the edges are written out', 'outputSmiCallEdges' in fsrc)

    # The findings have to reach bugs.md. Before this they existed only in
    # campaigns/<name>/log.txt, which nothing in the pipeline output, the run summary or
    # the triage stage points at -- the same shape of failure as a detector that fires and
    # never reports.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'bug_report', os.path.join(ROOT, 'scripts', 'bug_report.py'))
    bug_report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bug_report)

    check('bug_report can read the analyzer edges', hasattr(bug_report, 'source_crossings'))
    check('bug_report writes a source section', hasattr(bug_report, 'write_source_section'))

    import io
    buf = io.StringIO()
    bug_report.write_source_section(buf, cross_module.cross_module_edges(RWVARIABLE))
    md = buf.getvalue()
    check('the section is headed as source-derived',
          '## Firmware, found in the source' in md)
    check('the section says a row is not a confirmed defect',
          'not a confirmed defect' in md)
    check('the offset finding is marked in the table', 'offset arithmetic' in md)
    check('the handler is named in the table', 'RWVariableHandler' in md)
    check('the path is package-relative, not the builder container path',
          'OvmfPkg/RWVariable/RWVariable.c' in md and '/workspace/' not in md)
    # Counting every '|' would fail on a correctly escaped one: the escape keeps the
    # character and adds a backslash before it. Count the ones markdown will treat as
    # separators.
    sep = re.compile(r'(?<!\\)\|')
    rows = [row for row in md.splitlines() if row.startswith('| RWVariableHandler')]
    check('a pipe in the source text cannot break the table',
          rows and all(len(sep.findall(row)) == 6 for row in rows),
          str([len(sep.findall(row)) for row in rows]))
    check('the pipe case is actually present in the fixture',
          any('EFI_VARIABLE_NON_VOLATILE' in row for row in rows),
          'nothing in the table carries a pipe, so the escaping is untested')

    empty = io.StringIO()
    bug_report.write_source_section(empty, [])
    check('an empty section says None rather than a bare header',
          'None.' in empty.getvalue())

    # Driven through write_markdown rather than by calling the section writer directly:
    # a check that only calls the writer passes when write_markdown stops calling it,
    # which is what mutation case "C6 bugs.md section removed" showed.
    import tempfile
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, 'bugs.md')
        bug_report.write_markdown(out, 'title', 'preamble', {}, 0, 0, (),
                                  cross_module.cross_module_edges(RWVARIABLE))
        whole = open(out, encoding='utf-8').read()
    check('write_markdown emits the source section',
          '## Firmware, found in the source' in whole,
          'the section writer is never reached from write_markdown')
    check('write_markdown emits the offset finding',
          'offset arithmetic' in whole)
    check('the source section is kept apart from the sanitizer ones',
          whole.index('Firmware, provoked by an input')
          < whole.index('Firmware, found in the source'),
          'a source finding must not read as a sanitizer report')

    # source_crossings() reads the campaign directories, so it needs one. Without this the
    # loader was never run by any check -- mutation cases C11 and C12 both passed while it
    # was returning core-service rows and while its dedup was gone.
    with tempfile.TemporaryDirectory() as work:
        for name in ('DiscoveredSmi', 'SecondCampaign'):
            camp = os.path.join(work, name)
            os.makedirs(camp)
            with open(os.path.join(camp, 'smi-call-edges.json'), 'w') as handle:
                json.dump(RWVARIABLE + [
                    edge('RWVariableHandler', 'gSmst', 'SmmFreePool', 9,
                         [arg('CommData', '')]),
                ], handle)
        loaded = bug_report.source_crossings(work)

    kinds = {f['kind'] for f in loaded}
    check('the loader reads the campaign directories', loaded != [], 'nothing loaded')
    check('the loader keeps only peer-protocol crossings', kinds == {'peer-protocol'},
          str(kinds))
    # RWVARIABLE holds one peer crossing (SmmSetVariable; DuplicateMemory has no Service),
    # written into two campaign directories. One place in the source, so one row.
    check('the same source site in two campaigns is one row',
          len(loaded) == 1, f'{len(loaded)} row(s) from the same crossing in 2 campaigns')
    check('a missing edges file is not an error',
          bug_report.source_crossings(os.path.join(work, 'gone')) == [])

    # A library-attributed finding has to point at the caller. Reports carry one frame --
    # a nine-frame walk #GP'd inside __asan_store1 and capped every boot at one finding --
    # so a fault inside StrLen names the image StrLen was linked into, which is why issues
    # #47 and #48 were filed against VariableSmm.efi when the defect is in RWVariable.c.
    # The static crossings answer it without touching a stack.
    crossings = cross_module.cross_module_edges(RWVARIABLE)
    hinted = bug_report.likely_callers(
        'MdePkg/Library/BaseLib/String.c', 'VariableSmm.efi', crossings)
    check('a library finding is pointed at the handler the source names',
          any('RWVariableHandler' in h for h in hinted), str(hinted))
    check('firmware code of its own is not given a caller hint',
          bug_report.likely_callers(
              'OvmfPkg/RWVariable/RWVariable.c', 'RWVariable.efi', crossings) == [],
          'a module whose own code faulted already names the right place')
    check('no hint without crossings to point at',
          bug_report.likely_callers(
              'MdePkg/Library/BaseLib/String.c', 'VariableSmm.efi', []) == [])
    check('no hint without a module to attribute to',
          bug_report.likely_callers(
              'MdePkg/Library/BaseLib/String.c', '', crossings) == [])
    for lib in ('MdePkg/Library/BaseLib/String.c',
                'MdePkg/Library/BaseMemoryLibRepStr/CopyMem.c',
                'MdePkg/Library/BasePrintLib/PrintLibInternal.c'):
        check(f'{lib.split("/")[-2]} is treated as caller-blind',
              bug_report.likely_callers(lib, 'VariableSmm.efi', crossings) != [])

    # And it must reach the table, not just the function.
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, 'bugs.md')
        # Shaped like the real cluster the pipeline builds: cluster_source() reads
        # reports[0].path, which is where the library path that triggers the hint comes
        # from -- a stub without it never exercises the lookup.
        class FakeReport:
            path = 'MdePkg/Library/BaseLib/String.c'
            line = 39

        class Fake:
            module = 'VariableSmm.efi'
            site = 'String.c:39'
            klass = 'heap-buffer-overflow (read)'
            hits = 24
            protocols = {'DiscoveredSmi'}
            reports = [FakeReport()]
            def detail(self): return 'read of 2 bytes'
            def severity(self): return 4
        bug_report.write_markdown(out, 't', 'p', {'candidate': [(Fake(), '')]}, 1, 1, (),
                                  crossings)
        table = open(out, encoding='utf-8').read()
    check('the caller hint reaches the markdown row',
          'RWVariableHandler' in table and 'names the library, not the caller' in table,
          'the hint is computed but never printed')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
