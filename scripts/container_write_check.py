#!/usr/bin/env python3
"""Assert the harness-artefact verdict is reached where the report is written, and that no
stage writes a path a container produced.

Run 43704163314, 2026-11-15, fuzzed four edk2 refs. All four built, instrumented, passed
the detection probe, fuzzed 80-83 of 112 campaigns for 364k-502k iterations each, and each
one's triage container wrote a complete report -- 44, 48, 57 and 64 candidates, all of them
still on disk. All four runs are recorded as FAILED, in the stage that had just written
that report, with the same line:

    [triage] PermissionError: [Errno 13] Permission denied:
             '/home/gl055/fuzzuer-sweep/43704163314/fuzz-master/bugs.json'

bugs.json is written by bug_report.py from INSIDE the campaign image, as root, because the
.debug files that turn a module and an offset into a file and a line live in that image and
nowhere else. The results directory under it belongs to the user who started the run.
reown() gives that output back to them -- from inside a container, the only side of the
mount with the privilege to do it -- and it is called from Run.save(), after every stage has
run. So for the whole length of a stage, what a container has written in there is root's:
the host can read it and cannot write it.

The triage stage then reopened that report, to move a cpu-exception the harness itself had
caused by driving the platform's I/O ports out of `candidates` and into `filtered.harness`.
The right reclassification, in the wrong place -- and the only place its author owned.

Why no run caught it: a re-triage reruns over a directory an earlier run already reowned,
so the rewrite succeeds there, and that is the path a person runs by hand.
campaign_accounting_check.py asserted the reclassification itself and stayed green
throughout, because it lifted the host-side pass out of fuzz_edk2.py and ran it over a
bugs.json the check had written itself, as itself. That is the one fixture which cannot
reproduce the only condition that matters.

So what is asserted here is where the decision is made, who writes the file, and that the
stage can reach its verdict over a report it is not allowed to write.

Run: python3 scripts/container_write_check.py
"""

import ast
import builtins
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Lifted, not restated. The classification under test is bug_report's own, and a copy of
# the predicate here would keep agreeing with itself after the real one changed.
import bug_report as br                                           # noqa: E402

# The sweeps this is measured on. Optional, both of them: an evidence directory that was
# cleaned up is not a defect in the pipeline, and reddening over one is its own bug.
FAILED_RUN = os.environ.get('FUZZUER_FAILED_RUN',
                            '/home/gl055/fuzzuer-sweep/43704163314')
EVIDENCE = os.environ.get('FUZZUER_EVIDENCE_RUN',
                          '/home/gl055/fuzzuer-eval1/43454245046')

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Every string asserted on below appears in the paragraphs that explain the defect,
    including in this file's own docstring. Matching raw text would find the explanation
    rather than the statement: own_code_check was caught by exactly that once, counting a
    comment that quoted a section header.
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


def region(name, opens, closes):
    """The source text between two anchors, or None if either has moved.

    None rather than an exception, because a check that dies on a missing anchor prints a
    traceback and no verdict, and a mutation harness then credits the traceback as a
    catch.
    """
    text = source(name)
    start = text.find(opens)
    end = text.find(closes, start + 1) if start >= 0 else -1
    return None if start < 0 or end < 0 else text[start:end]


def as_function(body, indent=8):
    """A lifted stage region, wrapped so its locals work."""
    return ('def _run():\n'
            + '\n'.join('    ' + line[indent:] for line in body.splitlines()))


NOTE_OPENS = "        artefacts = [a for a in ((("
NOTE_CLOSES = '        # Zero candidates is a real answer'


def triage_note(found):
    """The clause the triage stage adds for a cluster the report says it reclassified.

    Lifted out of fuzz_edk2.py and run here, so that a sentence this file asserts on is
    the sentence the run prints.

    A raise comes back as a string rather than out of this function. The region is given
    the report and nothing else, so a region that has gone back to reading the FILE --
    which is the defect -- raises NameError from inside the lifted body, and letting that
    out would end this file on a traceback with no verdict under it. Scored instead by
    region_reads() below, which names what the region reads.
    """
    body = region('fuzz_edk2', NOTE_OPENS, NOTE_CLOSES)
    if body is None:
        return None
    names = {'found': found}
    try:
        exec(as_function(body) + '\n    return note\n', names)
        return names['_run']()
    except Exception as error:
        return f'<{error.__class__.__name__}: {error}>'


def region_reads(body):
    """The names the lifted region reads and is not given, by AST.

    The clause is built from the report the stage has already read. Anything else in here
    -- `report`, the path of the file; `campaigns`, the directory; `json`, to dump it --
    is the stage reaching back out at the thing it may not touch.
    """
    tree = ast.parse(as_function(body) + '\n    return note\n')
    bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
             and not isinstance(n.ctx, ast.Load)}
    bound |= {a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)}
    free = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
            and isinstance(n.ctx, ast.Load)} - bound
    return {n for n in free if not hasattr(builtins, n)}


def judged(cluster, boot_keys=()):
    """bug_report's verdict, with a raise turned into a verdict of its own.

    verdict() is the product under test and a mutation of it can raise -- weakening the
    every-protocol guard turns the member lookup into a KeyError. A traceback here is a
    red run with no count in it, which is indistinguishable from a check that was never
    written.
    """
    try:
        return br.verdict(cluster, set(boot_keys), 8)
    except Exception as error:
        return f'<{error.__class__.__name__}>', f'{error.__class__.__name__}: {error}'


# ------------------------------------------------------- the host-write scan
#
# Paths a container produces under a results directory. Each of these is created and
# filled by a process running as root inside the campaign image, over a bind mount that
# belongs to the user who started the run, and none of them is reowned until Run.save().
CONTAINER_PRODUCED = ('bugs.json', 'bugs.md', 'campaigns', 'detect_capture',
                      'bench_cases')

# shutil/os calls whose Nth argument is the thing written.
DEST = {'copyfile': 1, 'copy': 1, 'copy2': 1, 'copytree': 1, 'move': 1, 'rename': 1,
        'replace': 1}


def _strings(node):
    return {n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _own_nodes(node):
    """Every node under `node` that is not inside a nested function of it."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        here = stack.pop()
        yield here
        if not isinstance(here, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(here))


def _assigned(node):
    """name -> (strings, names) every assignment to it in THIS scope reads.

    By AST and not by substring, because `with open(report, 'w')` names no path at all:
    the path is three lines up, in `report = os.path.join(out, 'bugs.json')`. A scan that
    only looked at the write would see a local variable and pass.
    """
    found = {}
    for inner in _own_nodes(node):
        if not isinstance(inner, ast.Assign):
            continue
        for target in inner.targets:
            if isinstance(target, ast.Name):
                strings, names = found.setdefault(target.id, (set(), set()))
                strings |= _strings(inner.value)
                names |= {n.id for n in ast.walk(inner.value)
                          if isinstance(n, ast.Name)}
                found[target.id] = (strings, names)
    return found


def _resolve(node, scopes, depth=4):
    """Every string the expression can be built from, following aliases scope by scope."""
    seen = set(_strings(node))
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    done = set()
    while depth and names:
        depth -= 1
        nxt = set()
        for name in names - done:
            done.add(name)
            for scope in scopes:
                if name in scope:
                    strings, reads = scope[name]
                    seen |= strings
                    nxt |= reads
                    break
        names = nxt - done
    return seen


def _write_mode(call):
    mode = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == 'mode':
            mode = keyword.value
    text = (mode.value if isinstance(mode, ast.Constant)
            and isinstance(mode.value, str) else '')
    return text if re.search(r'[wax]', text) else ''


def _target_of(node):
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', '')
    if name == 'open' and node.args and _write_mode(node):
        return node.args[0]
    index = DEST.get(name)
    if index is not None and len(node.args) > index:
        return node.args[index]
    return None


def write_targets(text):
    """[(scope, expression, strings)] for every path this source opens for WRITING.

    Deletes are deliberately not here. Removing a root-owned file needs permission on the
    directory rather than on the file, so the host CAN do it -- and the fuzz stage does,
    through a container, with a comment saying why. Mixing the two would need an exception
    list, and an exception list is where the next one of these hides.
    """
    tree = ast.parse(text)
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    scope_of = {node: _assigned(node) for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))}

    def chain(node):
        out, here = [], parent.get(node)
        while here is not None:
            if here in scope_of:
                out.append(scope_of[here])
            here = parent.get(here)
        return out

    def named(node):
        names, here = [], parent.get(node)
        while here is not None:
            if isinstance(here, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(here.name)
            here = parent.get(here)
        return '.'.join(reversed(names)) or '<module>'

    out = []
    for node in ast.walk(tree):
        target = _target_of(node)
        if target is None:
            continue
        out.append((named(node), ast.unparse(target), _resolve(target, chain(node))))
    return out


def container_writes(text):
    """The write targets that resolve to something a container produced."""
    bad = []
    for where, expression, strings in write_targets(text):
        hit = sorted(s for s in strings if s in CONTAINER_PRODUCED)
        if hit:
            bad.append((where, expression, hit))
    return bad


# The defect, in the shape it shipped in: the path is a local alias and the write names
# only the variable. A scan that cannot see through that would have passed this.
PLANTED = """
def triage():
    report = os.path.join(out, 'bugs.json')
    found = json.load(open(report))
    with open(report, 'w') as handle:
        json.dump(found, handle, indent=2)
"""
# The same shape over a file the HOST writes, which must not be flagged. A scan that
# flagged this would be useless: run.json is written by Run.save() on every run.
INNOCENT = """
def save():
    record = os.path.join(out, 'run.json')
    with open(record, 'w') as handle:
        json.dump({}, handle, indent=2)
"""

# ------------------------------------------------------- fixtures
#
# The member-choice switch the generator emits for a protocol whose accessors reach I/O
# port space, copied from run 43454245046's EfiCpuIo2 harness -- the bound on the Address
# argument included, because that is what puts the fuzzer inside the legacy I/O page.
IO_HARNESS = """
    Read_Arg_2 = Read_Arg_2 % (4096 + 1);
    EFI_CPU_IO_PROTOCOL_IO_MEM Read_Member = ProtocolVariable->Mem.Read;
    switch(Read_MemberChoice % 2) {
        case 0: Read_Member = ProtocolVariable->Mem.Read; break;
        case 1: Read_Member = ProtocolVariable->Io.Read; break;
    }
    Write_Arg_2 = Write_Arg_2 % (4096 + 1);
    EFI_CPU_IO_PROTOCOL_IO_MEM Write_Member = ProtocolVariable->Mem.Write;
    switch(Write_MemberChoice % 2) {
        case 0: Write_Member = ProtocolVariable->Mem.Write; break;
        case 1: Write_Member = ProtocolVariable->Io.Write; break;
    }
"""
# The SAME harness with the Io arm replaced by a second memory arm, and nothing else
# changed. A pair differing in the protocol, the member names and the bound as well would
# prove nothing about which of those is being read.
MEM_HARNESS = IO_HARNESS.replace('->Io.', '->Mem.')

CRASH_HEAD = ('Phase,AtBoot,Module,Function,File,Line,Asan Msg,ErrorType,Message,'
              'Count\n')
# One ASan row from the SAME campaign that drives the ports. It has an address and an
# extent behind it and is argued on those, so it must stay a candidate.
ASAN_ROW = ('fuzz,,CpuIo2Dxe.efi,CpuIoWrite,/t/UefiCpuPkg/CpuIo2Dxe/CpuIo2Dxe.c,101,'
            'heap-buffer-overflow,asan,"address 0x000000001BDEF0A9, size '
            '0x0000000000000008, is_write 0x0000000000000001",3\n')


def serial(module, ip, base, kind='00(#DE - Divide Error)'):
    """A campaign's serial capture, carrying a fault the exception handler reported."""
    return (f'!!!! X64 Exception Type - {kind}  CPU Apic ID - 00000000 !!!!\n'
            f'!!!! Find image based on IP({ip}) /b/X64/{module}/DEBUG/{module}.dll '
            f'(ImageBase={base}, EntryPoint=000000001CE77198) !!!!\n')


def campaign(root, name, harness='', capture='', rows=''):
    where = os.path.join(root, name)
    os.makedirs(os.path.join(where, 'Firness'), exist_ok=True)
    if harness:
        io.open(os.path.join(where, 'Firness', 'FirnessHarnesses.c'), 'w',
                encoding='utf-8').write(harness)
    io.open(os.path.join(where, 'crashes.csv'), 'w', encoding='utf-8').write(
        CRASH_HEAD + rows)
    if capture:
        io.open(os.path.join(where, 'fuzz.txt'), 'w', encoding='utf-8').write(capture)
    return where


def fixture_root(root):
    """Four campaigns, and the protocol NAME does not predict the answer for any of them.

    EfiMmCpuIo is the one that makes the others worth anything. It is the other protocol
    with Io.Read/Io.Write in its declaration -- the generator emitted no Io arm for it on
    run 43704163314, where it has no harness at all -- so a reader that answered from the
    campaign's name rather than from the harness beside it would get this one wrong and
    every other fixture here right. Which is exactly the implementation a mutation of
    io_port_harness put in, and it passed until this campaign existed.
    """
    camps = os.path.join(root, 'campaigns')
    campaign(camps, 'EfiCpuIo2', IO_HARNESS,
             serial('CpuIo2Dxe', '0x1CE75296', '000000001CE70000'), ASAN_ROW)
    campaign(camps, 'EfiMmCpuIo', MEM_HARNESS,
             serial('MmCpuIoDxe', '0x1CD00789', '000000001CD00000'))
    campaign(camps, 'EfiBlockIo', MEM_HARNESS,
             serial('HiiDatabase', '0x1CA00123', '000000001CA00000'))
    campaign(camps, 'EfiAcpiSdt', '',
             serial('AcpiTableDxe', '0x1CB00456', '000000001CB00000'))
    return camps


def fault(protocol, module='CpuIo2Dxe.efi', site='+0x5296',
          klass='cpu-exception (#DE)', phase='fuzz'):
    report = br.Report({'Phase': phase, 'Module': module, 'File': site, 'Line': '',
                        'Asan Msg': '', 'ErrorType': klass,
                        'Message': f'1 fault(s) at {module}{site}', 'Count': '1'},
                       protocol)
    return report


def cluster(protocols, drives, klass='cpu-exception (#DE)', module='CpuIo2Dxe.efi',
            site='+0x5296', phase='fuzz'):
    """A cluster keyed as bug_report keys one, carrying the facts load() fills in."""
    held = br.Cluster((module, klass, site))
    for protocol in protocols:
        held.add(fault(protocol, module, site, klass, phase))
    held.io_ports = drives
    return held


def main():
    print('1. the decision is made in the file that writes the report')
    for name in ('io_port_harness', 'io_port_drivers', 'io_port_artefact',
                 'io_port_payload', 'IO_PORT_MEMBERS', 'IO_PORT_ARTEFACT'):
        check(f'bug_report carries {name}', hasattr(br, name),
              'the classification has to live where the report is written, because that '
              'is the only process that may write it')
    driver = code(source('fuzz_edk2'))
    check('and fuzz_edk2 no longer decides it on the host',
          'harness_io_artefacts' not in driver and 'IO_PORT_MEMBERS' not in driver,
          'a host-side pass has to reopen a report it did not write and cannot write')
    check('a comment quoting the removed helper would not satisfy that',
          'harness_io_artefacts' not in code('# artefacts = harness_io_artefacts(c, f)\n'
                                             'x = 1'),
          'the prose has to come off first or the assertion finds the explanation')

    root = tempfile.mkdtemp(prefix='container-write-')
    camps = fixture_root(root)
    print('\n   it reads the harness each campaign actually built')
    check('a harness that selects the I/O port accessor is recognised',
          br.io_port_harness(os.path.join(camps, 'EfiCpuIo2'))
          == ['->Io.Read', '->Io.Write'],
          f"{br.io_port_harness(os.path.join(camps, 'EfiCpuIo2'))}")
    check('one that drives only memory is not',
          br.io_port_harness(os.path.join(camps, 'EfiBlockIo')) == [],
          'the only difference between the two fixtures is the Io arm')
    check('a campaign whose generator left no harness answers [] rather than raising',
          br.io_port_harness(os.path.join(camps, 'EfiAcpiSdt')) == [])
    check('a campaign NAMED for the I/O protocol, whose harness drives memory, is not',
          br.io_port_harness(os.path.join(camps, 'EfiMmCpuIo')) == [],
          'the protocol name says only that the members exist; the generated harness is '
          'what says whether they are called, and reading the name instead answers this '
          'campaign wrongly and every other fixture here rightly')
    drives = br.io_port_drivers(camps)
    check('the run-wide map holds only the campaigns that drive ports',
          sorted(drives) == ['EfiCpuIo2'], f'{sorted(drives)}')
    check('and the accessors it found for one', drives.get('EfiCpuIo2')
          == ('->Io.Read', '->Io.Write'), f'{drives.get("EfiCpuIo2")}')
    check('a root with no campaigns is an empty map, not an exception',
          br.io_port_drivers(os.path.join(root, 'nothing')) == {})
    check('the harness it reads is inside the campaign directory it is given',
          'Firness' in code(source('bug_report')).split('def io_port_harness')[1][:400]
          and 'FirnessHarnesses.c' in source('bug_report'),
          'triage gets the campaigns as `-r /campaigns:ro`, so the evidence has to be '
          'under that root and may only be read')

    print('\n2. and only for the fault the harness caused')
    kind, why = judged(cluster(['EfiCpuIo2'], drives))
    check('a cpu-exception from an I/O port campaign is the harness, not a finding',
          kind == 'harness', f'{kind}: {why}')
    check('the reason names the member the harness called',
          '->Io.Write' in why and '->Io.Read' in why, f'{why!r}')
    check('and the ports that member reaches',
          '0x40-0x43' in why and '0x20/0xA0' in why, f'{why!r}')
    check('and the module it is NOT a defect in', 'CpuIo2Dxe.efi' in why, f'{why!r}')
    kind, _why = judged(cluster(['EfiBlockIo'], drives,
                                module='HiiDatabase.efi', site='+0x123'))
    check('the same fault from a campaign that drives no ports stays a candidate',
          kind == 'candidate', f'{kind}')
    kind, _why = judged(cluster(['EfiCpuIo2', 'EfiBlockIo'], drives))
    check('and so does one seen from both',
          kind == 'candidate',
          'the same fault reached from an ordinary target is evidence about the firmware')
    kind, _why = judged(cluster(['EfiCpuIo2'], drives,
                                klass='heap-buffer-overflow (write)'))
    check('a sanitizer report from the port campaign is not swept up with it',
          kind == 'candidate',
          'an asan report has an address and an extent behind it and is argued on those')
    bare = cluster(['EfiCpuIo2'], drives)
    bare.protocols = set()
    check('a cluster under no protocol at all is not reclassified',
          br.io_port_artefact(bare) == (), f'{br.io_port_artefact(bare)}')
    check('a Cluster built by hand defaults to "no campaign drives one"',
          br.Cluster(('m', 'cpu-exception (#DE)', 's')).io_ports == {},
          'every other check in this battery builds clusters by hand')
    check('so the verdict for one is unchanged',
          br.io_port_artefact(cluster(['EfiCpuIo2'], {})) == ())
    boot = cluster(['EfiCpuIo2'], drives, phase='boot')
    kind, _why = judged(boot, {boot.key})
    check('the test is last, so a boot-only fault is still background',
          kind == 'background',
          f'{kind} -- every test above this one describes the same report better, and '
          f'this may only reclassify what would otherwise be reported as a finding')

    print('\n3. the report the container writes already says so')
    out = os.path.join(root, 'bugs.json')
    ran = subprocess.run([sys.executable, os.path.join(HERE, 'bug_report.py'),
                          '-r', camps, '--json', out], capture_output=True, text=True,
                         timeout=600)
    check('bug_report runs over the fixture campaigns', ran.returncode == 0,
          f'rc={ran.returncode} {ran.stderr[-300:]}')
    found = json.load(open(out)) if os.path.isfile(out) else {}
    moved = [a for a in (((found.get('filtered') or {}).get('harness')) or [])
             if a.get('io_ports')]
    kept = [c.get('id') for c in (found.get('candidates') or [])]
    check('the fault lands in the harness bucket, which already means this',
          [a['id'] for a in moved] == ['CpuIo2Dxe.efi|cpu-exception (#DE)|+0x5296'],
          f'{[a["id"] for a in moved]}')
    check('and is gone from the candidates',
          'CpuIo2Dxe.efi|cpu-exception (#DE)|+0x5296' not in kept, f'{kept}')
    check('the entry carries the accessors, so nothing has to re-derive them',
          moved and moved[0].get('io_ports') == ['->Io.Read', '->Io.Write'],
          f'{moved[0] if moved else None}')
    check('and the campaigns it was seen under, which the verdict line names',
          moved and moved[0].get('protocols') == ['EfiCpuIo2'],
          f'{moved[0].get("protocols") if moved else None}')
    check('a filtered cluster that is NOT this carries neither field',
          all('io_ports' not in a for kind_ in ('artefact', 'background')
              for a in (((found.get('filtered') or {}).get(kind_)) or [])),
          'the fields are the marker, so they may not appear on anything else')
    check('the faults from campaigns driving no ports are still candidates',
          'HiiDatabase.efi|cpu-exception (#DE)|+0x123' in kept
          and 'AcpiTableDxe.efi|cpu-exception (#DE)|+0x456' in kept, f'{kept}')
    check('including the one from the campaign NAMED for the I/O protocol',
          'MmCpuIoDxe.efi|cpu-exception (#DE)|+0x789' in kept,
          f'{kept} -- EfiMmCpuIo declares the same accessors and its harness calls '
          f'neither, so its fault is about the firmware')
    check('and so is the asan report from the port campaign itself',
          'CpuIo2Dxe.efi|heap-buffer-overflow (write)|CpuIo2Dxe.c' in kept, f'{kept}')
    check('its own printed verdict says how many of the bucket this was',
          '1 the harness driving platform I/O ports' in ran.stdout,
          ran.stdout[:400])
    check('which is what stops it being filed, because that is the key filing reads',
          "json.load(open(args.bugs)).get('candidates')" in code(source('file_issues')),
          'if file_issues stops reading candidates this move stops having any effect')

    print('\n4. the stage reaches its verdict over a report it cannot write')
    lifted = region('fuzz_edk2', NOTE_OPENS, NOTE_CLOSES)
    check('the region this file lifts is still where it says it is', lifted is not None,
          f'{NOTE_OPENS!r} is not in fuzz_edk2.py; every sentence below is vacuous')
    reads = region_reads(lifted) if lifted else {'<nothing lifted>'}
    check('and it is built from the report alone', reads <= {'found'},
          f'it also reads {sorted(reads - {"found"})} -- the clause is made from the '
          f'report the stage has already read, and a region reaching for the path or for '
          f'json has gone back to the file it may not write')
    # The condition the four refs failed on, as closely as a check without root can make
    # it: a report this process may read and may not write. Mode bits rather than
    # ownership, because a non-root process cannot create a root-owned file -- and the
    # one thing that must not happen is this check quietly testing a writable file.
    os.chmod(out, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    refused = False
    try:
        io.open(out, 'a').close()
    except (OSError, PermissionError):
        refused = True
    if not refused:
        print(f'  --     this process can write a mode 0444 file (euid {os.geteuid()}); '
              f'the read-only condition cannot be made here and the sentences below '
              f'stand on the lift alone')
    else:
        check('the fixture report really is unwritable by this process', refused)
    said = triage_note(found)
    check('the stage still produces its clause', bool(said), f'{said!r}')
    check('and says how many were reclassified',
          said and '1 reported as a harness artefact rather than a finding' in said,
          f'{said!r}')
    check('and names the class and the site it came from',
          said and 'cpu-exception (#DE) at CpuIo2Dxe.efi+0x5296' in said, f'{said!r}')
    check('and the campaign that drove the ports', said and 'EfiCpuIo2' in said,
          f'{said!r}')
    check('the report on disk is byte-for-byte what the container wrote',
          json.load(open(out)) == found,
          'the clause is read out of the report; nothing may be written back')
    os.chmod(out, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    quiet = triage_note({'candidates': [], 'clusters': 0,
                         'filtered': {'harness': [{'id': 'x', 'module': 'm',
                                                   'site': 's', 'class': 'k',
                                                   'hits': 1, 'reason': 'by name'}]}})
    check('a harness cluster filtered by NAME is not counted as an I/O port artefact',
          quiet == '', f'{quiet!r} -- the bucket holds both and only one is this')
    check('a report with nothing to move says nothing about it',
          triage_note({'candidates': [], 'clusters': 0, 'filtered': {'harness': []}})
          == '')
    check('and one with no filtered bucket at all does not raise',
          triage_note({'candidates': [], 'clusters': 0}) == '')

    print('\n5. no stage writes a path a container produced')
    planted = container_writes(PLANTED)
    check('the scan sees through a local alias to the path',
          [h for _w, _e, h in planted] == [['bugs.json']], f'{planted}')
    check('and reports where it is', planted and planted[0][0] == 'triage',
          f'{planted}')
    check('while a host-written file in the same directory is left alone',
          container_writes(INNOCENT) == [], f'{container_writes(INNOCENT)}')
    bad = container_writes(source('fuzz_edk2'))
    check('fuzz_edk2 writes none of them',
          bad == [], '; '.join(f'{w}: {e} -> {h}' for w, e, h in bad))
    check('and the scan is looking at writes at all, on this very file',
          len(write_targets(source('fuzz_edk2'))) >= 8,
          f'{len(write_targets(source("fuzz_edk2")))} write(s) found in a file that '
          f'writes run.json, port.log, image.log and more -- the scan has gone blind')
    check('the triage stage opens nothing for writing',
          [t for t in write_targets(source('fuzz_edk2'))
           if t[0].endswith('triage')] == [],
          f'{[t for t in write_targets(source("fuzz_edk2")) if t[0].endswith("triage")]}')
    check('the report is still written by bug_report, in the container',
          "'--json', '/out/bugs.json'" in driver and "'docker', 'run'" in driver,
          'the .debug files that resolve an offset are in the image and nowhere else')
    check('the campaigns directory is still cleared through a container',
          "'rm -rf /out/campaigns'" in driver,
          'the one host-side delete that was already known to need this')
    check('reown still runs from save(), after every stage',
          re.search(r'def save\(self\):(?:.|\n)*?reown\(self\.out',
                    code(source('fuzz_edk2'))) is not None,
          'if it moved into a stage, this whole class of write would become legal and '
          'the assertions above would be the wrong ones')
    check('and the stage plan still ends with triage, inside that window',
          re.search(r"\('triage', triage\)\)\)", code(source('fuzz_edk2'))) is not None,
          'triage is the last stage, so nothing it leaves behind has been reowned')

    print(f'\nrun {os.path.basename(FAILED_RUN)}, the sweep this cost four refs')
    failed_run()
    print(f'\nrun {os.path.basename(EVIDENCE)}, the sweep the classification is measured on')
    evidence()

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def failed_run():
    """What the defect did to run 43704163314, from that run's own records."""
    refs = [d for d in sorted(os.listdir(FAILED_RUN))
            if os.path.isfile(os.path.join(FAILED_RUN, d, 'run.json'))] \
        if os.path.isdir(FAILED_RUN) else []
    if not refs:
        print(f'  --     {FAILED_RUN} is no longer on disk; nothing here is asserted')
        return
    denied, fuzzed, reports = [], [], []
    for ref in refs:
        run = json.load(open(os.path.join(FAILED_RUN, ref, 'run.json')))
        stages = {s['name']: s for s in run.get('stages') or []}
        triage = stages.get('triage') or {}
        if triage.get('ok') is False and 'PermissionError' in str(triage.get('detail')):
            denied.append(ref)
        if (stages.get('fuzz') or {}).get('ok') is not None:
            fuzzed.append(ref)
        path = os.path.join(FAILED_RUN, ref, 'bugs.json')
        if os.path.isfile(path):
            reports.append(json.load(open(path)))
    check('every ref of that run failed at triage with a PermissionError',
          len(denied) == len(refs) and len(refs) == 4, f'{len(denied)}/{len(refs)}')
    check('and every one of them had fuzzed first', len(fuzzed) == len(refs),
          f'{len(fuzzed)}/{len(refs)}')
    check('the reports it failed over are all there, with their candidates',
          len(reports) == len(refs)
          and all(r.get('candidates') for r in reports),
          f'{[len(r.get("candidates") or []) for r in reports]}')
    check('and not one of them carries the reclassification that was attempted',
          all(not (((r.get('filtered') or {}).get('harness')) or []) for r in reports),
          'the rewrite is where the move happened, so losing the write lost the move '
          'as well as the run')
    kept = [c['id'] for r in reports for c in r['candidates']
            if c['class'].startswith('cpu-exception') and c['protocols'] == ['EfiCpuIo2']]
    check('so the harness\'s own fault was still reported as a finding, on every ref',
          len(kept) == len(refs), f'{kept}')


def evidence():
    """Run 43454245046, where the one cluster this moves was measured."""
    camps = os.path.join(EVIDENCE, 'campaigns')
    report = os.path.join(EVIDENCE, 'bugs.json')
    if not (os.path.isdir(camps) and os.path.isfile(report)):
        print(f'  --     {EVIDENCE} is no longer on disk; nothing here is asserted')
        return
    drives = br.io_port_drivers(camps)
    check('two of its 138 harnesses drive platform I/O ports, and these two',
          sorted(drives) == ['EfiCpuIo2', 'EfiMmCpuIo'], f'{sorted(drives)}')
    found = json.load(open(report))
    faults = [c for c in found['candidates']
              if str(c.get('class') or '').startswith('cpu-exception')]
    moved = [c for c in faults
             if br.io_port_artefact(cluster(c['protocols'], drives, klass=c['class'],
                                            module=c['module'], site=c['site']))]
    check('it triaged three cpu-exception candidates', len(faults) == 3,
          f'{[c["id"] for c in faults]}')
    check('and exactly one of them is the harness driving those ports',
          [c['id'] for c in moved]
          == ['CpuIo2Dxe.efi|cpu-exception (#DE)|IoLibGcc.c'],
          f'{[c["id"] for c in moved]}')
    rest = sorted(c['id'] for c in faults if c not in moved)
    check('the HiiDatabase #GP and the AcpiTableDxe #PF stay findings',
          len(rest) == 2 and any('HiiDatabase' in i for i in rest)
          and any('AcpiTableDxe' in i for i in rest), f'{rest}')
    capture = os.path.join(camps, 'EfiCpuIo2', 'fuzz.txt')
    if os.path.isfile(capture):
        text = io.open(capture, encoding='utf-8', errors='replace').read()
        check('which is the #DE its own serial capture recorded',
              'X64 Exception Type - 00(#DE - Divide Error)' in text,
              'the fault this moves is the one the guest actually took')


if __name__ == '__main__':
    sys.exit(main())
