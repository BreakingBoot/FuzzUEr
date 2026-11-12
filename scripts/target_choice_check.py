#!/usr/bin/env python3
"""Assert the bounded gate fuzzes a real, stable subset of what a version discovered.

The cross-version gate reaches `fuzz` and `triage` on several edk2 releases without
spending a campaign budget on each, which means fuzzing a FEW of the targets rather than
all of them. Choosing those few is the part that can be wrong without looking wrong.

Naming protocols literally is the obvious implementation and it cannot work here: the
discovered set differs between releases -- 261 targets on edk2-stable202305 against 254
on edk2-stable202608 -- so a fixed name is a target that exists on some versions and not
others, and a ref that fuzzed NOTHING finishes quickly with every stage green. That is
the failure this guards: a gate reporting a clean result for work it never did.

Deterministic is not the same as reachable, which the first sweep measured the hard
way: the alphabetical head of the discovered set is AndroidBootImg and ArmScmiBase, two
protocols OvmfPkgX64 never installs. The bound chose both, fuzz_batch dropped both as not
installed, and the stage failed with "no campaign produced a log.json" on every ref that
reached it. The bound has to be taken over the targets this firmware can actually reach.

The other two are precedence and determinism. A bounded gate must not override a caller
that asked for specific targets, and two runs of one ref must choose the same subset or a
difference between them is a different draw rather than a regression -- neither of which
is visible in a log that says "fuzzing 2 target(s)" in every case.

Run: python3 scripts/target_choice_check.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

FAILED = 0
PASSED = 0


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
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


def census(path, rows):
    """A protocol_presence.py census. Written with CRLF, exactly as the real one is --
    a reader that splits on '\n' and compares the status to 'absent' matches nothing,
    silently keeps every protocol, and the bound is back to choosing by filename."""
    with open(path, 'w', newline='') as handle:
        handle.write('protocol,guid,status\r\n')
        for name, status in rows:
            handle.write(f'{name},00000000-0000-0000-0000-000000000000,{status}\r\n')
    return path


def evalset(where, names, extras=()):
    """A discover stage's output directory: one .txt per protocol."""
    for name in names:
        open(os.path.join(where, f'{name}.txt'), 'w').write('x')
    for name in extras:
        open(os.path.join(where, name), 'w').write('x')
    return where


def main():
    tool = load('fuzz_edk2')
    pick, SMI = tool.pick_targets, tool.SMI_TARGET

    with tempfile.TemporaryDirectory() as work:
        # Deliberately not in alphabetical creation order: os.listdir returns directory
        # order, so a selection that forgot to sort would pass on a tidy fixture and
        # choose differently on a real evalset.
        NAMES = ['UsbIo', 'Arp', 'Mtftp4', 'BlockIo', 'Dhcp4']
        BY_NAME = sorted(NAMES)          # ['Arp', 'BlockIo', 'Dhcp4', 'Mtftp4', 'UsbIo']
        full = evalset(work, NAMES, extras=[f'{SMI}.txt', 'notes.md', 'README'])

        print('bounded selection')
        two = pick(full, 2, smi=False, explicit=())
        check('takes exactly the limit', len(two) == 2, f'got {two}')
        # Against the names, not against a second call. Two calls agree whatever the
        # order is -- os.listdir is stable for an unchanged directory -- so comparing
        # the result to itself passes an implementation that never sorted at all, and
        # the subset then depends on the filesystem's hash order rather than on the ref.
        check('chosen by name, so a rerun of one ref chooses the same two',
              two == BY_NAME[:2],
              f'got {two}, expected {BY_NAME[:2]} -- directory order is not an order')
        check('every chosen target is one this version actually discovered',
              all(os.path.isfile(os.path.join(full, f'{t}.txt')) for t in two),
              f'got {two} -- a name that is not in the evalset fuzzes nothing, and the '
              f'ref finishes green having done no work')
        check('a limit larger than the discovered set is not an error',
              len(pick(full, 99, False, ())) == 5, pick(full, 99, False, ()))
        check('only .txt files are targets',
              all(t not in ('notes', 'README', 'notes.md') for t in pick(full, 99, False, ())),
              pick(full, 99, False, ()))

        print('\nall of them, which is what no -p means')
        check('limit 0 means every discovered target', pick(full, 0, False, ()) == [])
        check('a negative limit is not a slice from the end',
              pick(full, -1, False, ()) == [],
              'names[:-1] would silently fuzz all but one')

        print('\nthe handler list')
        check('the SMI target is not a protocol',
              SMI not in pick(full, 99, False, ()),
              f'{SMI}.txt shares the evalset with the protocol files and is not one of '
              f'them -- fuzzing it as a protocol spends a container and a build to die '
              f'in the generator')
        check('under --smi it is chosen first, and inside the limit',
              pick(full, 1, True, ()) == [SMI],
              f'got {pick(full, 1, True, ())} -- taking the alphabetical head here would '
              f'fuzz a protocol while reporting an SMI run')
        check('under --smi the rest are still protocols',
              pick(full, 3, True, ()) == [SMI] + BY_NAME[:2],
              pick(full, 3, True, ()))

        print('\nprecedence')
        check('an explicit --targets wins over the bound',
              pick(full, 2, False, ('Dhcp4', 'UsbIo', 'Arp')) == ['Dhcp4', 'UsbIo', 'Arp'],
              'a gate bounding targets must not override a caller who named them')
        check('an explicit --targets is kept in the order given',
              pick(full, 0, False, ('UsbIo', 'Arp')) == ['UsbIo', 'Arp'])
        check('explicit targets are not filtered against the evalset',
              pick(full, 0, False, ('NotDiscovered',)) == ['NotDiscovered'],
              'naming a target that discovery missed is a mistake worth seeing as an '
              'empty campaign, not one to silence here')

        print('\nreachability: the bound is taken over what this firmware installs')
        absent = tool.absent_targets
        rows = [('Arp', 'absent'), ('BlockIo', 'present'), ('Dhcp4', 'unknown'),
                ('Mtftp4', 'absent'), ('UsbIo', 'present')]
        seen = os.path.join(work, 'presence.csv')
        census(seen, rows)
        gone = absent(seen)
        check('a CRLF census parses, and only "absent" is dropped',
              gone == {'Arp', 'Mtftp4'},
              f'got {sorted(gone)} -- the file the fuzz stage writes uses CRLF. A reader '
              f'that splits the text on newlines itself keeps the carriage return on '
              f'every status and matches none of them, which looks exactly like a '
              f'firmware that installs everything')
        bound = pick(full, 2, False, (), seen)
        check('a protocol this firmware never installs is not chosen',
              'Arp' not in bound,
              f'got {bound} -- Arp heads the alphabet and heads the census as absent; '
              f'choosing it spends the whole bound on a LocateProtocol that fails')
        check('the bound is filled from the reachable targets instead',
              bound == ['BlockIo', 'Dhcp4'],
              f'got {bound}, expected the first two of {[n for n, st in sorted(rows) if st != "absent"]}')
        check('"unknown" is kept, because unknown is not absent',
              'Dhcp4' in bound,
              'the census cannot see a protocol installed on demand -- the whole network '
              'stack scores unknown, and dropping those bounds every gate to the handful '
              'it can prove')
        check('no census means the unfiltered head, not a crash',
              pick(full, 2, False, (), os.path.join(work, 'nope.csv')) == BY_NAME[:2])
        check('an unreadable census is the same as none',
              absent(os.path.join(work, 'nope.csv')) == set())
        check('an explicit --targets is still not filtered',
              pick(full, 0, False, ('Arp',), seen) == ['Arp'],
              'the caller named a protocol the census calls absent; that is worth an '
              'empty campaign they can see, not a silent drop')
        check('the SMI target survives a census that has no row for it',
              pick(full, 1, True, (), seen) == [SMI],
              'the handler list is not a protocol and the census never names it')
        every = census(os.path.join(work, 'all-gone.csv'),
                       [(n, 'absent') for n in NAMES])
        check('a census that empties the selection returns nothing rather than guessing',
              pick(full, 2, False, (), every) == [],
              'and the stage has to refuse: see the next check')

        print('\nan empty bounded selection must not mean "fuzz everything"')
        refuse = tool.bound_refusal
        check('a bound that selected nothing is refused',
              bool(refuse(2, None, [], 254)),
              'an empty list means "every target" to fuzz_batch, so a census that marked '
              'everything absent would turn --max-targets 2 into the full matrix on a '
              'gate that chose a bound to fit inside its runner')
        check('and the refusal says what happened',
              'selected nothing' in refuse(2, None, [], 254)
              and '254' in refuse(2, None, [], 254),
              refuse(2, None, [], 254))
        check('an unbounded run is not refused for selecting nothing',
              refuse(0, None, [], 254) == '',
              'limit 0 IS "every target", which is the default every existing run uses')
        check('a caller who named targets is not refused',
              refuse(2, ['Arp'], ['Arp'], 254) == ''
              and refuse(2, ['Arp'], [], 254) == '')
        check('a bound that selected something is not refused',
              refuse(2, None, ['BlockIo'], 254) == '')

        # Behaviour is only half of it: the stage has to CALL it and stop. Structural,
        # not a substring -- `if False and refusal:` keeps every substring intact and
        # changes the test from a name to a boolean operation.
        import ast as _ast
        body = _stage_source(tool, 'fuzz')
        tree = _ast.parse(body.strip())
        wired = False
        for node in _ast.walk(tree):
            if (isinstance(node, _ast.If) and isinstance(node.test, _ast.Name)
                    and node.test.id == 'refusal'
                    and any(isinstance(st, _ast.Return) for st in node.body)):
                wired = True
        check('the fuzz stage calls it and returns on a refusal',
              'bound_refusal(' in body and wired,
              'the policy is only worth asserting if the stage stops on it')

        print('\nthe flag itself')
        # The parser is built inside main(), so the default is read from the real
        # parser during a parse rather than from a module-level object there is none of.
        check('the default fuzzes everything, so no existing run changes behaviour',
              _default_max_targets(tool) == 0,
              f'default is {_default_max_targets(tool)!r} -- any non-zero default would '
              f'silently bound every campaign this project runs')

    print('\nthe gate that spends this')
    gate = os.path.join(os.path.dirname(HERE), '.github', 'workflows',
                        'cross-version.yml')
    try:
        import yaml
        flow = yaml.safe_load(open(gate))
    except Exception as exc:                       # pragma: no cover - CI has pyyaml
        check('cross-version.yml is readable', False, str(exc))
        flow = None
    if flow:
        # `on` is the YAML 1.1 boolean True once parsed, not the string.
        triggers = flow.get('on') or flow.get(True) or {}
        inputs = (triggers.get('workflow_dispatch') or {}).get('inputs') or {}
        default = (inputs.get('max_targets') or {}).get('default')
        check('the gate fuzzes by default',
              str(default).isdigit() and int(default) > 0,
              f'max_targets defaults to {default!r} -- at 0 every ref runs qualify-only '
              f'while the summary still claims a bounded campaign, which is the exact '
              f'shape of a gate green for work it never did')
        steps = flow['jobs']['cross-version']['steps']
        sweep = next((st for st in steps if st.get('id') == 'sweep'), {})
        body = sweep.get('run', '')
        check('and passes the bound to the driver rather than naming protocols',
              '--max-targets' in body and '--budget' in body
              and '--targets' not in body.replace('--max-targets', ''),
              'a named protocol exists on some releases and not others, so --targets '
              'here would fuzz nothing on the versions that lack it')
        verify = next((st for st in steps
                       if 'WANT = (' in str(st.get('run', ''))), {})
        want = str(verify.get('run', ''))
        check('and then insists fuzz and triage actually ran',
              "'fuzz'" in want and "'triage'" in want,
              'spending the budget and not checking the stage ran leaves every exit '
              'code at 0 and the gate green')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def _stage_source(tool, name):
    """The source of a stage function nested inside main(), by name."""
    import inspect
    import textwrap
    src = textwrap.dedent(inspect.getsource(tool.main))
    start = src.find(f'def {name}():')
    if start < 0:
        return ''
    after = src.find('\n    def ', start + 1)
    return src[start:after if after > 0 else len(src)]


def _default_max_targets(tool):
    """The --max-targets default, read from the real parser main() builds."""
    import argparse
    import contextlib
    import io as _io
    seen = {}
    real = argparse.ArgumentParser.parse_args

    def capture(self, *a, **k):
        for action in self._actions:
            if action.dest == 'max_targets':
                seen['default'] = action.default
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = capture
    try:
        with contextlib.redirect_stdout(_io.StringIO()), \
                contextlib.redirect_stderr(_io.StringIO()):
            saved = sys.argv
            sys.argv = ['fuzz_edk2.py', '--ref', 'x']
            try:
                tool.main()
            except SystemExit:
                pass
            finally:
                sys.argv = saved
    finally:
        argparse.ArgumentParser.parse_args = real
    return seen.get('default', 'absent')


if __name__ == '__main__':
    sys.exit(main())
