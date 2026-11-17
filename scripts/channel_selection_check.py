#!/usr/bin/env python3
"""Assert a caller who asks for nothing gets every protocol AND every SMI handler.

The four-ref sweep 43704163314 is the measurement this exists to stop repeating. Its own
`discover` stage line says, once per ref:

    253 protocols from 11 package(s), 17 SMI handlers (not fuzzed; pass --smi)

and its `fuzz` line says `80/112 campaign(s) fuzzed the harness [253 discovered, 141
skipped before launch]`. So 17 handlers were found and none were fuzzed, four times over,
on a run that reported WARN for the edge stability and said nothing at all about the
channel it had skipped. Nothing failed, because nothing asked.

The cause was the selection mechanism, not the workflow. `-p` named protocols; whether the
handler channel was in the run was a separate boolean whose default was off; and an input a
schedule does not carry arrives as the empty string, so the boolean could not tell "the
caller said no" from "the caller said nothing". An empty selection meant "every protocol
and no handler".

Now an empty selection means every target in BOTH channels, a channel word in `-p` means
every target in one of them, and `handlers:SmmVariableHandler` means one handler. This
checks that, and it checks the direction that no green run can reveal: a selection that
silently NARROWS. `--max-targets 2` once looked like a full sweep while running one harness
250 times, and the same shape here -- an empty selection resolving to nothing, or the
handler channel quietly dropping out of it -- reads from the outside as a clean result.

Two of these assertions are about plumbing rather than logic, because the plumbing is where
this failed twice: an env name the step does not declare reads as empty, the resolution
takes its default arm, and the flag never applies.

Run: python3 scripts/channel_selection_check.py
"""

import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWEEP = os.path.join(ROOT, '.github', 'workflows', 'fuzz-edk2.yml')
UPSTREAM = os.path.join(ROOT, '.github', 'workflows', 'upstream-smi.yml')
CROSS = os.path.join(ROOT, '.github', 'workflows', 'cross-version.yml')
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

    Every comment in the selection code quotes the spelling the code must use, names the
    run that measured the defect, and in two places writes out the very string an
    assertion greps for. Reading the raw text finds the explanation rather than the
    statement, and passes with the statement deleted.
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


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not."""
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def head(targets):
    """targets[0], or None. A mutation that empties the selection is the MOST important
    one here, and indexing straight into the list made the check die on it -- a traceback
    is not a failed assertion: nothing reading the exit code can tell the two apart."""
    return targets[0] if targets else None


class _Stop(Exception):
    pass


def parser_of(fb):
    """The argparse parser fuzz_batch really builds, lifted out of its own main().

    Asked of the parser rather than grepped out of the source, because both ways of
    grepping it are wrong and both passed a mutation. "action='store_true', default=True"
    is also how --discover is declared, so the string is present with --smi's default
    deleted; and "--no-smi" is a substring of "--no-smi-removed", so the flag reads as
    present after being renamed away. The parser answers the question that is actually
    being asked: what does a caller who passes nothing get.
    """
    import argparse
    grabbed = {}
    real = argparse.ArgumentParser.parse_args

    def spy(self, *args, **kwargs):
        grabbed['parser'] = self
        raise _Stop()

    argparse.ArgumentParser.parse_args = spy
    try:
        fb.main()
    except _Stop:
        pass
    except Exception:
        pass
    finally:
        argparse.ArgumentParser.parse_args = real
    return grabbed.get('parser')


def parsed(parser, argv):
    """The namespace for this argv, or None when the parser refuses it."""
    if parser is None:
        return None
    try:
        return parser.parse_args(['-o', os.devnull] + argv)
    except SystemExit:
        return None


# The fixture: one protocol request file per protocol, and both handler lists. Deliberately
# small and deliberately NOT alphabetically convenient -- Aaa sorts before the Discovered*
# names, so a default order that merely sorted would put a protocol first and the assertion
# that the handler channel LEADS would pass for the wrong reason.
PROTOCOLS = ['AaaFirst', 'EfiAcpiTable', 'ZzzLast']
HANDLERS = ['SmmVariableHandler', 'SmmLockBoxHandler', 'SmramProfileHandler']


def fixture(where, handler_lists=('DiscoveredSmi', 'DiscoveredSwSmi')):
    """A request directory. One attribute at a time: the ONLY difference between calls is
    which handler lists exist, so an assertion that changes behaviour cannot be credited to
    a protocol set that moved underneath it as well."""
    os.makedirs(where, exist_ok=True)
    for name in PROTOCOLS:
        with open(os.path.join(where, f'{name}.txt'), 'w') as handle:
            handle.write(f'[Protocols]\n  g{name}ProtocolGuid:Doit\n')
    for name in handler_lists:
        with open(os.path.join(where, f'{name}.txt'), 'w') as handle:
            handle.write('\n'.join(HANDLERS) + '\n')
    return where


def shell_block():
    """The channel resolution out of fuzz-edk2.yml, as runnable shell.

    Lifted rather than restated. A copy here would keep passing after the real block
    changed, which is the whole failure a check on a workflow exists to prevent.
    """
    text = io.open(SWEEP, encoding='utf-8').read()
    start = text.find('          CHANNELS="${IN_CHANNELS:-all}"')
    if start < 0:
        return None
    end = text.find('          # Sized to the runner', start)
    body = text[start:end if end > 0 else len(text)]
    return '\n'.join(line[10:] if line.startswith('          ') else line
                     for line in body.splitlines())


def resolve(channels='', timing='', event='workflow_dispatch', cron=''):
    """(exit code, {variable: value}) for what the workflow would choose."""
    body = shell_block()
    if body is None:
        return None, {}
    script = (f'REFS=""\nQUALIFY=""\nIN_CHANNELS="{channels}"\n'
              f'IN_HARNESS_TIMING="{timing}"\nGITHUB_EVENT_NAME="{event}"\n'
              f'EVENT_SCHEDULE="{cron}"\n{body}\n'
              f'echo "RESULT CHANNELS=$CHANNELS SMI=[$SMI] TARGETS=[$TARGETS] '
              f'TIMING=$TIMING REFS=[$REFS]"')
    done = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                          env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
    got = {}
    for line in done.stdout.splitlines():
        if line.startswith('RESULT '):
            for pair in re.finditer(r'(\w+)=(\[[^\]]*\]|\S*)', line[len('RESULT '):]):
                got[pair.group(1)] = pair.group(2).strip('[]')
    return done.returncode, got


def declares(name):
    """True when the step that resolves the channels also declares `name` in its own env."""
    try:
        import yaml
    except ImportError:
        return None
    try:
        parsed = yaml.safe_load(io.open(SWEEP, encoding='utf-8').read())
        for step in parsed['jobs']['matrix']['steps']:
            if 'CHANNELS="${IN_CHANNELS' in str(step.get('run') or ''):
                return name in (step.get('env') or {})
    except Exception:
        return False
    return False


def dispatch_input(name):
    try:
        import yaml
    except ImportError:
        return None
    try:
        parsed = yaml.safe_load(io.open(SWEEP, encoding='utf-8').read())
        on = parsed.get('on', parsed.get(True)) or {}
        return (on.get('workflow_dispatch') or {}).get('inputs', {}).get(name)
    except Exception:
        return None


def main():
    fb = load('fuzz_batch')
    holder = tempfile.TemporaryDirectory()

    print('the module under test is the one in this directory')
    # The recorded trap: a stale __pycache__ replays the old module and every assertion
    # below then describes code that is no longer there.
    check('fuzz_batch was loaded from scripts/, not from a cache of something else',
          os.path.abspath(fb.__file__) == os.path.join(HERE, 'fuzz_batch.py'),
          f'{getattr(fb, "__file__", "<none>")}')

    both = fixture(os.path.join(holder.name, 'both'))
    only_comm = fixture(os.path.join(holder.name, 'comm'), ('DiscoveredSmi',))
    no_handlers = fixture(os.path.join(holder.name, 'none'), ())

    print('\nan empty selection is EVERY target in BOTH channels')
    targets, filtered = fb.resolve_selection(both, None, True)
    check('every protocol is in it', set(PROTOCOLS) <= set(targets), f'{targets}')
    check('every handler list is in it too',
          {'DiscoveredSmi', 'DiscoveredSwSmi'} <= set(targets),
          f'{targets} -- this is the assertion sweep 43704163314 would have failed on all '
          f'four of its refs')
    check('and nothing else', len(targets) == len(PROTOCOLS) + 2, f'{targets}')
    check('an empty LIST means the same as no list at all',
          fb.resolve_selection(both, [], True)[0] == targets,
          'argparse gives [] for "-p" with no values and None when -p is absent; a default '
          'that only answered to one of them would depend on how the caller spelled it')
    first = head(targets)
    check('the handler channel leads, so it is not at the back of a 112-deep queue',
          first is not None and fb.channel_of(first) == fb.HANDLER_CHANNEL,
          f'{first} is first; the first firing of the Wednesday cron spent about '
          f'thirteen hours on protocols before reaching the handlers')
    check('a default selection writes no filtered request file', filtered == {},
          f'{filtered}')

    print('\n--no-smi is the one way back to the fast protocol-only sweep')
    off, _ = fb.resolve_selection(both, None, False)
    check('it drops both handler lists', not [t for t in off if fb.smi_base(t)], f'{off}')
    check('and keeps every protocol', set(off) == set(PROTOCOLS), f'{off}')
    check('it does not stop a selection from naming an SMI target',
          fb.resolve_selection(both, ['DiscoveredSmi'], False)[0] == ['DiscoveredSmi'],
          'the flag decides what an EMPTY selection reaches for; a name is a name')

    print('\nthe channel words')
    check('"protocols" is every protocol and no handler',
          fb.resolve_selection(both, ['protocols'], True)[0] == sorted(PROTOCOLS),
          f'{fb.resolve_selection(both, ["protocols"], True)[0]}')
    check('"handlers" is every handler list and no protocol',
          sorted(fb.resolve_selection(both, ['handlers'], True)[0])
          == ['DiscoveredSmi', 'DiscoveredSwSmi'],
          f'{fb.resolve_selection(both, ["handlers"], True)[0]}')
    check('"smi" is an alias for it, because that is what every flag here calls it',
          set(fb.resolve_selection(both, ['smi'], True)[0])
          == set(fb.resolve_selection(both, ['handlers'], True)[0]))
    check('a channel word is case insensitive',
          set(fb.resolve_selection(both, ['Handlers'], True)[0])
          == set(fb.resolve_selection(both, ['handlers'], True)[0]))
    check('both words together are the default set',
          set(fb.resolve_selection(both, ['protocols', 'handlers'], True)[0])
          == set(targets),
          'if these differ then "all" and "everything" are two different answers')
    check('"handlers" expands to what discovery WROTE, not to a name',
          fb.resolve_selection(only_comm, ['handlers'], True)[0] == ['DiscoveredSmi'],
          'naming DiscoveredSwSmi on a tree that has no software SMI costs a container, a '
          'full analysis and a build to find out the request file is missing')
    check('a tree with no handler list still fuzzes every protocol',
          set(fb.resolve_selection(no_handlers, None, True)[0]) == set(PROTOCOLS),
          'the default must degrade to the protocols, not to nothing')

    print('\none handler, which is a real selector and not a flag that widens')
    one, filtered = fb.resolve_selection(both, ['handlers:SmmVariableHandler'], True)
    single = head(one)
    check('it resolves to exactly one target', len(one) == 1, f'{one}')
    check('the target belongs to the handler channel',
          single is not None and fb.channel_of(single) == fb.HANDLER_CHANNEL
          and fb.smi_base(single) == fb.SMI_PROTOCOL, f'{one}')
    check('the target name carries no colon',
          single is not None and ':' not in single,
          f'{single} -- a target name becomes a docker -v argument and a colon there is '
          f'docker\'s own field separator, so the campaign would mount somewhere else')
    written = fb.write_handler_requests(both, filtered)
    check('its request file holds that handler and only that handler',
          written.get(single) == ['SmmVariableHandler'], f'{written}')
    check('and that is what is on disk',
          single is not None
          and os.path.isfile(os.path.join(both, f'{single}.txt'))
          and io.open(os.path.join(both, f'{single}.txt')).read().split()
          == ['SmmVariableHandler'])
    check('naming it under its request file instead is the same target',
          fb.resolve_selection(both, ['DiscoveredSmi:SmmVariableHandler'], True)[0] == one)
    check('a handler the list does not name is REFUSED, not widened to all of them',
          refuses(fb, both, ['handlers:NoSuchHandler']),
          'the generator would resolve no target function, and that arrives after a '
          'container, an analysis and a build, reading like a handler with no surface')
    check('a protocol with a handler suffix is refused',
          refuses(fb, both, ['EfiAcpiTable:Doit']),
          'a protocol member is chosen in its request file, not in -p')
    check('a handler asked for on a tree with no such list is refused',
          refuses(fb, no_handlers, ['handlers:SmmVariableHandler']))

    print('\na filtered file left on disk does not widen the next run')
    again, _ = fb.resolve_selection(both, None, True)
    check('the derived target is not a channel member',
          single is not None and single not in again,
          f'{again} -- it is still there from the write above; listing it would fuzz that '
          f'handler twice, once alone and once inside the full list, and make the target '
          f'count of two identical runs differ')
    check('the default set is unchanged by it', set(again) == set(targets), f'{again}')
    check('but it is still reachable by naming it',
          single is not None
          and fb.resolve_selection(both, [single], True)[0] == [single])
    check('derived() is what tells them apart',
          single is not None and fb.derived(single)
          and not fb.derived('DiscoveredSmi') and not fb.derived('EfiAcpiTable'))

    print('\nthe channel is a property of the target, not of the batch')
    check('an SMI request file maps to itself',
          fb.smi_base('DiscoveredSmi') == 'DiscoveredSmi'
          and fb.smi_base('DiscoveredSwSmi') == 'DiscoveredSwSmi')
    check('a single-handler target maps to the list it came from',
          single is not None and fb.smi_base(single) == 'DiscoveredSmi')
    check('a protocol maps to nothing', fb.smi_base('EfiAcpiTable') is None)
    fbsrc = code(source('fuzz_batch'))
    check('the firness flags are looked up by that base, not by the target name',
          'SMI_TARGETS[base]' in fbsrc,
          'SMI_TARGETS has no key "DiscoveredSmi.SmmVariableHandler", so indexing it with '
          'the target name is a KeyError in the launch loop')
    check('the flag and the dxe timing still turn on the SAME resolved answer',
          before(fbsrc, 'smi_campaign = args.smi and base is not None',
                 'if not smi_campaign and env.get(') ,
          'keyed apart, a campaign gets the dxe placement without --smi and firness.py '
          'refuses it at startup; absent entirely if either line is gone')
    check('the mode is resolved once, from handlers_wanted, and read everywhere else',
          'args.smi = handlers_wanted(asked, os.environ)' in fbsrc,
          'two resolutions of one question is how the flag and the timing come apart')
    # The STATEMENT, not the variable name: "orphans" survives a mutation to
    # `orphans = []`, which is exactly the shape that silences the warning while leaving
    # every grep for the name satisfied. code() has already removed the prose, so a
    # comment quoting this line cannot satisfy it either.
    check('a handler target in a run whose mode resolved off is still detected',
          'orphans = handlers if not args.smi else []' in fbsrc,
          'it would be analysed as a protocol and die in the generator after a container '
          'and a full analysis; overriding the mode instead would hand it the dxe timing '
          'without the flag, which firness.py refuses at startup')
    check('and the run says so, naming both ways out',
          'is an SMI handler list and this run is not ' in fbsrc
          and 'Pass --smi, or build the firmware with ' in fbsrc,
          'a warning with no remedy in it is a line someone scrolls past')
    check('the software SMI target still gets --sw-smi',
          fb.SMI_TARGETS[fb.SW_SMI_PROTOCOL].split() == ['--smi', '--sw-smi'],
          f'{fb.SMI_TARGETS}')
    # Asked of the real parser. The two obvious greps both pass a mutation that removes
    # the behaviour: --discover is ALSO declared "action='store_true', default=True", and
    # "--no-smi" is a substring of a flag renamed to "--no-smi-removed".
    parser = parser_of(fb)
    check('fuzz_batch\'s own parser could be read', parser is not None,
          'the assertions below are vacuous without it')
    bare = parsed(parser, [])
    check('passing neither flag is a THIRD state, not a silent no',
          bare is not None and bare.smi is None,
          f'smi={getattr(bare, "smi", "<no parser>")} -- a two-state flag could not tell '
          f'"the caller said no" from "the caller said nothing", and nothing is the case '
          f'that has to mean everything')
    check('--smi is a flag the parser accepts', parsed(parser, ['--smi']) is not None
          and parsed(parser, ['--smi']).smi is True)
    off_ns = parsed(parser, ['--no-smi'])
    check('--no-smi is a flag the parser accepts and it turns that channel off',
          off_ns is not None and off_ns.smi is False,
          f'{off_ns} -- this is the one obvious way to the fast protocol-only sweep, and '
          f'a parser that refuses it fails the run at startup')

    print('\nand an unset flag resolves from the firmware, not from a hope about it')
    smm = {'FIRNESS_ANALYSIS_DEFINES': '-D ASAN_SCOPE=full -D SMM_REQUIRE=TRUE'}
    check('unset on an SMM build means the handler channel is in',
          fb.handlers_wanted(None, smm) is True,
          'this is the default the instruction asks for: a caller who passes nothing gets '
          'both channels')
    check('unset on a build with NO SMM core leaves it out',
          fb.handlers_wanted(None, {'FIRNESS_ANALYSIS_DEFINES': '-D ASAN_SCOPE=full'})
          is False,
          'SMM_REQUIRE=FALSE leaves OVMF with zero SMM modules, the analyser writes a '
          'null smi-function-guid-map.json, and the campaign dies in the generator after '
          'a container and a full analysis -- once per ref. fuzz_edk2.py passes --smi '
          'only when it built one, and never passes --no-smi, so a flag that defaulted '
          'plainly ON would do exactly that on every protocol-only sweep')
    check('unset with no analysis defines at all leaves it out',
          fb.handlers_wanted(None, {}) is False)
    check('--smi overrides the firmware, because a caller may know better',
          fb.handlers_wanted(True, {}) is True)
    check('--no-smi overrides it the other way, on an SMM build',
          fb.handlers_wanted(False, smm) is False)
    check('the marker it reads is the one fuzz_edk2.py writes',
          fb.SMM_BUILD_MARK == 'SMM_REQUIRE=TRUE', f'{fb.SMM_BUILD_MARK}')
    check('and it is read out of the variable fuzz_batch already forwards',
          'FIRNESS_ANALYSIS_DEFINES' in fbsrc,
          'a different variable name would read as empty and the default would be off '
          'with nothing saying so')

    print('\nthe presence census is a protocol census and says so')
    check('an SMI target is not reported as a gap in it',
          'not smi_base(p)' in fbsrc,
          '"1 protocol(s) are absent from the census (DiscoveredSmi...)" printed on every '
          'SMI run, which trains a reader to ignore the one warning that would tell them '
          'the census was taken against different firmware')
    check('absent and smm-only are still skipped for protocols',
          "not in ('absent', 'smm-only')" in fbsrc)
    check('the stale warning is still computed before the absent filter runs',
          before(fbsrc, 'stale = [', 'absent = ['),
          'absent entirely if the line is gone')

    print('\nthe workflow reads the channel from a declared input and acts on it')
    check('the resolution block is still there to read', shell_block() is not None,
          'if this fails every number below is vacuous')
    declared = dispatch_input('channels')
    check('fuzz-edk2.yml declares a `channels` input',
          isinstance(declared, dict), f'{declared}')
    check('its default is all', (declared or {}).get('default') == 'all',
          f'{(declared or {}).get("default")} -- the instruction is that a caller who '
          f'passes nothing gets everything')
    check('it offers exactly the three channels',
          sorted((declared or {}).get('options') or [])
          == ['all', 'handlers', 'protocols'], f'{(declared or {}).get("options")}')
    check('the step that resolves it DECLARES IN_CHANNELS in its own env',
          declares('IN_CHANNELS') is not False,
          'an undeclared name reads as the empty string, the resolution takes its default '
          'arm, and the input silently never applies -- twice on this project')
    check('the old `smi` boolean is gone, so there is one selector and not two',
          dispatch_input('smi') is None,
          'two inputs for one decision is how they drift')

    rc, got = resolve()
    check('a dispatch with nothing typed asks for both channels',
          rc == 0 and got.get('CHANNELS') == 'all' and got.get('SMI') == '--smi',
          f'rc={rc} {got}')
    check('...and passes NO --targets, which is what means "every discovered target"',
          got.get('TARGETS') == '',
          f'{got} -- a channel word here would also make fuzz_edk2.py size the fuzz '
          f'stage timeout for one campaign while 112 ran')
    rc, got = resolve(channels='protocols')
    check('channels=protocols drops --smi', rc == 0 and got.get('SMI') == '', f'{got}')
    rc, got = resolve(channels='handlers')
    check('channels=handlers asks for the handler CHANNEL, not one file by name',
          rc == 0 and got.get('TARGETS') == '--targets handlers',
          f'{got} -- "--targets DiscoveredSmi" could never reach DiscoveredSwSmi')
    check('and it takes the dxe timing, which is what beats the EndOfDxe latch',
          got.get('TIMING') == 'dxe', f'{got}')
    rc, got = resolve(event='schedule', cron='0 3 * * 0')
    check('the Sunday cron pins protocols, because four refs of `all` is ~52h of a 24h job',
          rc == 0 and got.get('CHANNELS') == 'protocols', f'rc={rc} {got}')
    rc, got = resolve(event='schedule', cron='0 3 * * 3')
    check('the Wednesday cron pins handlers on master, so mainline gets both channels weekly',
          rc == 0 and got.get('CHANNELS') == 'handlers' and got.get('REFS') == 'master',
          f'rc={rc} {got}')
    rc, got = resolve(event='push')
    check('a push stays protocol-only: it is the control-flow test',
          rc == 0 and got.get('CHANNELS') == 'protocols', f'rc={rc} {got}')
    rc, _ = resolve(channels='protocols', timing='dxe')
    check('dxe with the protocol channel is refused before a 24h job starts', rc == 1,
          'it builds a UEFI_APPLICATION, places it in the FV, and every target then '
          'reports "the boot never reached the harness"')
    rc, got = resolve(channels='all', timing='dxe')
    check('dxe with BOTH channels is allowed', rc == 0 and got.get('TIMING') == 'dxe',
          f'rc={rc} {got} -- fuzz_batch drops the timing per protocol campaign; measured '
          f'on eval1 sweep 43454245046, all 138 protocol harnesses were UEFI_APPLICATION')
    rc, _ = resolve(channels='everything')
    check('a channel nobody implemented is refused rather than ignored', rc == 1)

    print('\nand the other two campaign workflows say which channel they are')
    up = io.open(UPSTREAM, encoding='utf-8').read()
    check('upstream-smi.yml asks for the handler channel',
          re.search(r'^\s*targets:\s*handlers\s*$', up, re.M) is not None,
          'it named DiscoveredSmi, so it could never cover the software SMI list')
    check('and still asks for the SMM_REQUIRE build that gives it something to reach',
          re.search(r'^\s*smi:\s*true\s*$', up, re.M) is not None)
    cross = io.open(CROSS, encoding='utf-8').read()
    check('cross-version.yml says why it is protocols only, with the evidence',
          'PROTOCOLS ONLY' in cross and 'edk2-stable202608' in cross
          and 'fuzzuer-smi-out' in cross,
          'the default is both channels, so a gate that pins one owes a reason a reader '
          'can check rather than an omission')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def refuses(fb, requests, chosen):
    """True when this selection is refused rather than silently resolved to something."""
    try:
        targets, filtered = fb.resolve_selection(requests, chosen, True)
        fb.write_handler_requests(requests, filtered)
    except SystemExit:
        return True
    return False


if __name__ == '__main__':
    sys.exit(main())
