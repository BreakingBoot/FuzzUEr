#!/usr/bin/env python3
"""Assert --smi is given to the SMI target and to no other campaign in the batch.

--smi was a batch-wide mode switch: launch() appended it to EVERY campaign's command.
harness_generator/main.py branches on that flag and re-reads `-i <Protocol>.txt` as a list
of handler names rather than a protocol request, so each protocol campaign in a mixed batch
built the SMI harness instead of its own. Measured on run 42140097717: 63 campaigns
launched, 44 wrote a FirnessHarnesses.c, and all 44 shared one md5
(209d05016bba1f8ed970c043e319e702) across DiscoveredSmi, EdkiiBootLogo2, EdkiiFormBrowserEx
and the rest. The run was green, every per-protocol coverage number in it was the same
harness measured over and over, and nothing in the output said so.

FIRNESS_HARNESS_TIMING travels with the flag. firness.py refuses the dxe timing without
--smi -- "FIRNESS_HARNESS_TIMING=dxe needs --smi", because the dxe harness is a DXE_DRIVER
whose depex floor is gEfiSmmCommunicationProtocolGuid and without the flag the generator
would emit a UEFI_APPLICATION nothing ever runs. So a batch that carries dxe for the SMI
target has to drop it for the protocol ones, or the flag becoming per-target kills every
protocol campaign at startup. The note that says so is said once for the batch: a mixed run
is one SMI campaign and many protocol ones, and repeating it buries the launches.

Both decisions turn on the same thing, so they are asserted against the same thing: whether
this campaign is getting --smi, not whether it is the one named DiscoveredSmi. Keyed on the
name, naming DiscoveredSmi in -p WITHOUT --smi kept dxe for a campaign that was not getting
the flag -- the refusal the pop exists to prevent, through the one door left open.

This drives fuzz_batch.py rather than reading it. A source grep cannot answer either
question here -- launch()'s own comment quotes "--smi" and the error it is avoiding, so a
substring search passes on the prose whatever the code does.

The environment needs a capture of its own. --dry-run prints argv[:8] and the command, and
every `-e NAME=VALUE` falls in the gap between them, so Batch below replaces the module's
`subprocess` with a recorder and lets the real launch() build the real argv. Nothing is
spawned; the whole argv is kept, flags and environment together. The last section re-runs
the documented --dry-run invocation as a separate process, with docker itself replaced on
PATH, so the two capture paths have to agree about the flag.

Run: python3 scripts/smi_per_target_check.py
"""
import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))

FAILED = 0
PASSED = 0

TARGETS = ['DiscoveredSmi', 'EfiAcpiTable', 'EfiHiiFont']
SMI = TARGETS[0]
PROTOCOLS = TARGETS[1:]
TIMING = 'FIRNESS_HARNESS_TIMING'


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def load(name):
    """A fresh fuzz_batch, not a cached one.

    _TIMING_NOTED and _ANNOUNCED are module globals, so a module reused between batches
    starts the second one already announced and the once-per-batch assertion below would
    be measuring the first batch. Each call re-executes the file into a new module and
    nothing is registered in sys.modules.
    """
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Result:
    """What subprocess.run hands back, as fuzz_batch reads it."""

    def __init__(self, stdout='', returncode=0):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = returncode


@contextlib.contextmanager
def environment(timing):
    """The host environment a batch is launched from.

    Every FIRNESS_* name is cleared first. launch() forwards whatever the host has, so a
    developer who exports FIRNESS_QEMU_ICOUNT or a timing of their own would otherwise
    change what these assertions compare.
    """
    saved = dict(os.environ)
    for name in [k for k in os.environ if k.startswith('FIRNESS_')]:
        del os.environ[name]
    if timing:
        os.environ[TIMING] = timing
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


class Batch:
    """One run of fuzz_batch.main(), with docker replaced by a recorder.

    The command line is the real one and so is every decision taken on the way to the
    `docker run`: argument parsing, the request path, the launch loop, launch() itself.
    Only the two calls that would leave this process are replaced -- subprocess, so no
    container is created, and time, so the launch loop does not wait 30 seconds for
    campaigns that are not running.
    """

    def __init__(self, protocols, smi=False, timing=None):
        module = load('fuzz_batch')
        runs = []

        def fake_run(argv, **_kwargs):
            argv = list(argv)
            if argv[:2] != ['docker', 'run']:
                # docker ps (nothing of ours is running) and docker rm -f
                return Result()
            if '--name' in argv:
                runs.append(argv)
                return Result()
            if '--entrypoint' in argv:
                # image_supports() greps firness.py --help for the flags this batch wants
                return Result('--iteration-timeout --max-steps --seed-corpus --snapshot')
            # bindable() writes through the daemon and looks for the file here
            for index, item in enumerate(argv):
                if item == '-v' and argv[index + 1].endswith(':/probe'):
                    source = argv[index + 1][:-len(':/probe')]
                    open(os.path.join(source, '.bindprobe'), 'w').close()
            return Result()

        module.subprocess = types.SimpleNamespace(run=fake_run)
        module.time = types.SimpleNamespace(sleep=lambda *_: None)

        output = tempfile.mkdtemp(prefix='smitarget-out-')
        tree = tempfile.mkdtemp(prefix='smitarget-tree-')
        argv = ['fuzz_batch.py', '-o', output, '-p'] + list(protocols) + [
            '--no-discover', '--no-anacache', '--backend', 'qemu', '--tree', tree,
            '-j', str(len(protocols) + 1)]
        if smi:
            argv.append('--smi')
        spoken = io.StringIO()
        saved_argv = sys.argv
        try:
            sys.argv = argv
            with environment(timing), contextlib.redirect_stdout(spoken):
                module.main()
        finally:
            sys.argv = saved_argv
            shutil.rmtree(output, ignore_errors=True)
            shutil.rmtree(tree, ignore_errors=True)

        self.output = spoken.getvalue()
        self.campaigns = {}
        for run in runs:
            command = run[-1]
            found = re.search(r'-i /input/\S*/(\w+)\.txt', command)
            if not found:
                raise SystemExit(f'cannot tell which target this campaign is: {command}')
            env = {}
            for index, item in enumerate(run):
                if item == '-e' and '=' in run[index + 1]:
                    name, value = run[index + 1].split('=', 1)
                    env[name] = value
            self.campaigns[found.group(1)] = (command, env)

    def command(self, protocol):
        return self.campaigns[protocol][0]

    def env(self, protocol):
        return self.campaigns[protocol][1]

    def smi_flagged(self):
        return sorted(p for p in self.campaigns if ' --smi' in self.command(p))

    def notes(self):
        """The timing note, told apart from the rest of the batch's narration.

        Matched on lower-case 'timing': the only other line that mentions the setting is
        the environment announcement, which carries it as FIRNESS_HARNESS_TIMING.
        """
        return [line for line in self.output.splitlines() if 'timing' in line]


def dry_run(protocols, smi, timing):
    """The documented invocation, in its own process, with docker stubbed out on PATH.

    --dry-run still runs `docker ps` and `docker rm -f` to refuse a colliding campaign, so
    a shim answers both rather than this check touching the daemon. Returns the command
    string per target, parsed out of the "would run:" lines.
    """
    work = tempfile.mkdtemp(prefix='smitarget-dry-')
    try:
        shim = os.path.join(work, 'bin')
        os.makedirs(shim)
        docker = os.path.join(shim, 'docker')
        open(docker, 'w').write('#!/bin/sh\nexit 0\n')
        os.chmod(docker, 0o755)
        env = {k: v for k, v in os.environ.items() if not k.startswith('FIRNESS_')}
        env['PATH'] = shim + os.pathsep + env.get('PATH', '')
        if timing:
            env[TIMING] = timing
        argv = [sys.executable, os.path.join(HERE, 'fuzz_batch.py'),
                '-o', os.path.join(work, 'out'), '-p'] + list(protocols) + [
                    '--no-discover', '--dry-run', '--backend', 'qemu',
                    '--tree', os.path.join(work, 'empty')]
        if smi:
            argv.append('--smi')
        result = subprocess.run(argv, capture_output=True, text=True, env=env)
        commands = {}
        for line in result.stdout.splitlines():
            if 'would run:' not in line:
                continue
            found = re.search(r'-i /input/\S*/(\w+)\.txt', line)
            if found:
                commands[found.group(1)] = line
        return commands, result.stdout + result.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    print('--smi belongs to the SMI target, not to the batch')
    mixed = Batch(TARGETS, smi=True)
    check('every requested target was launched',
          sorted(mixed.campaigns) == sorted(TARGETS),
          f'launched {sorted(mixed.campaigns)}')
    check('the SMI target is given --smi', ' --smi' in mixed.command(SMI),
          mixed.command(SMI))
    for protocol in PROTOCOLS:
        check(f'{protocol} is not',
              '--smi' not in mixed.command(protocol),
              f'{mixed.command(protocol)}\n         this is the defect: the generator '
              f'then re-reads {protocol}.txt as a handler list and builds the SMI '
              f'harness, so the campaign fuzzes something other than {protocol} and '
              f'says nothing about it')
    check('exactly one campaign in the batch carries it',
          mixed.smi_flagged() == [SMI], f'carried by {mixed.smi_flagged()}')
    # The two commands are compared whole, so this fails for a change that gives the SMI
    # target a different pipeline rather than a different flag. The protocol name is the
    # only other thing that may differ between them.
    check('and --smi is the whole of the difference between the two commands',
          mixed.command(SMI).replace(' --smi', '').replace(SMI, PROTOCOLS[0])
          == mixed.command(PROTOCOLS[0]),
          f'{mixed.command(SMI)}\n         {mixed.command(PROTOCOLS[0])}')

    print('\nwithout --smi no campaign gets it')
    plain = Batch(TARGETS, smi=False)
    check('not even the SMI target', '--smi' not in plain.command(SMI),
          f'{plain.command(SMI)}\n         --smi is what the caller asked for, and this '
          f'batch did not ask')
    check('and not the protocols', plain.smi_flagged() == [], plain.smi_flagged())

    print('\nthe dxe timing follows the flag it depends on')
    dxe = Batch(TARGETS, smi=True, timing='dxe')
    check('the SMI target keeps FIRNESS_HARNESS_TIMING=dxe',
          dxe.env(SMI).get(TIMING) == 'dxe',
          f'{SMI} env is {dxe.env(SMI)} -- dxe IS the SMI harness placement, so dropping '
          f'it here builds the application harness and the latch question goes untested')
    for protocol in PROTOCOLS:
        check(f'{protocol} does not carry it at all',
              TIMING not in dxe.env(protocol),
              f'{protocol} env is {dxe.env(protocol)} -- firness.py exits on '
              f'"FIRNESS_HARNESS_TIMING=dxe needs --smi" before it fuzzes anything, so '
              f'every protocol campaign in the batch dies at startup')
    # The pop has to take that one key. Holding the rest of the environment equal is what
    # makes the two assertions above mean "the timing was removed" rather than "these two
    # campaigns differ somehow".
    kept = dict(dxe.env(SMI))
    kept.pop(TIMING, None)
    check('and nothing else was taken with it', kept == dxe.env(PROTOCOLS[0]),
          f'{kept} != {dxe.env(PROTOCOLS[0])}')
    check('the campaigns still get the forwarded settings',
          'FIRNESS_QEMU_ICOUNT' in dxe.env(PROTOCOLS[0]), dxe.env(PROTOCOLS[0]))

    print('\nthe SMI target without the flag is not an SMI campaign')
    # Same targets and the same exported timing as the batch above; --smi is the only
    # difference between the two, so what differs in the result is what the flag decided.
    unflagged = Batch(TARGETS, smi=False, timing='dxe')
    check('naming it in -p without --smi does not give it the flag',
          '--smi' not in unflagged.command(SMI), unflagged.command(SMI))
    check('so it does not keep the dxe timing either',
          TIMING not in unflagged.env(SMI),
          f'{SMI} env is {unflagged.env(SMI)} -- the campaign is not getting --smi, so '
          f'firness.py refuses dxe at startup. Gating the pop on the target\'s NAME '
          f'rather than on what the flag decided leaves this one door open, and the '
          f'error it exists to prevent comes back through it')
    check('it is a protocol campaign in every respect, environment included',
          unflagged.env(SMI) == unflagged.env(PROTOCOLS[0]),
          f'{unflagged.env(SMI)} != {unflagged.env(PROTOCOLS[0])}')
    check('and the pair turns on the flag alone, not on the target name',
          dxe.env(SMI).get(TIMING) == 'dxe' and TIMING not in unflagged.env(SMI),
          f'with --smi {dxe.env(SMI).get(TIMING)!r}, without it '
          f'{unflagged.env(SMI).get(TIMING)!r} -- one target, one exported setting, and '
          f'the flag is the whole of what decides whether it survives')
    check('the note is said for this batch too', len(unflagged.notes()) == 1,
          f'{len(unflagged.notes())} notes: {unflagged.notes()}')

    print('\nthe note is said once for the batch')
    check('the batch says why the protocol campaigns lost the timing',
          len(dxe.notes()) >= 1,
          'a setting the caller exported was dropped silently, and the campaign that '
          'behaves differently because of it is the one they were watching')
    check('once, not once per protocol campaign', len(dxe.notes()) == 1,
          f'{len(dxe.notes())} notes for {len(PROTOCOLS)} protocol campaigns:\n         '
          + '\n         '.join(dxe.notes()))

    print('\na timing that is not dxe is left alone')
    app = Batch(TARGETS, smi=True, timing='application')
    for target in TARGETS:
        check(f'{target} keeps FIRNESS_HARNESS_TIMING=application',
              app.env(target).get(TIMING) == 'application',
              f'{target} env is {app.env(target)} -- only dxe is refused without --smi; '
              f'dropping any timing makes the setting unusable for the protocols it is '
              f'valid for')
    check('and nothing is said about a timing that was not changed',
          app.notes() == [], app.notes())

    print('\nthe same answers through the documented --dry-run invocation')
    commands, spoken = dry_run(TARGETS, smi=True, timing='dxe')
    check('the dry run reports one command per target',
          sorted(commands) == sorted(TARGETS),
          f'{sorted(commands)}\n         {spoken[-400:]}')
    check('the SMI target is given --smi there too',
          ' --smi' in commands.get(SMI, ''), commands.get(SMI, '(no line)'))
    check('and the protocol targets are not',
          all('--smi' not in commands.get(p, '') for p in PROTOCOLS),
          '\n         '.join(commands.get(p, '(no line)') for p in PROTOCOLS))

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
