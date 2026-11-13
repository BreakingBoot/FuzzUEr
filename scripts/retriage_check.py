#!/usr/bin/env python3
"""Assert a re-triage re-reads a finished run and cannot quietly do nothing.

Triage is code, and it moved three times in one day. bug_report.py learned that a double
fetch is only a defect where a concurrent writer can exist, which took run 43452927684
from 91 candidates to 24 on exactly the same campaigns; the site keys moved with the
findings, so the issues filed from the old keys no longer match; and the issue body
learned to show the code for a finding the sanitizer reported against its own
instrumentation. The tracker has to be rebuilt from the same data after each of those.

Re-fuzzing to do it is ten hours on a 138-target sweep -- a fetch, a port, a build and 138
campaigns -- to re-read crash CSVs that are already on disk. So --triage-only runs the
last stage over the campaigns in --out and nothing else.

The two ways that can go wrong are the ones asserted hardest here:

  * It recreates something. A mode that falls through to the build stage is not a
    re-triage, it is the run it was supposed to replace.
  * It does nothing and says so cheerfully. A re-triage that finds no campaigns, touches
    nothing and exits 0 is indistinguishable in CI from a re-triage that read everything
    and reported the same findings as before. Hence the refusals, and hence the counts in
    the output.

The image is the third thing. A sanitizer report is a module and an offset; only the
.debug images of the build that was running turn it into a file and a line. Triaging run
A's campaigns against run B's image produces source lines that are confident and wrong,
which is worse than not running -- so the tag is checked, named, and recorded.

Run: python3 scripts/retriage_check.py
"""

import importlib.util
import inspect
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
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
    # fuzz_edk2 imports bench_cases from beside it, which a bare spec load does not put
    # on the path.
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    This file's subject is a mode whose docstrings and comments explain it at length, and
    every word asserted on below appears in that prose. Matching raw text would find the
    explanation of the behaviour rather than the behaviour.
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


def stage_source(tool, name):
    """One stage closure's text. They are locals of main() and cannot be imported."""
    src = inspect.getsource(tool.main)
    start = src.find(f'def {name}():')
    if start < 0:
        return ''
    after = src.find('\n    def ', start + 1)
    return src[start:after if after > 0 else len(src)]


def plan_for(triage_only):
    """fuzz_edk2's own stage plan, lifted out of main() and evaluated.

    Lifting rather than restating: a list of stage names written out here would keep
    passing after the real plan learned to build something again, which is the one thing
    this check exists to notice.
    """
    text = source('fuzz_edk2')
    start = text.index('    plan = ((')
    end = text.index('\n    ok = True', start)
    body = '\n'.join(line[4:] for line in text[start:end].splitlines())
    names = {'args': types.SimpleNamespace(triage_only=triage_only)}
    for stage in ('reuse', 'triage', 'ready', 'fetch', 'submodules', 'port', 'vendor',
                  'sync', 'build', 'instrumented', 'discover', 'stage_image', 'detects',
                  'fuzz'):
        names[stage] = stage
    exec(body, names)
    return [name for name, _ in names['plan']]


def triage_detail(tool, found, read, image_tag):
    """The line the triage stage reports, built by the stage's own f-string."""
    src = stage_source(tool, 'triage')
    start = src.rindex('        return True, (')
    tail = src[start:].rstrip().split('return True, (', 1)[1]
    names = {'found': found, 'read': read, 'image_tag': image_tag}
    exec('detail = (' + tail, names)
    return names['detail']


def campaigns_at(root, names, with_csv=()):
    """A results directory holding campaigns, some of which reported."""
    for name in names:
        where = os.path.join(root, 'campaigns', name)
        os.makedirs(where, exist_ok=True)
        if name in with_csv:
            io.open(os.path.join(where, 'crashes.csv'), 'w', encoding='utf-8').write(
                'Phase,AtBoot,Module,Function,File,Line,Asan Msg,ErrorType,'
                'Message,Count\n')
    return os.path.join(root, 'campaigns')


def yes(_image):
    return True


def no(_image):
    return False


def seen(_path, _image):
    return True


def unseen(_path, _image):
    return False


def main():
    tool = load('fuzz_edk2')
    holder = tempfile.TemporaryDirectory()
    # ONE fixture for the refusals, so that each of them differs from the run that
    # succeeds in exactly the attribute it is about. Two fixtures that differ in two
    # things make every assertion below vacuous.
    good = os.path.join(holder.name, 'run-a')
    full = campaigns_at(good, ('EfiAcpiTable', 'EfiHiiFont', 'DiscoveredSmi'),
                        with_csv=('EfiAcpiTable', 'EfiHiiFont'))
    passing = tool.reusable(full, 'fuzzuer-ref:latest', out=good, present=yes,
                            visible=seen)

    print('it refuses rather than making what is missing')
    gone = os.path.join(holder.name, 'run-b')
    os.makedirs(gone, exist_ok=True)
    ok, why = tool.reusable(os.path.join(gone, 'campaigns'), 'fuzzuer-ref:latest',
                            out=gone, present=yes, visible=seen)
    check('a results directory with no campaigns in it is refused', ok is False, why)
    check('and the refusal names the directory it looked in',
          os.path.join(gone, 'campaigns') in why, why)
    check('and says it will not fuzz to produce one',
          'never fuzzes' in why, why)
    bare = os.path.join(holder.name, 'run-c')
    os.makedirs(os.path.join(bare, 'campaigns'), exist_ok=True)
    ok, why = tool.reusable(os.path.join(bare, 'campaigns'), 'fuzzuer-ref:latest',
                            out=bare, present=yes, visible=seen)
    check('a campaigns directory holding no campaign is refused too', ok is False, why)
    check('and that refusal is about the data, not about the image',
          'not on this host' not in why, why)
    check('the same call passes once there is a campaign to read',
          passing[0] is True, passing[1])

    print('\nit refuses when the image it would symbolise against is gone')
    ok, why = tool.reusable(full, 'fuzzuer-ref:latest', out=good, present=no,
                            visible=seen)
    check('an absent campaign image is refused', ok is False, why)
    check('and the refusal names the tag', 'fuzzuer-ref:latest' in why, why)
    check('and says what the tag was for',
          '.debug' in why and 'different build' in why,
          'a reader who does not know why the image matters will reach for another one, '
          'and get source lines from a build that was never running')
    check('the image refusal is about the image, with the campaigns plainly there',
          'no campaign data' not in why, why)
    check('only the image changed between that refusal and the run that passed',
          passing[0] is True, 'the fixture and every other argument are identical')

    print('\nit refuses a results directory a container cannot see')
    ok, why = tool.reusable(full, 'fuzzuer-ref:latest', out=good, present=yes,
                            visible=unseen)
    check('a mount that comes back empty inside the container is refused', ok is False,
          why)
    check('and is not reported as an absent campaign',
          'would read as absent' in why, why)

    print('\nit says how much it read, so a no-op cannot look like a result')
    ok, why = passing
    check('the campaigns are counted', '3 campaign(s)' in why, why)
    check('the ones carrying a report are counted separately',
          '2 with a crashes.csv' in why, why)
    check('the image is named in the same line', 'fuzzuer-ref:latest' in why, why)
    quiet = tool.reusable(campaigns_at(os.path.join(holder.name, 'run-d'), ('OneOnly',)),
                          'fuzzuer-ref:latest', out=os.path.join(holder.name, 'run-d'),
                          present=yes, visible=seen)
    check('a campaign that reported nothing still counts as a campaign',
          quiet[0] is True and '1 campaign(s)' in quiet[1]
          and '0 with a crashes.csv' in quiet[1], quiet[1])
    said = triage_detail(tool, {'candidates': [1, 2, 3], 'clusters': 7}, 4, 'fuzzuer-x:1')
    check('triage reports its candidate count', '3 candidate(s)' in said, said)
    check('and the clusters they came from', '7 cluster(s)' in said, said)
    check('and how many campaigns it read them out of', '4 campaign(s)' in said, said)
    check('and which image it resolved the addresses against',
          'fuzzuer-x:1' in said, said)

    print('\nnothing is fetched, built or fuzzed')
    plan = plan_for(True)
    check('a re-triage runs the reuse check and the triage, in that order',
          plan == ['reuse', 'triage'], f'{plan}')
    check('it does not reach the build stage', 'build' not in plan, f'{plan}')
    check('it does not reach the fuzz stage', 'fuzz' not in plan, f'{plan}')
    check('it does not rebuild the campaign image', 'image' not in plan, f'{plan}')
    check('and it fetches and ports nothing',
          not {'fetch', 'port', 'submodules', 'sync'} & set(plan), f'{plan}')
    whole = plan_for(False)
    check('a normal run still runs every stage it always did',
          whole == ['ready', 'fetch', 'submodules', 'port', 'vendor', 'sync', 'build',
                    'instrumented', 'discover', 'image', 'detects', 'fuzz', 'triage'],
          f'{whole}')

    print('\nthe triage CODE comes from the checkout, the build from the image')
    body = code(stage_source(tool, 'triage'))
    check('a re-triage mounts this checkout over the image\'s scripts',
          '/workspace/scripts:ro' in body,
          'the image carries the scripts/ it was BUILT with, so without this a re-triage '
          'runs the triage it is meant to replace and reports the same numbers')
    check('and only on a re-triage',
          re.search(r'if args\.triage_only:\s*\n\s*argv \+=', body) is not None, body)
    check('the .debug tree it symbolises against is still the image\'s',
          "'--build', '/workspace/tmp/edk2'" in body, body)

    print('\nthe record says which build the report describes')
    where = os.path.join(holder.name, 'saved')
    run = tool.Run('some-ref', where)
    run.image = 'fuzzuer-some-ref:latest'
    run.stage('reuse').ok = True
    run.save()
    saved = json.load(open(os.path.join(where, 'run.json')))
    check('run.json names the image the run used',
          saved.get('image') == 'fuzzuer-some-ref:latest', f'{saved.get("image")!r}')
    driver = code(source('fuzz_edk2'))
    check('the run.json a re-triage replaces is kept',
          "'run-fuzz.json'" in driver and 'shutil.copyfile' in driver,
          'it is the only machine-readable account of the campaign that produced the '
          'data being re-read')

    print('\nthe exit codes still mean what they meant')
    def verdict(stages):
        made = tool.Run('ref', where)
        for name, state in stages:
            made.stage(name).ok = state
        # report() prints the stage table on its way to the exit code, and four of those
        # in the middle of this check read as four runs rather than as one assertion.
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            return made.report()
    check('a re-triage that read and reported exits 0',
          verdict((('reuse', True), ('triage', True))) == 0)
    check('a refusal exits 1',
          verdict((('reuse', False),)) == 1)
    check('a degraded stage still exits 2',
          verdict((('reuse', True), ('triage', tool.WARN))) == 2)
    check('a stage that was deliberately not run is not degraded',
          verdict((('reuse', True), ('triage', True), ('fuzz', None))) == 0,
          'skipping the stages a mode exists to skip must not colour the run')

    print('\nthe mode is reachable from the action')
    helped = subprocess.run([sys.executable, os.path.join(HERE, 'fuzz_edk2.py'), '--help'],
                            capture_output=True, text=True, timeout=120)
    check('the driver takes --triage-only', '--triage-only' in helped.stdout,
          helped.stdout[-400:])
    refused = subprocess.run([sys.executable, os.path.join(HERE, 'fuzz_edk2.py'),
                              '--ref', 'x', '--out', os.path.join(holder.name, 'nope'),
                              '--triage-only', '--skip-fuzz'],
                             capture_output=True, text=True, timeout=120)
    check('--triage-only with --skip-fuzz is refused before anything runs',
          refused.returncode != 0
          and '--skip-fuzz' in refused.stdout + refused.stderr,
          f'rc={refused.returncode} {refused.stdout}{refused.stderr}'[:300])
    try:
        import yaml
    except ImportError:
        print('  PyYAML absent, so action.yml cannot be parsed; its wiring is unchecked')
        yaml = None
    if yaml is not None:
        action = yaml.safe_load(io.open(os.path.join(REPO, 'action.yml'),
                                        encoding='utf-8'))
        inputs = action.get('inputs') or {}
        check('action.yml declares a triage-only input', 'triage-only' in inputs,
              f'{sorted(inputs)}')
        check('it is off by default',
              str((inputs.get('triage-only') or {}).get('default')) == 'false',
              'every existing caller must keep running the whole pipeline')
        check('its description says the campaigns and the image have to be there already',
              'image' in str((inputs.get('triage-only') or {}).get('description', '')),
              'the two ways this mode refuses are the two things a caller has to '
              'provide, so they belong in the input a caller reads')
        steps = (action.get('runs') or {}).get('steps') or []
        fuzz_step = next((s for s in steps if s.get('id') == 'run'), {})
        env = fuzz_step.get('env') or {}
        check('the Fuzz step takes it through the environment',
              env.get('IN_TRIAGE_ONLY') == '${{ inputs.triage-only }}',
              f'{env.get("IN_TRIAGE_ONLY")!r} -- an input interpolated into the body '
              f'instead is how a caller\'s text reaches this shell')
        run_body = str(fuzz_step.get('run', ''))
        check('and the body turns it into the driver\'s flag',
              re.search(r'IN_TRIAGE_ONLY.*\n?.*--triage-only', run_body) is not None,
              'the input is declared and never passed otherwise')
        check('the body reads the name the step declares',
              not (set(re.findall(r'IN_[A-Z_]+', run_body)) - set(env)),
              f'{sorted(set(re.findall(r"IN_[A-Z_]+", run_body)) - set(env))} is read '
              f'and never declared')
        bootstrap = next((s for s in steps
                          if str(s.get('name', '')).startswith('Bootstrap')), {})
        check('the bootstrap step is skipped on a re-triage',
              "inputs.triage-only != 'true'" in str(bootstrap.get('if', '')),
              f'{bootstrap.get("if")!r} -- bootstrapping is hours on a runner missing '
              f'the base image, which a re-triage never uses')
        issues = next((s for s in steps if s.get('id') == 'issues'), {})
        check('the issue filing still runs off the candidate count, so it follows',
              'steps.run.outputs.candidates' in str(issues.get('if', '')),
              'a re-triage that files nothing leaves the tracker on the old site keys')

    print('\nthe triage that runs is the triage in this checkout, on BOTH paths')
    # The re-triage path is explicit about this -- it mounts the checkout's scripts over
    # the image's, because the image's copy is whatever existed when the image was built,
    # which on a re-triage is exactly the triage being replaced. Measured: without the
    # mount the same campaigns come back as 91 candidates instead of 24, which is the
    # no-op failure wearing the result it was supposed to produce.
    #
    # The FULL path relies on a different mechanism and nothing said so: the image stage
    # copies this checkout's scripts/ into the build context and runs docker build every
    # time, so the image's copy cannot be stale. That invariant is one "the image already
    # exists, skip the build" optimisation away from silently triaging with old code, and
    # the symptom would be a sweep reporting the previous release's findings. Both
    # mechanisms are asserted here so neither can be removed on its own.
    body = code(source('fuzz_edk2'))
    check('the image stage copies this checkout\'s scripts into the build context',
          "os.path.join(REPO, 'scripts'), 'scripts'" in body,
          'the image\'s /workspace/scripts is the only copy a full run\'s triage reads')
    check('and builds the image rather than reusing one that exists',
          "'docker', 'build', '-t', image_tag" in body
          and 'image_present(image_tag)' not in
              body[body.index("'docker', 'build', '-t', image_tag") - 900:
                   body.index("'docker', 'build', '-t', image_tag")],
          'a reuse branch here would make the copy above dead and the triage stale')
    # One expression, binding the host path to the container path to read-only. Three
    # separate substring tests would each stay true while the line that joins them was
    # rewritten -- which is what a mutation of the first of four /workspace/scripts
    # occurrences demonstrated: every part present, the mount gone.
    check('the re-triage mounts THIS checkout at the path triage reads from',
          re.search(r'os\.path\.join\(REPO,\s*"scripts"\)\}:/workspace/scripts:ro',
                    body) is not None,
          'a re-triage cannot rebuild the image, so the mount is its only way to be new, '
          'and it has to land on the path bug_report.py is invoked from')
    check('and triage is invoked from that same path',
          "'/workspace/scripts/bug_report.py'" in body,
          'a mount somewhere else is a mount that changes nothing')
    check('and the build tree stays the image\'s, because the .debug images live there',
          "'--build', '/workspace/tmp/edk2'" in body,
          'symbolising an address needs the build that ran, not the code that triages')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
