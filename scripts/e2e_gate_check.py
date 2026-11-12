"""Assert the end-to-end gates, by running the gates that are actually in the workflows.

    python3 scripts/e2e_gate_check.py

Three things are checked, and all three by running the real thing rather than restating it:

  * stable-e2e.yml decides whether a release is fit to tag -- one release, fuzzing and
    triage included.
  * cross-version.yml decides whether the pipeline still qualifies across SEVERAL
    releases -- port, build, instrumented, detects, no fuzzing budget.
  * the push triggers, so a branch pushed to reach one of them cannot start another
    workflow's firmware build beside it.

Both gates are heredoc'd Python, so nothing in this repository could see them: the YAML
parse takes a heredoc body as a string and the Python parse only reads scripts/*.py. The
stable one has been wrong three times, and every time in the same direction -- it passed a
run it should have rejected:

  * it pattern-matched the `stages` OUTPUT, a count like "13/13", for the words "fuzz"
    and "triage". A count never contains a word, so no run could fail it.
  * it then used `not stages[n]['ok']`, which counts ok=None -- a stage deliberately
    skipped -- as a failure, so a correct qualify-only run failed its own gate.
  * and `ok is not True` rejected ok="warn": the stage ran, its triage is the report, and
    a single campaign of four losing its boot would have failed the gate.

So this EXTRACTS the live gates out of the workflows and runs them against fixtures. A
copy would drift; this cannot.
"""

import ast
import glob
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FLOW = os.path.join(REPO, '.github', 'workflows')
STABLE = os.path.join(FLOW, 'stable-e2e.yml')
CROSS = os.path.join(FLOW, 'cross-version.yml')

BASE = [{'name': 'build', 'ok': True, 'detail': 'firmware built, FV 65% full'},
        {'name': 'detects', 'ok': True, 'detail': 'benchmark 12 of 12'}]

FUZZED = '4/4 campaign(s) fuzzed the harness (900 iteration(s))'

# (name, extra stages, write bugs.json, expected exit, why this shape matters)
CASES = [
    ('clean',
     [{'name': 'fuzz', 'ok': True, 'detail': FUZZED},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s) from 0 cluster(s)'}],
     True, 0, 'an ordinary end-to-end run'),
    ('degraded',
     [{'name': 'fuzz', 'ok': 'warn',
       'detail': '3/4 campaign(s) fuzzed the harness (49334 iteration(s)) -- 1 produced '
                 'nothing'},
      {'name': 'triage', 'ok': True, 'detail': '9 candidate(s) from 10 cluster(s)'}],
     True, 0, 'a degraded fuzz stage still RAN; its triage is the report'),
    ('qualify-only',
     [{'name': 'fuzz', 'ok': None, 'detail': 'not run: --skip-fuzz'},
      {'name': 'triage', 'ok': None, 'detail': 'not run: --skip-fuzz'}],
     True, 1, 'the hole this gate exists for: every stage passes and nothing was fuzzed'),
    ('fuzz-failed',
     [{'name': 'fuzz', 'ok': False, 'detail': 'every boot spent its budget'},
      {'name': 'triage', 'ok': None, 'detail': 'not run'}],
     True, 1, 'a failed stage'),
    ('nothing-reached-the-harness',
     [{'name': 'fuzz', 'ok': True,
       'detail': '0/4 campaign(s) fuzzed the harness (0 iteration(s))'},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s) from 0 cluster(s)'}],
     True, 1, 'the port applied, the firmware built, and no campaign got in'),
    ('no-report',
     [{'name': 'fuzz', 'ok': True, 'detail': FUZZED},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s)'}],
     False, 1, 'triage claimed to run and wrote no bugs.json'),
    ('stages-absent', [], True, 1, 'fuzz and triage not in run.json at all'),
]


def extract(workflow, step, argc=1):
    """One gate's own source, out of its step's heredoc.

    `argc` is how many arguments the step hands the heredoc, which is the signature this
    locates it by: a step that stopped passing them is a step that no longer runs the gate
    being tested here.
    """
    try:
        text = open(workflow, encoding='utf-8').read()
    except OSError as exc:
        sys.exit(f'::error::cannot read {workflow}: {exc}')
    # The step first, so a heredoc belonging to another step cannot be picked up -- both
    # of these workflows have more than one.
    start = text.find(f'- name: {step}')
    if start < 0:
        sys.exit(f'::error::no step named {step!r} in {workflow} -- it was renamed, and '
                 f'this check is now testing nothing')
    hit = re.search(r"python3 - ((?:\"\$\w+\" ){%d})<<'PY'\n(.*?)\n\s*PY\s*$" % argc,
                    text[start:], re.S | re.M)
    if not hit:
        sys.exit(f'::error::the step {step!r} no longer carries a PY heredoc taking '
                 f'{argc} argument(s)')
    body = hit.group(2)
    # Strip the YAML block indentation, which is whatever the first line carries.
    pad = len(body) - len(body.lstrip(' '))
    return '\n'.join(l[pad:] if l.startswith(' ' * pad) else l for l in body.split('\n'))


def run_gate(source, argv):
    """Write a gate to disk and run it, isolated from this process's imports."""
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False,
                                     encoding='utf-8') as handle:
        handle.write(source)
        path = handle.name
    try:
        return subprocess.run([sys.executable, '-I', path, *argv],
                              capture_output=True, text=True)
    finally:
        os.unlink(path)


def stable_gate():
    """stable-e2e.yml: one release, and the fuzz and triage stages must have RUN."""
    print('the stable-release gate (stable-e2e.yml)')
    # The step's FULL name. `find` matches a prefix, so the shorter 'Every stage ran' this
    # used to carry went on finding the step after any rename of its tail -- and the
    # mutation that renames it was then not caught by anything.
    source = extract(STABLE, 'Every stage ran and the pipeline reached triage', argc=1)
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, extra, bugs, want, why in CASES:
            root = os.path.join(tmp, name)
            os.makedirs(root)
            json.dump({'ref': 'edk2-stable202608', 'stages': BASE + extra},
                      open(os.path.join(root, 'run.json'), 'w'))
            if bugs:
                json.dump({'candidates': [], 'clusters': 0},
                          open(os.path.join(root, 'bugs.json'), 'w'))
            done = run_gate(source, [root])
            if done.returncode != want:
                print(f'  [FAIL] {name}: gate exited {done.returncode}, want {want} '
                      f'-- {why}')
                for line in (done.stdout + done.stderr).strip().split('\n')[-4:]:
                    print(f'         {line}')
                bad = 1
            else:
                verdict = 'accepts' if want == 0 else 'rejects'
                print(f'  [ok  ] {verdict:<7} {name:<28} {why}')
    # A gate that accepted everything would pass every case above only if none of them
    # expected a rejection. Assert the fixtures themselves still disagree.
    if not any(c[3] for c in CASES) or all(c[3] for c in CASES):
        print('::error::the fixtures no longer cover both outcomes')
        bad = 1
    return bad


# ---------------------------------------------------------------------------
# cross-version.yml
#
# The verdict step there judges exit codes, and sweep_verdict.py --selftest already
# asserts that policy. What is asserted here is the OTHER half: that the six stages which
# can notice a release moving under the port actually ran. Every exit code can be 0 while
# a stage never ran, and the whole gate would be green having proved the firmware compiles
# and nothing about whether ASan is in it, or whether a harness can be built for that
# release at all.
#
# `fuzz` and `triage` are in that set since the gate stopped being qualify-only. They are
# the only per-version evidence that a HARNESS can be generated, built and driven against
# the release's own headers, which no amount of firmware checking implies -- so a ref that
# skipped them must not qualify, and the fuzz-skipped case below is what holds that.
# ---------------------------------------------------------------------------

QUALIFIED = [{'name': 'port', 'ok': True, 'detail': '22 clean, 9 resolved, 0 unresolved'},
             {'name': 'build', 'ok': True, 'detail': 'firmware built, FV 65% full'},
             {'name': 'instrumented', 'ok': True, 'detail': '246/246 modules'},
             {'name': 'discover', 'ok': True, 'detail': '244 protocol(s)'},
             {'name': 'detects', 'ok': True, 'detail': 'benchmark 12 of 12'},
             {'name': 'fuzz', 'ok': True, 'detail': FUZZED},
             {'name': 'triage', 'ok': True,
              'detail': '0 candidate(s) from 0 cluster(s)'}]

SPREAD = ['edk2-stable202305', 'edk2-stable202405', 'edk2-stable202508',
          'edk2-stable202608']


def with_stage(name, ok, detail='changed'):
    """QUALIFIED with one stage replaced, or removed when `ok` is 'absent'."""
    out = []
    for stage in QUALIFIED:
        if stage['name'] != name:
            out.append(dict(stage))
        elif ok != 'absent':
            out.append({'name': name, 'ok': ok, 'detail': detail})
    return out


# (name, [(ref, exit code, stages or None)], expected exit, why)
CROSS_CASES = [
    ('clean', [(r, 0, QUALIFIED) for r in SPREAD] + [('master', 0, QUALIFIED)], 0,
     'four releases and master, every qualifying stage passed'),
    ('degraded',
     [(SPREAD[0], 2, with_stage('instrumented', 'warn', '238/246 modules')),
      (SPREAD[1], 0, QUALIFIED), (SPREAD[2], 0, QUALIFIED), (SPREAD[3], 0, QUALIFIED),
      ('master', 0, QUALIFIED)], 0,
     'a WARN stage RAN. "ok is not True" would reject it, and a WARN exiting 1 is what '
     'made the weekly sweep red on every run it ever completed'),
    ('detects-skipped',
     [(SPREAD[0], 0, QUALIFIED), (SPREAD[1], 0, QUALIFIED), (SPREAD[2], 0, QUALIFIED),
      (SPREAD[3], 0, with_stage('detects', None, 'not run')),
      ('master', 0, QUALIFIED)], 1,
     'the hole this step exists for: every exit code is 0 and nothing proved ASan '
     'reports on the newest release'),
    ('instrumented-skipped',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 0, with_stage('instrumented', None, 'not run')),
        ('master', 0, QUALIFIED)], 1,
     'a build that succeeded does not imply the modules carry __asan_load/__asan_store'),
    ('port-failed',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 1, with_stage('port', False, '22 clean, 1 failed -- the port did '
                                                 'not land')),
        ('master', 0, QUALIFIED)], 1,
     'exactly the OvmfPkgIa32.dsc shape: the newest release hard-failed at port and '
     'everything older was fine'),
    ('stage-absent',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 0, with_stage('detects', 'absent')), ('master', 0, QUALIFIED)], 1,
     'a stage missing from run.json altogether, which `stages.get(n)["ok"]` would have '
     'raised on rather than reported'),
    ('master-alone-bad',
     [(r, 0, QUALIFIED) for r in SPREAD]
     + [('master', 0, with_stage('detects', False, 'no report'))], 0,
     'upstream master is early warning, not a regression here -- the same split the '
     'verdict step makes'),
    ('release-ok-but-no-run-json',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]] + [(SPREAD[3], 0, None),
                                                ('master', 0, QUALIFIED)], 1,
     'exit 0 and no run.json: the driver said it was fine and left no record of it'),
    ('release-failed-and-no-run-json',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]] + [(SPREAD[3], 1, None),
                                                ('master', 0, QUALIFIED)], 0,
     'a ref that died before writing one is the VERDICT step\'s error, and saying it '
     'twice is noise -- paired_verdict() asserts the job is still red'),
    ('fuzz-skipped',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 0, with_stage('fuzz', None, 'not run: --skip-fuzz')),
        ('master', 0, QUALIFIED)], 1,
     'the hole the bounded gate exists to close: the firmware stages all passed and no '
     'harness was ever generated for the newest release, with every exit code 0'),
    ('triage-skipped',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 0, with_stage('triage', None, 'not run')),
        ('master', 0, QUALIFIED)], 1,
     'a campaign that ran and was never read is not a result'),
    ('fuzz-degraded',
     [(r, 0, QUALIFIED) for r in SPREAD[:3]]
     + [(SPREAD[3], 2, with_stage('fuzz', 'warn',
                                  '3/4 campaign(s) fuzzed the harness')),
        ('master', 0, QUALIFIED)], 0,
     'a campaign short of its targets RAN. No full-size sweep has ever come back '
     'without one, so rejecting a WARN here would make this red on every run'),
    ('empty-ledger', [], 1,
     'no ref was qualified at all, which must never be green -- the failure a loop that '
     'never ran produces'),
]


def gate_wants(source):
    """The stage names cross-version.yml's own step insists on, read from its source.

    A literal list here is a second copy of a policy, and the copy is what goes stale.
    """
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', '') == 'WANT'):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError('cross-version.yml\'s stage step declares no WANT tuple')


def lay_out(root, ledger_path, refs):
    """Write a fixture: one fuzz-<slug>/run.json per ref, plus the ledger."""
    slug = lambda ref: re.sub(r'[^A-Za-z0-9._-]', '-', ref)
    with open(ledger_path, 'w', encoding='utf-8') as handle:
        for ref, code, stages in refs:
            handle.write(f'{ref} {code}\n')
            if stages is None:
                continue
            where = os.path.join(root, f'fuzz-{slug(ref)}')
            os.makedirs(where, exist_ok=True)
            json.dump({'ref': ref, 'stages': stages},
                      open(os.path.join(where, 'run.json'), 'w'))


def cross_gate():
    """cross-version.yml: the qualifying stages ran, on every version."""
    print('the cross-version gate (cross-version.yml)')
    source = extract(CROSS, 'The qualifying stages ran on every version', argc=2)
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, refs, want, why in CROSS_CASES:
            root = os.path.join(tmp, name)
            os.makedirs(root)
            ledger = os.path.join(tmp, f'{name}.rc')
            lay_out(root, ledger, refs)
            done = run_gate(source, [root, ledger])
            if done.returncode != want:
                print(f'  [FAIL] {name}: gate exited {done.returncode}, want {want} '
                      f'-- {why}')
                for line in (done.stdout + done.stderr).strip().split('\n')[-5:]:
                    print(f'         {line}')
                bad = 1
            else:
                verdict = 'accepts' if want == 0 else 'rejects'
                print(f'  [ok  ] {verdict:<7} {name:<30} {why}')
    if not any(c[2] for c in CROSS_CASES) or all(c[2] for c in CROSS_CASES):
        print('::error::the cross-version fixtures no longer cover both outcomes')
        bad = 1
    return bad


def paired_verdict():
    """Every bad ledger is caught by the pair of steps, not necessarily by one of them.

    cross-version.yml judges a run twice: sweep_verdict.py reads the exit codes, and the
    stage step reads what actually ran. Either may legitimately pass a shape the other
    rejects -- a ref that died before writing a run.json is the verdict's business, and a
    ref that exited 0 with `detects` skipped is the stage step's. Both steps carry
    `if: always()`, so what makes the JOB red is the disjunction, and that is what has to
    hold. Asserting each step alone would let a shape fall between them.
    """
    print('and no bad shape falls between the two steps')
    sys.path.insert(0, HERE)
    try:
        import sweep_verdict
    except Exception as exc:                                  # noqa: BLE001
        print(f'  [FAIL] cannot import the verdict policy: {exc}')
        return 1
    source = extract(CROSS, 'The qualifying stages ran on every version', argc=2)
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        # The gate's own list, not a copy of it. This was spelled out here as
        # ('port', 'build', 'instrumented', 'detects') and silently disagreed with the
        # workflow the moment the gate started demanding fuzz and triage: every case
        # using the clean fixture then went red while this still expected green, and the
        # check failed in CI rather than reporting what changed.
        want_stages = gate_wants(source)
        for name, refs, want, why in CROSS_CASES:
            root = os.path.join(tmp, name)
            os.makedirs(root)
            ledger = os.path.join(tmp, f'{name}.rc')
            lay_out(root, ledger, refs)
            stage_red = run_gate(source, [root, ledger]).returncode != 0
            verdict_red, _ = sweep_verdict.verdict([(r, c) for r, c, _ in refs])
            job_red = stage_red or verdict_red
            # Which shapes SHOULD leave the job red: anything where a release did not
            # come back clean or degraded, or where a release's qualifying stages did
            # not run. Derived from the fixture rather than listed, so a new case cannot
            # be added without an expectation.
            release = re.compile(r'^edk2-stable\d{6}(\.\d+)?$')
            should = not refs or any(
                release.match(ref) and (code not in (0, 2) or stages is None
                                        or any(s['ok'] in (False, None)
                                               for s in stages
                                               if s['name'] in want_stages)
                                        or set(want_stages)
                                        - {s['name'] for s in stages})
                for ref, code, stages in refs)
            if job_red != should:
                print(f'  [FAIL] {name}: job red={job_red}, want {should} '
                      f'(stage={stage_red} verdict={verdict_red}) -- {why}')
                bad = 1
            else:
                who = ('neither' if not job_red else
                       'both' if stage_red and verdict_red else
                       'stage step' if stage_red else 'verdict step')
                print(f'  [ok  ] red={str(job_red):<5} by {who:<12} {name}')
    return bad


# ---------------------------------------------------------------------------
# The push triggers.
#
# A branch prefix is how every one of these workflows is reached without an API token, and
# the prefixes overlap by construction: action-smoke.yml matches `ci-**` and excludes the
# dedicated ones one at a time, so a NEW prefix is a collision until somebody remembers to
# add it to that list. Each of these workflows builds firmware on a runner that takes one
# job at a time, so a collision means a targeted test silently costs two builds and queues
# behind itself -- and a `fuzzuer-cleanup-**` branch once matched `fuzzuer-**` and started
# a campaign.
# ---------------------------------------------------------------------------

# checks.yml has `push:` with no branch filter, so it runs on every push by design. It is
# the cheap static-check job, not a firmware build, so it is not part of the exclusivity
# rule below -- and that is stated here rather than discovered.
UNFILTERED_OK = {'checks.yml'}


def to_regex(pattern):
    """GitHub's branch-filter glob, as a regex.

    `**` crosses `/`, `*` does not, `?` is one character that is not `/`. Everything else
    is literal -- which matters, because `.` appears in a ref name and would otherwise
    match anything.
    """
    out, i = [], 0
    while i < len(pattern):
        char = pattern[i]
        if char == '*':
            if pattern[i:i + 2] == '**':
                out.append('.*')
                i += 2
                continue
            out.append('[^/]*')
        elif char == '?':
            out.append('[^/]')
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile('^' + ''.join(out) + '$')


def matches(patterns, branch):
    """Does a push to `branch` trigger a workflow with these branch patterns?

    Order matters, the way GitHub documents it: a later matching pattern overrides an
    earlier one, so a `!` after a positive match excludes and a positive after a `!`
    re-includes. `not any(negative)` would get the common case right and the order wrong.
    """
    hit = False
    for pattern in patterns:
        negated = pattern.startswith('!')
        if to_regex(pattern[1:] if negated else pattern).match(branch):
            hit = not negated
    return hit


def push_filters():
    """{workflow file: [branch patterns]} for every workflow with a push trigger."""
    try:
        import yaml
    except ImportError:
        return None
    out = {}
    for name in sorted(os.listdir(FLOW)):
        if not name.endswith(('.yml', '.yaml')):
            continue
        with open(os.path.join(FLOW, name), encoding='utf-8') as handle:
            doc = yaml.safe_load(handle)
        if not isinstance(doc, dict):
            continue
        # `on:` is a YAML boolean, so PyYAML gives it the key True. A check that looked
        # only for the string would find no triggers at all and pass every assertion.
        triggers = doc.get(True, doc.get('on'))
        if not isinstance(triggers, dict) or 'push' not in triggers:
            continue
        push = triggers['push'] or {}
        out[name] = list(push.get('branches') or []) if isinstance(push, dict) else []
    return out


def triggers():
    """Each prefix reaches exactly one firmware-building workflow."""
    print('and a branch pushed to reach one gate reaches only that gate')
    filters = push_filters()
    if filters is None:
        print('  [skip] PyYAML is not installed, so the triggers cannot be parsed')
        return 0
    bad = 0
    builders = {n: p for n, p in filters.items()
                if n not in UNFILTERED_OK and p}
    if len(builders) < 4:
        print(f'  [FAIL] only {len(builders)} branch-filtered workflow(s) found; the '
              f'parse is wrong, not the repository')
        return 1
    # Every positive pattern anybody declared, turned into a branch somebody would push.
    # Derived from the files, so a prefix added without an exclusion fails here rather
    # than on the runner.
    samples = []
    for name, patterns in sorted(builders.items()):
        for pattern in patterns:
            if pattern.startswith('!'):
                continue
            samples.append((name, pattern.replace('**', 'sample')
                                          .replace('*', 'sample')))
    for owner, branch in samples:
        reached = sorted(n for n, p in builders.items() if matches(p, branch))
        if reached == [owner]:
            print(f'  [ok  ] {branch:<22} -> {owner}')
            continue
        # A pattern can legitimately be the catch-all: `ci-**` belongs to action-smoke,
        # and `ci-sample` reaching only action-smoke is the case above. Anything else
        # reaching two workflows is two firmware builds for one push.
        bad = 1
        if not reached:
            print(f'  [FAIL] {branch:<22} -> nothing. {owner} declares this pattern and '
                  f'a push to it would run no workflow at all')
        else:
            print(f'  [FAIL] {branch:<22} -> {", ".join(reached)}. One push, '
                  f'{len(reached)} firmware builds on a runner that takes one job')
    # The specific pair this check was written for, named so a reader can see it is
    # covered rather than inferring it from the loop.
    for branch, want in (('ci-versions-1', 'cross-version.yml'),
                         ('ci-versions-a/b', 'cross-version.yml'),
                         ('ci-stable-1', 'stable-e2e.yml'),
                         ('ci-sweep-1', 'fuzz-edk2.yml'),
                         ('ci-anything-else', 'action-smoke.yml')):
        reached = sorted(n for n, p in builders.items() if matches(p, branch))
        if reached != [want]:
            print(f'  [FAIL] {branch} reaches {reached or "nothing"}, want [{want}]')
            bad = 1
    # And checks.yml still runs on all of them: it is where every assertion in this file
    # is executed, so a branch filter appearing on it would silently stop all of this.
    if 'checks.yml' in filters and filters['checks.yml']:
        print(f'  [FAIL] checks.yml now filters branches ({filters["checks.yml"]}), so '
              f'these checks no longer run on a ci-* push')
        bad = 1
    else:
        print('  [ok  ] checks.yml runs on every push, so these checks run beside each gate')
    return bad


# ---------------------------------------------------------------------------
# The shell around the gates.
#
# The steps above are Python and can be extracted and run. The step that CHOOSES the refs
# and runs the loop is shell, and the first version of it appended `master` straight onto a
# command substitution -- which strips the trailing newline, so the list came out as
# "... edk2-stable202405 edk2-stable202305master": four refs instead of five, the last one
# a ref that does not exist. It fails to fetch, it is not a release so its failure is only
# a warning, and the gate is GREEN having qualified three releases and called it four.
#
# So the step bodies are taken out of the YAML and run against a stub driver and a
# synthetic edk2. Nothing is built; what is under test is the plumbing.
# ---------------------------------------------------------------------------

STUB = '''\
import json, os, sys
ref = sys.argv[sys.argv.index('--ref') + 1]
out = sys.argv[sys.argv.index('--out') + 1]
os.makedirs(out, exist_ok=True)
stages = [{'name': n, 'ok': True, 'detail': f'{n} ok'} for n in
          ('ready', 'fetch', 'submodules', 'port', 'vendor', 'sync', 'build',
           'instrumented', 'discover', 'image', 'detects')]
# Modelled on the driver's own contract rather than fixed: the gate fuzzes a bounded
# subset by default and passes --skip-fuzz only when asked for 0 targets, so a stub that
# always reported a skipped campaign would assert the gate against a shape it no longer
# produces -- which is exactly how this check went stale.
skipped = '--skip-fuzz' in sys.argv
stages += [{'name': n,
            'ok': None if skipped else True,
            'detail': 'not run: --skip-fuzz' if skipped else f'{n} ok'}
           for n in ('fuzz', 'triage')]
plan = dict(p.split('=') for p in os.environ.get('STUB_RC', '').split(',') if p)
rc = int(plan.get(ref, 0))
if rc:
    for s in stages:
        if s['name'] == 'detects':
            s['ok'] = False if rc == 1 else 'warn'
json.dump({'ref': ref, 'stages': stages}, open(os.path.join(out, 'run.json'), 'w'))
sys.exit(rc)
'''


def sandbox(tmp):
    """A repository shaped like this one, with a stub driver and a synthetic edk2.

    The edk2 is a real git repository carrying a tag per release the README claims, so
    --pick resolves them with no network and no submodule: in checks.yml the submodule sits
    at the fork's commit with no upstream tags fetched, and a dry run that depended on
    those would fail for a reason that has nothing to do with the workflow.
    """
    root = os.path.join(tmp, 'repo')
    os.makedirs(os.path.join(root, 'scripts'))
    os.makedirs(os.path.join(root, 'eval_source'))
    os.symlink(os.path.join(HERE, 'sweep_verdict.py'),
               os.path.join(root, 'scripts', 'sweep_verdict.py'))
    # The REAL README, so the claim under test is the claim this repository publishes.
    os.symlink(os.path.join(REPO, 'README.md'), os.path.join(root, 'README.md'))
    with open(os.path.join(root, 'scripts', 'fuzz_edk2.py'), 'w',
              encoding='utf-8') as handle:
        handle.write(STUB)
    tree = os.path.join(root, 'eval_source', 'edk2')
    os.makedirs(tree)
    quiet = dict(capture_output=True, check=False)
    subprocess.run(['git', 'init', '-q', '-b', 'master', tree], **quiet)
    open(os.path.join(tree, 'x'), 'w').close()
    subprocess.run(['git', '-C', tree, 'add', 'x'], **quiet)
    subprocess.run(['git', '-C', tree, '-c', 'user.email=c@example.invalid',
                    '-c', 'user.name=c', '-c', 'commit.gpgsign=false',
                    'commit', '-qm', 'base'], **quiet)
    sys.path.insert(0, HERE)
    import sweep_verdict
    for ref in sweep_verdict.claimed_versions(os.path.join(REPO, 'README.md')):
        subprocess.run(['git', '-C', tree, 'tag', ref], **quiet)
    return root


def step_bodies():
    """{step name: its `run:` script} for the cross-version job."""
    try:
        import yaml
    except ImportError:
        return None
    with open(CROSS, encoding='utf-8') as handle:
        doc = yaml.safe_load(handle)
    out = {}
    for step in doc['jobs']['cross-version']['steps']:
        name = step.get('name') or step.get('id')
        if 'run' in step:
            out[name] = (step['run'], step.get('env') or {})
    return out


def shell_plumbing():
    """cross-version.yml's own steps, run with a stub driver."""
    print('and the workflow\'s shell picks the refs it says it picks')
    bodies = step_bodies()
    if bodies is None:
        print('  [skip] PyYAML is not installed, so the steps cannot be extracted')
        return 0
    need = ['Qualify each version', 'Did every version qualify',
            'The qualifying stages ran on every version']
    for name in need:
        if name not in bodies:
            print(f'  [FAIL] cross-version.yml has no {name!r} step with a `run:`')
            return 1
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = sandbox(tmp)

        def resolve(text, out, temp):
            """The few ${{ }} expressions these steps use, and nothing else."""
            def one(hit):
                expr = hit.group(1).strip()
                if expr.startswith('steps.where.outputs.out'):
                    return out
                if expr.startswith('runner.temp'):
                    return temp
                if expr.startswith('github.event.inputs.'):
                    return ''                    # a push carries no inputs
                raise AssertionError(f'unsupported expression: {expr}')
            return re.sub(r'\$\{\{(.*?)\}\}', one, text)

        def step(name, out, temp, extra):
            body, env = bodies[name]
            full = dict(os.environ)
            for key, value in env.items():
                full[key] = resolve(str(value), out, temp)
            full.update(extra)
            return subprocess.run(['bash', '-e', '-c', resolve(body, out, temp)],
                                  cwd=root, capture_output=True, text=True, env=full)

        # (name, stub plan, expected verdict exit, expected stage exit, why)
        for name, plan, want_v, want_s, why in (
                ('all-green', '', 0, 0, 'every picked release and master clean'),
                ('master-broken', 'master=1', 0, 0,
                 'upstream master is early warning, not a red gate'),
                ('release-degraded', 'edk2-stable202305=2', 0, 0,
                 'exit 2 is degraded and its WARN stage still ran'),
        ):
            out = os.path.join(tmp, 'out', name)
            temp = os.path.join(tmp, 'temp', name)
            os.makedirs(out)
            os.makedirs(temp)
            ran = step('Qualify each version', out, temp, {'STUB_RC': plan})
            got_v = step('Did every version qualify', out, temp, {}).returncode
            got_s = step('The qualifying stages ran on every version', out, temp,
                         {}).returncode
            ledger = os.path.join(temp, 'cross.rc')
            refs = [l.split()[0] for l in open(ledger, encoding='utf-8')
                    if l.split()] if os.path.isfile(ledger) else []
            # Five refs: four releases and master. Each must be one the synthetic tree
            # can resolve -- the concatenation bug produced a ref that was neither a
            # release nor resolvable, and warned instead of failing.
            resolved = [r for r in refs if subprocess.run(
                ['git', '-C', os.path.join(root, 'eval_source', 'edk2'), 'rev-parse',
                 '--verify', '--quiet', f'{r}^{{commit}}'],
                capture_output=True).returncode == 0]
            trouble = []
            if len(refs) != 5:
                trouble.append(f'{len(refs)} ref(s) in the ledger, want 5 '
                               f'(4 releases + master): {refs}')
            if refs[-1:] != ['master']:
                trouble.append(f'master is not the last ref: {refs}')
            if resolved != refs:
                trouble.append(f'ref(s) the tree cannot resolve: '
                               f'{sorted(set(refs) - set(resolved))}')
            if len(set(refs)) != len(refs):
                trouble.append(f'a ref was qualified twice: {refs}')
            # One results directory per ref, at the slug the verdict step reads back.
            made = sorted(d for d in os.listdir(out) if d.startswith('fuzz-'))
            want_dirs = sorted('fuzz-' + re.sub(r'[^A-Za-z0-9._-]', '-', r)
                               for r in refs)
            if made != want_dirs:
                trouble.append(f'results dirs {made} do not match the ledger '
                               f'{want_dirs}')
            if (got_v, got_s) != (want_v, want_s):
                trouble.append(f'verdict exited {got_v} (want {want_v}), stage step '
                               f'{got_s} (want {want_s})')
            if trouble:
                print(f'  [FAIL] {name}: ' + '; '.join(trouble))
                for line in (ran.stdout + ran.stderr).strip().split('\n')[-6:]:
                    print(f'         {line}')
                bad = 1
            else:
                print(f'  [ok  ] {name:<18} {len(refs)} refs, verdict {got_v}, '
                      f'stage {got_s} -- {why}')
        # A release that fails has to be red, or none of the above means anything.
        out = os.path.join(tmp, 'out', 'release-broken')
        temp = os.path.join(tmp, 'temp', 'release-broken')
        os.makedirs(out)
        os.makedirs(temp)
        newest = sorted(sweep_claimed(), key=lambda r: r)[-1]
        step('Qualify each version', out, temp, {'STUB_RC': f'{newest}=1'})
        got_v = step('Did every version qualify', out, temp, {}).returncode
        got_s = step('The qualifying stages ran on every version', out, temp,
                     {}).returncode
        if (got_v, got_s) == (1, 1):
            print(f'  [ok  ] release-broken     {newest} failed: red in both steps')
        else:
            print(f'  [FAIL] release-broken: verdict {got_v}, stage {got_s}, want 1 and 1')
            bad = 1
    return bad


def action_pins():
    """Every `uses:` that names this action must name it in a form GitHub will resolve.

    A SHORTENED commit SHA is not one. `uses: BreakingBoot/FuzzUEr@d02e72e2` fails with
    "the provided ref `d02e72e2` is the shortened version of a commit SHA, which is not
    supported", and it fails FOUR SECONDS into the job -- after the queue wait, after the
    checkout -- so it reads as the campaign having died rather than as a bad pin. Measured
    2026-11-12 on BreakingBoot/eval1_edk2, which had been pinned by a full SHA until the
    pin was bumped by hand.

    It matters most in examples/: that file is what a consumer copies, and a short SHA
    there breaks every repository that copies it, in a way nothing in this repository runs.
    """
    print('and every action pin is in a form GitHub resolves')
    bad = 0
    pin = re.compile(r'uses:\s*([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)@(\S+)')
    seen = 0
    for path in sorted(glob.glob(os.path.join(FLOW, '*.yml'))
                       + glob.glob(os.path.join(REPO, 'examples', '*.yml'))
                       + glob.glob(os.path.join(REPO, 'examples', '*.yaml'))):
        for number, line in enumerate(
                open(path, encoding='utf-8', errors='replace'), start=1):
            hit = pin.search(line)
            if not hit:
                continue
            repo, ref = hit.group(1), hit.group(2).strip().strip('"\'')
            seen += 1
            # A full SHA, or a name. The failure mode is the thing in between: hex, and
            # short enough to look like a convenient abbreviation.
            hexish = all(c in '0123456789abcdefABCDEF' for c in ref)
            if hexish and len(ref) != 40 and len(ref) >= 6:
                print(f'  [FAIL] {os.path.basename(path)}:{number} {repo}@{ref} '
                      f'is a shortened SHA ({len(ref)} chars) -- GitHub refuses it, '
                      f'four seconds into the job')
                bad = 1
    if not seen:
        print('  [FAIL] no `uses: owner/repo@ref` pin was found to check at all')
        bad = 1
    else:
        print(f'  [ok  ] {seen} pin(s), none a shortened SHA')
    return bad


def sweep_claimed():
    sys.path.insert(0, HERE)
    import sweep_verdict
    return sweep_verdict.claimed_versions(os.path.join(REPO, 'README.md'))


def failure_names_the_case():
    """A ref that fails `detects` must say WHICH benchmark class regressed.

    The first cross-version sweep failed two of five refs with this, verbatim:

        benchmark 11 of 12 scorable classes detected --  regressed

    There is nothing between the dash and the word. The stage collected the failing
    cases by filtering for MISS and WRONG, which are two of the EIGHT verdicts
    bench_cases.py scores as a non-detection, and the case that actually failed was
    `control FAIL` -- the positive control reporting on correct firmware, which is the
    single most important row on the board. The run said a class regressed and named
    none, on a gate whose whole output is that one line.

    Reading the verdict set from bench_cases rather than copying it is the fix for the
    class of bug, not just this instance: a copy is what goes stale the next time a
    verdict is added, and the symptom is again a silent omission rather than an error.
    """
    bad = 0
    sys.path.insert(0, HERE)
    import bench_cases
    import fuzz_edk2
    name = fuzz_edk2.regressed_cases

    # Both shapes the log writes a verdict in: the running list, where the verdict ends
    # the line, and the summary table, where evidence follows it. The real log carries
    # every case in BOTH, so a case must be named once.
    log = ('Scoring 3 case(s), one boot each, 2 at a time\n'
           '  heap-buffer-overflow     PASS\n'
           '  control                  FAIL\n'
           '  smm-control              MISS\n'
           '\n'
           'CASE                     VERDICT  EVIDENCE\n'
           '-----------------------------------------\n'
           'control                  FAIL     reported on correct code\n'
           'heap-buffer-overflow     PASS     bug_descr=heap-buffer-overflow\n'
           'smm-control              MISS     the SMI did not arrive\n'
           '-----------------------------------------\n'
           '1 of 3 scorable classes detected\n')
    got = name(log)
    if got != ['control FAIL', 'smm-control MISS']:
        print(f'  [FAIL] a failing detects stage names {got!r}')
        print('         expected the FAIL and the MISS, once each, with their verdicts')
        bad = 1
    else:
        print('  [ok  ] a failing stage names every non-detecting case, with its verdict')

    if any(e.startswith('heap-buffer-overflow') for e in got):
        print('  [FAIL] a PASS was reported as a regression')
        bad = 1

    # The property that keeps it true: EVERY non-PASS verdict bench_cases scores is
    # recognised here. A literal list in fuzz_edk2 would drop the next one added.
    missing = []
    for verdict in bench_cases.SCORED:
        if verdict == 'PASS':
            continue
        probe = f'thecase                  {verdict}     some evidence\n'
        if name(probe) != [f'thecase {verdict}']:
            missing.append(verdict)
    if missing:
        print(f'  [FAIL] these scored verdicts are not recognised as a regression: '
              f'{", ".join(missing)}')
        print('         bench_cases.py scores them as a non-detection, so a stage that '
              'fails on one of them names nothing')
        bad = 1
    else:
        print(f'  [ok  ] all {len(bench_cases.SCORED) - 1} non-detecting verdicts are '
              f'named, read from bench_cases rather than copied')

    for exempt in bench_cases.EXEMPT:
        if name(f'thecase                  {exempt}     not scorable\n'):
            print(f'  [FAIL] {exempt} is an exemption and was reported as a regression')
            bad = 1

    source = inspect.getsource(fuzz_edk2.regressed_cases)
    if 'bench_cases.SCORED' not in source:
        print('  [FAIL] regressed_cases does not read bench_cases.SCORED')
        print('         a second copy of the verdict set is the bug this check exists for')
        bad = 1
    return bad


def main():
    bad = (stable_gate() | cross_gate() | paired_verdict() | shell_plumbing()
           | triggers() | action_pins() | failure_names_the_case())
    print('  end-to-end gates: ' + ('FAILED' if bad else 'OK'))
    return bad


if __name__ == '__main__':
    sys.exit(main())
