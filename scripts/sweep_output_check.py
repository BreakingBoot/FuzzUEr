#!/usr/bin/env python3
"""Does the sweep's output outlive the job, and can its three readers still find it?

The sweep destroyed its own results. scripts/fuzz_edk2.py defaulted `--out` to
<repo>/results/fuzz-<slug>, fuzz-edk2.yml passed no --out, .gitignore ignores
`results/*`, and actions/checkout@v4 runs `git clean -ffdx` -- where -x removes IGNORED
files too. So the next job to land on the self-hosted runner deleted the last sweep's
output. Measured 2026-11-11: run 42999334016, the only SMI sweep that has ever
completed, finished at 14:47 UTC and a Checks job that started at 14:47:42 wiped
results/fuzz-master. The 90-day artifact was the only copy left of it.

Nothing checked the output path, and a check that only grepped the YAML for `$HOME`
would not be one: the fix has to keep THREE readers working, each of which finds the
results by a different route --

  * scripts/sweep_verdict.py --results results, which opens results/fuzz-<slug>/run.json
    by name, per ref in the ledger
  * the Summarise step, which globs results/fuzz-*/run.json
  * actions/upload-artifact, whose eleven path patterns are all results/fuzz-*/...

-- so this check RUNS the sweep step. It slices the step body out of the workflow, runs
it under the shell GitHub uses with a stub driver standing in for fuzz_edk2.py, in a
temporary directory standing in for the workspace, with HOME and GITHUB_RUN_ID of its
own. Then it asserts where the bytes landed, and runs the real verdict, the real
Summarise body and the real artifact patterns against what the step left behind.

That is what makes the assertions evidence rather than string matching: a mutation that
moves the output out of the workspace but forgets the readers fails here, and so does
the original defect -- a stub that is given no --out writes where the driver used to,
and the readers are all perfectly happy with that.

Run: python3 scripts/sweep_output_check.py
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
WORKFLOW = os.path.join(REPO, '.github', 'workflows', 'fuzz-edk2.yml')

# The run whose results were wiped. Used as the simulated run id so a failure here reads
# as the failure it stands for.
RUN_ID = '42999334016'
SUNDAY, WEDNESDAY = '0 3 * * 0', '0 3 * * 3'

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


def die(message):
    """A missing anchor is a failure, never a skip: an extraction that matches nothing is
    how a check goes blind while staying green."""
    print(f'::error::{message}')
    sys.exit(1)


# ---------------------------------------------------------------- the workflow it checks

def workflow():
    import yaml
    with open(WORKFLOW, encoding='utf-8') as handle:
        return yaml.safe_load(handle)


def steps(wf):
    jobs = wf.get('jobs') or {}
    if len(jobs) != 1:
        die(f'expected one job in {WORKFLOW}, found {sorted(jobs)}')
    found = {}
    for step in next(iter(jobs.values()))['steps']:
        if step.get('id') == 'sweep':
            found['sweep'] = step
        elif step.get('name') == 'Did this sweep pass':
            found['verdict'] = step
        elif step.get('name') == 'Summarise':
            found['summarise'] = step
        elif str(step.get('uses', '')).startswith('actions/upload-artifact'):
            found['upload'] = step
    for name in ('sweep', 'verdict', 'summarise', 'upload'):
        if name not in found:
            die(f'no {name} step in {WORKFLOW}; this check must be re-anchored rather '
                f'than guessing which step took its place')
    if '${{' in found['sweep']['run']:
        die('the sweep step body now interpolates an expression, so running it outside '
            'Actions no longer reproduces what Actions runs; re-anchor this check')
    return found


def upload_patterns(upload):
    with_ = upload.get('with') or {}
    patterns = [p.strip() for p in str(with_.get('path', '')).splitlines() if p.strip()]
    if not patterns:
        die('the upload step lists no paths')
    return patterns


# ------------------------------------------------------------------- the driver's default

def driver_base(home, run_id, actions=True):
    """What `--out` defaults into, asked of the driver rather than restated here."""
    sys.path.insert(0, HERE)
    try:
        import fuzz_edk2
    except Exception as exc:                                  # pragma: no cover
        die(f'cannot import the driver to ask it where results go: {exc}')
    fn = getattr(fuzz_edk2, 'results_base', None)
    if fn is None:
        return None
    saved = {k: os.environ.get(k) for k in ('GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'HOME')}
    try:
        os.environ['GITHUB_ACTIONS'] = 'true' if actions else 'false'
        os.environ['GITHUB_RUN_ID'] = run_id
        os.environ['HOME'] = home
        return os.path.abspath(fn())
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root + os.sep)


# ------------------------------------------------------------------------ the simulation

# Writes one of every file the artifact step names, records the arguments it was given,
# and -- when it is given no --out -- writes where the driver used to default to. That
# fallback is deliberate: it is the shape of the original defect, so dropping --out from
# the workflow has to fail this check rather than look like a pass.
STUB = r'''import json, os, re, sys
argv = sys.argv[1:]


def opt(name):
    return argv[argv.index(name) + 1] if name in argv else ''


ref = opt('--ref')
slug = re.sub(r'[^A-Za-z0-9._-]', '-', ref)
out = opt('--out') or os.path.join(os.getcwd(), 'results', 'fuzz-' + slug)
out = os.path.abspath(out)
os.makedirs(out, exist_ok=True)
with open(os.environ['STUB_ARGV_LOG'], 'a') as handle:
    handle.write(json.dumps({'ref': ref, 'out': out, 'argv': argv,
                             'cwd': os.getcwd()}) + '\n')
json.dump({'ref': ref, 'stages': [
    {'name': 'port', 'ok': True, 'detail': '29 clean'},
    {'name': 'build', 'ok': True, 'detail': 'built'},
    {'name': 'fuzz', 'ok': 'warn', 'detail': '239/243 campaign(s) fuzzed'},
    {'name': 'triage', 'ok': True, 'detail': '3 candidate(s)'},
]}, open(os.path.join(out, 'run.json'), 'w'))
for name in ('bugs.md', 'bugs.json', 'presence.csv', 'bench_cases.log', 'pipeline.log'):
    open(os.path.join(out, name), 'w').write('{}' if name.endswith('.json') else 'x\n')
camp = os.path.join(out, 'campaigns', 'DiscoveredSmi')
os.makedirs(camp, exist_ok=True)
for name in ('crashes.csv', 'log.json', 'run.log', 'fuzz.txt'):
    open(os.path.join(camp, name), 'w').write('{}' if name.endswith('.json') else 'x\n')
os.makedirs(os.path.join(out, 'reproducers'), exist_ok=True)
open(os.path.join(out, 'reproducers', 'input-0001.bin'), 'wb').write(b'\x00')
print('stub driver: wrote', out)
sys.exit(int(os.environ.get('STUB_RC', '0')))
'''

# `git -C eval_source/edk2 tag -l ... --sort=-v:refname`, already sorted. A dotted tag is
# in the list on purpose: the slug rule has to survive one, and the verdict looks the
# directory up by that name.
STUB_GIT = '''#!/bin/sh
for a in "$@"; do
  if [ "$a" = tag ]; then
    printf '%s\\n' edk2-stable202608 edk2-stable202605 edk2-stable202508.01 \\
                   edk2-stable202602
    exit 0
  fi
done
exit 0
'''


class Sim:
    def __init__(self, work, ws, home, ledger, calls, proc):
        self.work, self.ws, self.home = work, ws, home
        self.ledger, self.calls, self.proc = ledger, calls, proc

    def bash(self, script, env=None):
        """Run a step body the way Actions runs a `run:` step, in the workspace."""
        path = os.path.join(self.work, 'consumer.sh')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(script)
        return subprocess.run(['bash', '--noprofile', '--norc', '-e', path],
                              cwd=self.ws, env=dict(self.env, **(env or {})),
                              capture_output=True, text=True, timeout=600)


def simulate(body, extra_env):
    work = tempfile.mkdtemp(prefix='sweep-output-')
    ws = os.path.join(work, 'workspace')          # stands in for the checkout
    home = os.path.join(work, 'home')             # stands in for the runner's HOME
    binary = os.path.join(work, 'bin')
    for path in (os.path.join(ws, 'scripts'), os.path.join(ws, 'results'), home, binary):
        os.makedirs(path, exist_ok=True)
    # The two hand-written write-ups that live among the campaign directories and ARE
    # tracked -- which is why results/ cannot simply become a symlink.
    with open(os.path.join(ws, 'results', 'findings.md'), 'w') as handle:
        handle.write('# tracked\n')
    with open(os.path.join(ws, 'scripts', 'fuzz_edk2.py'), 'w') as handle:
        handle.write(STUB)
    # The real reader, invoked the way the workflow invokes it.
    shutil.copy(os.path.join(HERE, 'sweep_verdict.py'),
                os.path.join(ws, 'scripts', 'sweep_verdict.py'))
    with open(os.path.join(binary, 'git'), 'w') as handle:
        handle.write(STUB_GIT)
    os.chmod(os.path.join(binary, 'git'), 0o755)

    ledger = os.path.join(work, 'sweep.rc')
    argv_log = os.path.join(work, 'argv.jsonl')
    open(argv_log, 'w').close()
    script = os.path.join(work, 'step.sh')
    with open(script, 'w', encoding='utf-8') as handle:
        handle.write(body)

    env = dict(os.environ)
    env.pop('GITHUB_STEP_SUMMARY', None)
    env.update(
        HOME=home, PATH=binary + os.pathsep + env['PATH'],
        LEDGER=ledger, STUB_ARGV_LOG=argv_log, STUB_RC='0',
        GITHUB_ACTIONS='true', GITHUB_RUN_ID=RUN_ID, GITHUB_WORKSPACE=ws,
        GITHUB_EVENT_NAME='schedule', EVENT_SCHEDULE='',
        IN_REFS='', IN_BUDGET='', IN_JOBS='4', IN_BOOT_TIMEOUT='',
        IN_QUALIFY='true', IN_SMI='', IN_HARNESS_TIMING='application',
        FIRNESS_QEMU_ICOUNT='shift=auto,sleep=off', FIRNESS_CONTAINER_PREFIX='ci',
    )
    env.update(extra_env)
    proc = subprocess.run(['bash', '--noprofile', '--norc', '-e', script],
                          cwd=ws, env=env, capture_output=True, text=True, timeout=900)
    with open(argv_log, encoding='utf-8') as handle:
        calls = [json.loads(line) for line in handle if line.strip()]
    sim = Sim(work, ws, home, ledger, calls, proc)
    sim.env = env
    return sim


def tail(proc, lines=8):
    for line in (proc.stdout + proc.stderr).strip().splitlines()[-lines:]:
        print(f'         | {line[:120]}')


# ------------------------------------------------------------------------- the assertions

def where_it_landed(sim, label, keep):
    """The output is outside the workspace, per ref, and the workspace holds links."""
    check(f'{label}: the sweep step ran to the end', sim.proc.returncode == 0,
          f'exit {sim.proc.returncode}')
    if sim.proc.returncode != 0:
        tail(sim.proc)

    check(f'{label}: every ref got its own --out',
          bool(sim.calls) and all(c['out'] for c in sim.calls)
          and all('--out' in c['argv'] for c in sim.calls),
          'a ref invoked without --out falls back to the driver default, and that '
          'default inside the checkout is the whole defect')
    outs = [c['out'] for c in sim.calls]
    check(f'{label}: the refs do not share one output directory',
          len(set(outs)) == len(outs),
          f'{len(set(outs))} directories for {len(outs)} refs: one ref overwrites '
          f'another and the sweep reports the last one twice')
    check(f'{label}: no output lands in the workspace',
          all(not inside(o, sim.ws) for o in outs),
          '\n         '.join(o for o in outs if inside(o, sim.ws)) +
          '\n         actions/checkout git-cleans the workspace, ignored files included')
    check(f'{label}: the run id keys the directory',
          all(RUN_ID in os.path.relpath(o, sim.home).split(os.sep) for o in outs
              if not inside(o, sim.ws)) and outs != [],
          f'{outs[:2]} is not keyed by {RUN_ID}: the next sweep on this runner writes '
          f'fuzz-master over this one')
    check(f'{label}: the step keeps the results where the DRIVER defaults to',
          keep is not None and all(os.path.dirname(o) == keep for o in outs),
          f'the step writes {sorted({os.path.dirname(o) for o in outs})} and the driver '
          f'defaults into {keep}: two places that have to be edited together will not be')

    # The workspace copy is a LINK, not a copy: a copy is what half-works.
    links, strays = [], []
    for entry in sorted(os.listdir(os.path.join(sim.ws, 'results'))):
        path = os.path.join(sim.ws, 'results', entry)
        if os.path.islink(path):
            links.append(entry)
        elif not entry.endswith('.md'):
            strays.append(entry)
    check(f'{label}: the workspace holds one link per ref',
          len(links) == len(sim.calls) and len(links) > 0,
          f'{links} for {[c["ref"] for c in sim.calls]}')
    check(f'{label}: and holds no copy of the results',
          not strays,
          f'{strays} are real entries under the workspace results/, so the sweep keeps '
          f'the only copy of something where git clean will find it')
    for call in sim.calls:
        slug = re.sub(r'[^A-Za-z0-9._-]', '-', call['ref'])
        link = os.path.join(sim.ws, 'results', f'fuzz-{slug}')
        check(f'{label}: results/fuzz-{slug} points at {call["ref"]}\'s output',
              os.path.islink(link)
              and os.path.realpath(link) == os.path.realpath(call['out']),
              f'{link} -> {os.path.realpath(link) if os.path.exists(link) else "(nothing)"}'
              f', wanted {call["out"]}')


def readers(sim, verdict_step, summarise_step, patterns, label):
    """Every route to the results still arrives, through the link."""
    keep_roots = {os.path.realpath(c['out']) for c in sim.calls}

    # 1. the verdict: opens results/fuzz-<slug>/run.json by name, per ledger ref.
    command = verdict_step['run'].strip()
    swapped, n = re.subn(r"--ledger\s+'[^']*'",
                         '--ledger ' + shlex.quote(sim.ledger), command)
    if n != 1:
        die('the verdict step no longer passes a quoted --ledger; re-anchor this check')
    proc = sim.bash(swapped)
    check(f'{label}: sweep_verdict.py reads every ref\'s run.json',
          proc.returncode == 0 and 'no run.json' not in proc.stdout
          and all(c['ref'] in proc.stdout for c in sim.calls),
          'the verdict prints "(no run.json -- this ref died before the first stage '
          'wrote one)" for a ref whose results it cannot find, and a sweep that ran '
          'fine then reads as one that died')
    if proc.returncode != 0 or 'no run.json' in proc.stdout:
        tail(proc)
    check(f'{label}: and finds the stages inside it',
          proc.stdout.count('[WARN] fuzz') == len(sim.calls),
          f'{proc.stdout.count("[WARN] fuzz")} stage boards for {len(sim.calls)} refs')

    # 2. Summarise: the glob in the step's own heredoc, run as the step runs it.
    summary = os.path.join(sim.work, 'step_summary.md')
    open(summary, 'w').close()
    proc = sim.bash(summarise_step['run'], env={'GITHUB_STEP_SUMMARY': summary})
    with open(summary, encoding='utf-8') as handle:
        table = handle.read()
    check(f'{label}: the Summarise glob resolves to every ref',
          proc.returncode == 0 and 'No runs produced a run.json' not in table
          and all(f'| `{c["ref"]}` |' in table for c in sim.calls),
          f'the step wrote:\n         ' + table.strip().replace('\n', '\n         '))

    # 3. the artifact: eleven patterns, globbed the way the action globs them.
    missing, outside = [], []
    # Globbed from the workspace, as the action does, and required to resolve to a real
    # FILE: that is the step the symlink has to survive, and `os.path.isfile` follows it
    # for the same reason @actions/glob's followSymbolicLinks does.
    for pattern in patterns:
        proc = subprocess.run(
            ['python3', '-c',
             'import glob, os, sys\n'
             'print("\\n".join(os.path.realpath(h)\n'
             '                 for h in glob.glob(sys.argv[1], recursive=True)\n'
             '                 if os.path.isfile(h)))', pattern],
            cwd=sim.ws, capture_output=True, text=True, timeout=120)
        hits = [h for h in proc.stdout.splitlines() if h]
        if not hits:
            missing.append(pattern)
        elif not any(any(inside(h, root) for root in keep_roots) for h in hits):
            outside.append(pattern)
    check(f'{label}: all {len(patterns)} artifact patterns still match a file',
          not missing,
          'nothing matches ' + ', '.join(missing) + '. upload-artifact is configured '
          'if-no-files-found: warn, so an unmatched pattern is a GREEN run with an '
          'empty artifact -- exactly the outcome that left run 42999334016 with '
          'nothing at all')
    check(f'{label}: and every one of them reaches the kept copy',
          not outside,
          ', '.join(outside) + ' matched files that are not under the kept output, so '
          'the artifact would be built from something the next job deletes')


def slug_rule(body):
    """The shell slug names the directory the readers look up. Prove it is THEIR rule."""
    line = re.search(r'^\s*SLUG=\$\(.*\)\s*$', body, re.M)
    if not line:
        die('no SLUG=$(...) assignment in the sweep step; the directory name is a '
            'contract with sweep_verdict.py and this check must see how it is made')
    sys.path.insert(0, HERE)
    import sweep_verdict
    script = f'ref="$1"\n{line.group(0).strip()}\nprintf %s "$SLUG"\n'
    path = os.path.join(tempfile.mkdtemp(prefix='sweep-slug-'), 'slug.sh')
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(script)
    bad = []
    for ref in ('edk2-stable202608', 'edk2-stable202508.01', 'master',
                'a2d6ba512a0587e1798093dc73775451a1aa7c55', 'my/platform-branch',
                'refs/heads/master', 'edk2-stable202608-rc1'):
        got = subprocess.run(['bash', '--noprofile', '--norc', path, ref],
                             capture_output=True, text=True, timeout=60).stdout
        want = sweep_verdict.slug(ref)
        if got != want:
            bad.append(f'{ref}: the step says fuzz-{got}, the reader opens fuzz-{want}')
    check("the step's slug is the one the readers look results up by", not bad,
          '\n         '.join(bad))


def unchanged(wf, sim_wed):
    """What this sweep fuzzes is not this change's business -- so pin it."""
    triggers = wf.get('on', wf.get(True)) or {}
    crons = [c.get('cron') for c in (triggers.get('schedule') or [])]
    check('both crons are still there', crons == [SUNDAY, WEDNESDAY], f'{crons}')
    calls = sim_wed.calls
    check('the Wednesday pass is still master only',
          [c['ref'] for c in calls] == ['master'], f'{[c["ref"] for c in calls]}')
    argv = calls[0]['argv'] if calls else []
    for flag, value in (('--targets', 'DiscoveredSmi'), ('--harness-timing', 'dxe'),
                        ('--budget', '600')):
        check(f'the Wednesday pass still passes {flag} {value}',
              flag in argv and argv[argv.index(flag) + 1] == value,
              f'argv was {argv}')
    check('the Wednesday pass still passes --smi', '--smi' in argv, f'argv was {argv}')


def main():
    wf = workflow()
    step = steps(wf)
    body = step['sweep']['run']
    patterns = upload_patterns(step['upload'])

    print('the slug the readers look up')
    slug_rule(body)

    print('\nwhere the driver sends results when nobody says')
    local = driver_base(os.path.expanduser('~'), RUN_ID, actions=False)
    check('the driver still has a results_base() to ask', local is not None,
          'scripts/fuzz_edk2.py must keep the default in one named place, or this '
          'check cannot tell where an --out-less run would write')
    check('from a shell it is still the repository',
          local == os.path.join(REPO, 'results'),
          f'{local}: a local run keeps its results beside the write-ups and the older '
          f'campaigns, and nothing cleans them there')

    print('\nthe Sunday sweep: four refs, the schedule\'s own empty inputs')
    sim = simulate(body, {'EVENT_SCHEDULE': SUNDAY})
    ci_base = driver_base(sim.home, RUN_ID)
    check('in CI the driver default is outside the workspace',
          ci_base is not None and not inside(ci_base, REPO),
          f'{ci_base} is inside {REPO}, which IS the workspace in CI and which '
          f'actions/checkout cleans with git clean -ffdx')
    check('and is keyed by the run id',
          ci_base is not None and RUN_ID in ci_base.split(os.sep),
          f'{ci_base}')
    check('the schedule still resolves four refs',
          len(sim.calls) == 4 and sim.calls[-1]['ref'] == 'master',
          f'{[c["ref"] for c in sim.calls]}')
    where_it_landed(sim, 'sunday', ci_base)
    readers(sim, step['verdict'], step['summarise'], patterns, 'sunday')

    print('\nthe Wednesday SMI pass: the sweep that was wiped')
    sim_wed = simulate(body, {'EVENT_SCHEDULE': WEDNESDAY})
    where_it_landed(sim_wed, 'wednesday', driver_base(sim_wed.home, RUN_ID))
    readers(sim_wed, step['verdict'], step['summarise'], patterns, 'wednesday')

    print('\nwhat this change was not allowed to touch')
    unchanged(wf, sim_wed)

    for one in (sim, sim_wed):
        shutil.rmtree(one.work, ignore_errors=True)

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
