#!/usr/bin/env python3
"""Assert the issue cleanup removes the label before it closes, and guards what it closes.

The ordering is the whole point and it is invisible from the outside. already_filed()
queries `state=all` BY DESIGN, so a closed issue still holds its site key and the site is
not refiled every week. Closing first and unlabelling after would leave the key held by an
issue nobody will look at again; unlabelling first frees it. Nothing about the code reads
as order-dependent, so it is asserted here against a recorded call sequence.

The guards matter as much: this tool closes things. It must refuse upstream edk2 like every
other entry point, and it must not close an issue it did not file.

The slate wipe -- --all-labelled, which enumerates the label instead of being handed
numbers -- is asserted against a STATEFUL stand-in for the REST endpoints rather than a
call recorder, because every one of its failure modes is a state or a count rather than a
call: a listing that silently stops at GitHub's 30-per-page default, an enumeration that
asks for open issues only and so reports a clean slate over a blocked one, a second run
that wipes the same slate again because the first one never took the labels off, a listing
that failed being reported as an empty one. None of those shows up in a sequence of calls;
all of them show up in what the stand-in holds afterwards.

Run: python3 scripts/close_issues_check.py
"""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
from urllib.parse import parse_qs, urlparse

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
    spec.loader.exec_module(module)
    return module


class Recorder:
    """Stands in for file_issues, recording every call instead of making one."""

    LABEL_FINDING = 'fuzzuer-finding'

    def __init__(self, issues):
        self.issues = issues
        self.calls = []

    def refuse_upstream(self, slug, what):
        self.calls.append(('refuse_upstream', slug, what))

    def why(self, payload):
        return 'recorded'

    def call(self, token, method, path, body=None, dry=False):
        self.calls.append((method, path, body))
        if method == 'GET':
            number = int(path.rsplit('/', 1)[-1])
            if number not in self.issues:
                return 404, {'message': 'Not Found'}
            return 200, self.issues[number]
        if method == 'DELETE':
            return 204, None
        return 200, {}


def run(tool, recorder, argv):
    saved_argv, saved_loader = sys.argv, tool.load_file_issues
    sys.argv = ['close_issues.py'] + argv
    tool.load_file_issues = lambda: recorder
    try:
        return tool.main()
    finally:
        sys.argv, tool.load_file_issues = saved_argv, saved_loader


def run_capture(tool, recorder, argv):
    """run(), with the tool's own output captured so the result line can be parsed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = run(tool, recorder, argv)
    return code, buf.getvalue()


def result_of(text):
    """The machine-readable last line, as a dict. {} when there is none."""
    for line in reversed(text.splitlines()):
        if line.startswith('result:'):
            return dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)
    return {}


class Github:
    """A stateful stand-in for the REST endpoints, not a call recorder.

    It paginates the way GitHub documents -- 30 per page when per_page is absent, capped
    at 100 -- and it defaults `state` to open, because those two defaults are what a
    slate wipe gets silently truncated by. A DELETE really removes the label from the
    stored issue and a PATCH really changes its state, so a second run sees what the
    first one left behind, which is the only way idempotency can be asserted at all.

    It mirrors call()'s dry-run behaviour exactly: a GET is still performed, everything
    else returns (0, {}) without touching anything. A stand-in that honoured writes in
    dry-run mode would make the dry-run assertions pass on a tool that changed the world.
    """

    LABEL_FINDING = 'fuzzuer-finding'
    DEFAULT_PER_PAGE = 30
    MAX_PER_PAGE = 100

    def __init__(self, issues, extra=None, ghosts=(), fail_list=False):
        self.issues = {n: {**i, 'labels': [dict(l) for l in (i.get('labels') or [])]}
                       for n, i in issues.items()}
        self.extra = list(extra or [])       # rows the list endpoint returns verbatim
        self.ghosts = set(ghosts)            # returned by a labels= query regardless
        self.fail_list = fail_list
        self.calls = []
        self.lists = []

    # -- the bits close_issues.py reaches for on the file_issues module -----------------
    def refuse_upstream(self, slug, what):
        self.calls.append(('refuse_upstream', slug, what))

    def why(self, payload):
        if isinstance(payload, dict) and payload.get('message'):
            return payload['message']
        return 'recorded'

    def call(self, token, method, path, body=None, dry=False):
        self.calls.append((method, path, body))
        if dry and method != 'GET':
            return 0, {}
        if method == 'GET':
            return self._list(path) if '?' in path else self._one(path)
        if method == 'DELETE':
            return self._unlabel(path)
        if method == 'PATCH':
            return self._patch(path, body)
        return 200, {}

    # -- endpoints ---------------------------------------------------------------------
    def _row(self, number):
        issue = self.issues[number]
        return {**issue, 'number': number}

    def _list(self, path):
        query = parse_qs(urlparse(path).query)
        self.lists.append(query)
        if self.fail_list:
            return 404, {'message': 'Not Found'}
        per = min(max(int(query.get('per_page', [self.DEFAULT_PER_PAGE])[0]), 1),
                  self.MAX_PER_PAGE)
        page = int(query.get('page', ['1'])[0])
        want = query.get('labels', [''])[0]
        state = query.get('state', ['open'])[0]
        rows = []
        for number in sorted(self.issues):
            row = self._row(number)
            if state != 'all' and row.get('state', 'open') != state:
                continue
            if want and not any(l.get('name') == want for l in row['labels']):
                # Measured on a real repository: once the label itself has been deleted,
                # ?labels=<name> keeps answering with the issues that used to carry it,
                # each reporting labels: [].
                if number not in self.ghosts:
                    continue
            rows.append(row)
        rows.extend(self.extra)
        start = (page - 1) * per
        return 200, rows[start:start + per]

    def _one(self, path):
        number = int(path.rsplit('/', 1)[-1])
        if number not in self.issues:
            return 404, {'message': 'Not Found'}
        return 200, self._row(number)

    def _unlabel(self, path):
        parts = path.strip('/').split('/')
        number, name = int(parts[parts.index('issues') + 1]), parts[-1]
        issue = self.issues.get(number)
        if issue is None:
            return 404, {'message': 'Not Found'}
        before = len(issue['labels'])
        issue['labels'] = [l for l in issue['labels'] if l.get('name') != name]
        if len(issue['labels']) == before:
            return 404, {'message': 'Label does not exist'}
        return 204, None

    def _patch(self, path, body):
        number = int(path.rsplit('/', 1)[-1])
        if number not in self.issues:
            return 404, {'message': 'Not Found'}
        self.issues[number].update(body or {})
        return 200, self._row(number)

    # -- what the assertions read ------------------------------------------------------
    def touched(self, method):
        """The issue numbers a given method was sent to."""
        out = []
        for call in self.calls:
            if call[0] != method or '/issues/' not in str(call[1]):
                continue
            tail = str(call[1]).split('/issues/', 1)[1].split('/')[0]
            if tail.isdigit():
                out.append(int(tail))
        return out

    def still_labelled(self):
        return sorted(n for n, i in self.issues.items()
                      if any(l.get('name') == self.LABEL_FINDING for l in i['labels']))

    def still_open(self):
        return sorted(n for n, i in self.issues.items()
                      if i.get('state', 'open') != 'closed')


def finding(number, state='open', label='fuzzuer-finding'):
    return {'title': f'a finding at site {number}', 'state': state,
            'labels': [{'name': label}]}


def main():
    tool = load('close_issues')

    print('the number list')
    check('a range is inclusive', tool.parse_issues('37-46')
          == list(range(37, 47)))
    check('singles and ranges mix, in order',
          tool.parse_issues('37-39,51,40') == [37, 38, 39, 51, 40])
    check('a repeat is dropped', tool.parse_issues('5,5,6') == [5, 6])
    for bad in ('46-37', '0', '-3', '1-200', 'x', '1,,,2-'):
        try:
            tool.parse_issues(bad)
            ok = bad == '1,,,2-'      # trailing empty pieces are fine
        except ValueError:
            ok = True
        except Exception:
            ok = False
        check(f'{bad!r} is handled rather than crashing', ok)
    check('the cap is 50', tool.MAX_ISSUES == 50)

    print('\nthe guards')
    recorder = Recorder({})
    code = run(tool, recorder, ['--slug', 'tianocore/edk2', '--issues', '1', '--dry-run'])
    check('upstream is refused before any call is made',
          recorder.calls and recorder.calls[0][0] == 'refuse_upstream',
          f'first call was {recorder.calls[:1]}')

    unlabelled = {7: {'title': 'something else', 'state': 'open', 'labels': [{'name': 'bug'}]}}
    recorder = Recorder(unlabelled)
    os.environ['GITHUB_TOKEN'] = 'x'
    code = run(tool, recorder, ['--slug', 'me/mine', '--issues', '7'])
    methods = [c[0] for c in recorder.calls]
    check('an issue without the finding label is not closed',
          'PATCH' not in methods, f'calls were {methods}')
    recorder = Recorder(unlabelled)
    code = run(tool, recorder, ['--slug', 'me/mine', '--issues', '7', '--force'])
    check('--force closes it anyway',
          'PATCH' in [c[0] for c in recorder.calls])

    print('\nthe ordering')
    filed = {51: {'title': 'a report line as a title', 'state': 'open',
                  'labels': [{'name': 'fuzzuer-finding'}]}}
    recorder = Recorder(filed)
    code = run(tool, recorder, ['--slug', 'me/mine', '--issues', '51', '--unlabel',
                                '--reason', 'the extractor defect is fixed'])
    order = [(c[0], c[1]) for c in recorder.calls if c[0] in ('DELETE', 'PATCH', 'POST')]
    delete_at = next((i for i, c in enumerate(order) if c[0] == 'DELETE'), -1)
    patch_at = next((i for i, c in enumerate(order) if c[0] == 'PATCH'), -1)
    check('the label is removed', delete_at >= 0
          and order[delete_at][1].endswith('/labels/fuzzuer-finding'))
    check('the issue is closed', patch_at >= 0)
    check('and the label comes off BEFORE the close',
          0 <= delete_at < patch_at,
          'a closed issue keeps its site key, so unlabelling afterwards never frees it')
    check('the reason is posted as a comment',
          any(c[0] == 'POST' and c[1].endswith('/comments') for c in recorder.calls))
    check('the comment is posted before the close',
          next(i for i, c in enumerate(order) if c[0] == 'POST') < patch_at,
          'a comment after the close still lands, but the issue reads as closed without '
          'a reason for anyone watching it happen')
    body = next(c[2] for c in recorder.calls if c[0] == 'PATCH')
    check('the close is not_planned, not completed',
          body.get('state') == 'closed' and body.get('state_reason') == 'not_planned',
          f'got {body}')

    print('\nwithout --unlabel the key is deliberately kept')
    recorder = Recorder({52: {'title': 'a real finding', 'state': 'open',
                              'labels': [{'name': 'fuzzuer-finding'}]}})
    code = run(tool, recorder, ['--slug', 'me/mine', '--issues', '52'])
    check('no label call is made', 'DELETE' not in [c[0] for c in recorder.calls],
          'closing a real finding should keep its site key so it is not refiled')
    recorder = Recorder({52: {'title': 'a real finding', 'state': 'closed',
                              'labels': [{'name': 'fuzzuer-finding'}]}})
    code = run(tool, recorder, ['--slug', 'me/mine', '--issues', '52'])
    check('an already-closed issue is left alone',
          'PATCH' not in [c[0] for c in recorder.calls])
    os.environ.pop('GITHUB_TOKEN', None)

    # ---------------------------------------------------------------- the slate wipe ---
    os.environ['GITHUB_TOKEN'] = 'x'
    WIPE = ['--slug', 'me/mine', '--all-labelled', '--unlabel']

    print('\nthe slate wipe enumerates the label')
    # 150, which is past GitHub's 30-per-page default and past one page at any size it
    # will serve. A repository that has been fuzzed weekly for a few months is here.
    gh = Github({n: finding(n) for n in range(1, 151)})
    code, out = run_capture(tool, gh, WIPE + ['--limit', '0'])
    res = result_of(out)
    check('every labelled issue is enumerated, not one page of them',
          res.get('enumerated') == '150',
          f'enumerated={res.get("enumerated")} of 150 -- GitHub serves 30 per page '
          f'unless asked otherwise, and a page loop that trusts a short page has to ask '
          f'for the size it compares against')
    check('and the whole slate is wiped',
          res.get('closed') == '150' and res.get('unlabelled') == '150'
          and gh.still_labelled() == [] and gh.still_open() == [],
          f'{res}; {len(gh.still_labelled())} still labelled, '
          f'{len(gh.still_open())} still open')
    check('150 issues cost at most 3 list requests, not 16',
          len(gh.lists) <= 3,
          f'{len(gh.lists)} list requests -- the page size asked for has to be one '
          f'GitHub honours (it caps at 100), or every wipe pays a request per 10 issues '
          f'and runs into the page ceiling on a busy repository')
    check('the enumeration is ordered, so the log reads in issue order',
          gh.touched('PATCH') == sorted(gh.touched('PATCH')))

    print('\na CLOSED issue still holding the label is the point')
    # The one that blocks a refile. Closing alone leaves it labelled, and already_filed()
    # reads state=all, so an open-only enumeration reports a clean slate over a blocked
    # one.
    gh = Github({1: finding(1), 2: finding(2), 3: finding(3),
                 7: finding(7, 'closed'), 8: finding(8, 'closed'),
                 9: finding(9, 'closed'), 10: finding(10, 'closed')})
    code, out = run_capture(tool, gh, WIPE + ['--reason', 'slate wipe'])
    res = result_of(out)
    check('closed issues are enumerated as well as open ones',
          res.get('enumerated') == '7',
          f'enumerated={res.get("enumerated")} of 7 (3 open, 4 closed) -- GitHub lists '
          f'open issues only unless state=all is asked for')
    check('and every one of them loses the label, which is what frees the site key',
          gh.still_labelled() == [], f'still labelled: {gh.still_labelled()}')
    check('an already-closed issue is not commented on or re-closed',
          sorted(set(gh.touched('POST'))) == [1, 2, 3]
          and sorted(set(gh.touched('PATCH'))) == [1, 2, 3],
          f'commented on {sorted(set(gh.touched("POST")))}, patched '
          f'{sorted(set(gh.touched("PATCH")))} -- re-closing a closed issue adds a '
          f'second identical comment to it on every run')
    check('the counts add up to what was enumerated',
          int(res.get('closed', -1)) + int(res.get('skipped', -1))
          + int(res.get('failed', -1)) == int(res.get('enumerated', -2)),
          f'{res} -- a gate compares the acted-on counts against enumerated, so they '
          f'have to be comparable')

    print('\nthe label comes off before the close here too')
    gh = Github({4: finding(4), 5: finding(5)})
    code, out = run_capture(tool, gh, WIPE + ['--reason', 'slate wipe'])
    order = [(c[0], c[1]) for c in gh.calls if c[0] in ('DELETE', 'POST', 'PATCH')]
    for number in (4, 5):
        mine = [i for i, c in enumerate(order) if f'/issues/{number}' in c[1]]
        kinds = [order[i][0] for i in mine]
        check(f'#{number}: DELETE, then POST, then PATCH',
              kinds == ['DELETE', 'POST', 'PATCH'], f'got {kinds}')

    print('\nrunning it twice is a no-op')
    gh = Github({n: finding(n) for n in range(60, 71)})
    first_code, first_out = run_capture(tool, gh, WIPE)
    before = len(gh.calls)
    second_code, second_out = run_capture(tool, gh, WIPE)
    second = gh.calls[before:]
    first, res = result_of(first_out), result_of(second_out)
    check('the first run wipes all 11', first.get('closed') == '11')
    check('the second enumerates nothing',
          res.get('enumerated') == '0' and res.get('list') == 'ok', f'{res}')
    check('the second changes nothing',
          not [c for c in second if c[0] in ('DELETE', 'POST', 'PATCH')],
          f'second run made {[c[0] for c in second]}')
    check('and the second is not an error',
          second_code == 0, f'exit {second_code}')

    print('\nwhat it refuses to touch')
    gh = Github({11: finding(11)},
                extra=[{'number': 999, 'title': 'a pull request', 'state': 'open',
                        'labels': [{'name': 'fuzzuer-finding'}],
                        'pull_request': {'url': 'x'}}])
    code, out = run_capture(tool, gh, WIPE)
    check('a pull request in the list is not closed',
          999 not in gh.touched('PATCH') and 999 not in gh.touched('DELETE')
          and result_of(out).get('enumerated') == '1',
          f'{result_of(out)}; patched {gh.touched("PATCH")} -- the issues endpoint '
          f'returns PRs too')

    # The label was deleted wholesale at some point, so ?labels= answers with issues that
    # report labels: []. Their keys are already free; closing them would be closing real
    # findings for nothing.
    gh = Github({12: finding(12),
                 13: {'title': 'key already free', 'state': 'open', 'labels': []}},
                ghosts=[13])
    code, out = run_capture(tool, gh, WIPE)
    check('an issue the query returned but whose own labels are empty is left alone',
          result_of(out).get('enumerated') == '1' and gh.touched('PATCH') == [12],
          f'{result_of(out)}; patched {gh.touched("PATCH")} -- trust the issue, not the '
          f'filter: a deleted label keeps answering with the issues that used to carry '
          f'it, and their site keys are already free')

    print('\nwithout --unlabel a slate wipe is refused outright')
    gh = Github({n: finding(n) for n in range(20, 25)})
    code, out = run_capture(tool, gh, ['--slug', 'me/mine', '--all-labelled'])
    check('--all-labelled without --unlabel exits 2 and lists nothing',
          code == 2 and not gh.lists,
          f'exit {code}, {len(gh.lists)} list requests -- closing without unlabelling '
          f'looks like it worked and then the next campaign refiles nothing')
    check('and nothing was closed',
          gh.still_labelled() == list(range(20, 25)) and gh.still_open() == list(range(20, 25)))
    code, out = run_capture(tool, gh, ['--slug', 'me/mine', '--all-labelled',
                                       '--keep-keys'])
    check('--keep-keys is the deliberate way to close and keep the keys',
          code == 0 and gh.still_labelled() == list(range(20, 25))
          and gh.still_open() == [], f'exit {code}; {result_of(out)}')
    code, out = run_capture(tool, gh, ['--slug', 'me/mine', '--issues', '20',
                                       '--all-labelled', '--unlabel'])
    check('the two modes are mutually exclusive', code == 2, f'exit {code}')
    code, out = run_capture(tool, gh, ['--slug', 'me/mine', '--unlabel'])
    check('and one of them is required', code == 2, f'exit {code}')

    print('\na listing that failed is not an empty one')
    gh = Github({n: finding(n) for n in range(30, 35)}, fail_list=True)
    code, out = run_capture(tool, gh, WIPE)
    res = result_of(out)
    check('with a token, a failed listing is an error',
          code == 1 and res.get('list') == 'failed', f'exit {code}; {res}')
    check('and nothing is touched on a short list',
          not gh.touched('DELETE') and not gh.touched('PATCH'),
          'acting on half a slate leaves the other half holding its site keys')
    check('it does not say the slate was clean',
          'nothing' not in out.lower() or 'cannot enumerate' in out,
          'a failed listing reported as an empty one is the failure that looks like '
          'success')
    os.environ.pop('GITHUB_TOKEN', None)
    gh = Github({n: finding(n) for n in range(30, 35)}, fail_list=True)
    code, out = run_capture(tool, gh, WIPE + ['--dry-run'])
    res = result_of(out)
    check('without a token it is a dry run that reports it could not read, not 5 failures',
          code == 0 and res.get('list') == 'failed' and res.get('failed') == '0',
          f'exit {code}; {res} -- call() performs GETs even in dry-run mode, and a '
          f'private repository 404s without a token: 11 of those were once reported as '
          f'failures of the thing being rehearsed')

    print('\na dry run changes nothing and still says what it would do')
    gh = Github({n: finding(n) for n in range(40, 45)})
    code, out = run_capture(tool, gh, WIPE + ['--dry-run', '--reason', 'slate wipe'])
    res = result_of(out)
    check('it reports the whole slate',
          code == 0 and res.get('enumerated') == '5' and res.get('closed') == '5',
          f'exit {code}; {res}')
    check('and every issue is still labelled and still open afterwards',
          gh.still_labelled() == list(range(40, 45))
          and gh.still_open() == list(range(40, 45)),
          f'labelled {gh.still_labelled()}, open {gh.still_open()}')
    check('it names each issue it would close',
          all(f'#{n}' in out for n in range(40, 45)) and 'would close' in out)
    os.environ['GITHUB_TOKEN'] = 'x'

    print('\n--limit stops rather than wipe more than was meant')
    gh = Github({n: finding(n) for n in range(50, 60)})
    code, out = run_capture(tool, gh, WIPE + ['--limit', '5'])
    res = result_of(out)
    check('ten issues against --limit 5 is an error, not a wipe of five',
          code == 1 and res.get('list') == 'failed'
          and not gh.touched('DELETE') and not gh.touched('PATCH'),
          f'exit {code}; {res}; deleted {gh.touched("DELETE")}')
    check('and the count is in the message so the operator can decide',
          '10' in out and '5' in out, out[-400:])
    os.environ.pop('GITHUB_TOKEN', None)

    print('\nupstream is refused on the new path as well')
    gh = Github({1: finding(1)})
    code, out = run_capture(tool, gh, ['--slug', 'tianocore/edk2', '--all-labelled'])
    check('before the argument checks, so a usage error cannot mask it',
          gh.calls and gh.calls[0][0] == 'refuse_upstream',
          f'first call was {gh.calls[:1]} -- --all-labelled without --unlabel is a usage '
          f'error, and it must not be the thing that stops the run')
    # Against the real refuse_upstream, in a subprocess, because the stand-in records it
    # instead of exiting and so cannot show the exit code the five other call sites use.
    for slug in ('tianocore/edk2', 'TianoCore/edk2-platforms',
                 'https://github.com/tianocore/edk2.git'):
        # Not python -I: file_issues.py imports its sibling issue_evidence, which needs
        # the script directory on sys.path, and isolated mode takes it off.
        done = subprocess.run(
            [sys.executable, os.path.join(HERE, 'close_issues.py'),
             '--slug', slug, '--all-labelled', '--unlabel', '--dry-run'],
            capture_output=True, text=True, timeout=60)
        check(f'{slug} exits 3 with no request made',
              done.returncode == 3 and 'refusing to close issues' in done.stdout,
              f'exit {done.returncode}: {done.stdout[:200]}{done.stderr[:200]}')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
