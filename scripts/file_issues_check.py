#!/usr/bin/env python3
"""Assert the filer does not file the same site twice.

"Do not open a duplicate issue for a bug already filed" is a requirement with no visible
failure mode. A filer that deduplicates nothing looks identical to one that works until a
scheduled run has opened its fourth copy of the same finding, and by then the repository is
the evidence. Nothing in CI tested it: close_issues_check.py asserts the TEARDOWN ordering
that frees a site key, and this is the other half -- that a key which is still held stops a
re-file, and that one which was freed does not.

Asserted end to end, by running main() repeatedly against a stateful stand-in for the REST
endpoints, because every interesting failure is a STATE rather than a call: a fingerprint
that does not survive the round trip through an issue body, a key that changes when the
report text changes, an issue whose label was removed, a listing that failed being treated
as an empty slate. A call recorder cannot see any of those.

The third run is the one that exists for a specific regression. A double-fetch report now
carries the handler, the struct field, its offset and width and both read sites, where it
used to carry a bare address -- so the issue BODY for an unchanged finding is different
text. Had the site key been derived from the report rather than from module, class and
source, enriching it would have made every previously-filed finding look new, and the next
scheduled run would have refiled the lot. It is not, and run 3 is what keeps it that way.

Run: python3 scripts/file_issues_check.py
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
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
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


class FakeHub:
    """The issue endpoints, with state, standing in for github.com.

    Deliberately NOT a recorder. The questions here are "how many issues exist now" and
    "did this key stop a re-file", and both are answered by what this object holds after a
    run rather than by the sequence of requests that got there.
    """

    def __init__(self, has_issues=True, list_status=200, per_page_cap=100):
        self.issues = []                  # the repository's issues, in creation order
        self.has_issues = has_issues
        self.list_status = list_status
        self.per_page_cap = per_page_cap  # to prove the filer pages rather than truncating
        self.label_posts = 0

    # -- helpers for the assertions -------------------------------------------------
    def labelled(self):
        return [i for i in self.issues
                if any(l['name'] == 'fuzzuer-finding' for l in i['labels'])]

    def unlabel(self, number):
        for issue in self.issues:
            if issue['number'] == number:
                issue['labels'] = []

    def close(self, number):
        for issue in self.issues:
            if issue['number'] == number:
                issue['state'] = 'closed'

    # -- the endpoint ---------------------------------------------------------------
    def call(self, token, method, path, body=None, dry=False):
        url = urlparse(path)
        query = parse_qs(url.query)
        if method == 'GET' and re.fullmatch(r'/repos/[^/]+/[^/]+', url.path):
            return 200, {'has_issues': self.has_issues}
        if method == 'GET' and url.path.endswith('/issues'):
            if self.list_status != 200:
                return self.list_status, {'message': 'Bad credentials'}
            # GitHub's own filter answers with issues that USED to carry the label, so
            # the stand-in does too -- the filer is supposed to re-check labels itself.
            rows = list(self.issues)
            if query.get('state', ['open'])[0] != 'all':
                rows = [r for r in rows if r['state'] == 'open']
            size = min(int(query.get('per_page', ['30'])[0]), self.per_page_cap)
            page = int(query.get('page', ['1'])[0])
            return 200, rows[(page - 1) * size: page * size]
        if method == 'POST' and url.path.endswith('/issues'):
            number = len(self.issues) + 1
            self.issues.append({
                'number': number, 'state': 'open',
                'title': body['title'], 'body': body['body'],
                'labels': [{'name': n} for n in body.get('labels', [])],
                'html_url': f'https://example.invalid/issues/{number}'})
            return 201, self.issues[-1]
        if method == 'POST' and url.path.endswith('/labels'):
            self.label_posts += 1
            return 200, {}
        return 200, {}


def run_filer(tool, hub, bugs_path, extra=()):
    """main() with the single HTTP chokepoint swapped for the stand-in."""
    saved_argv, saved_call = sys.argv, tool.call
    sys.argv = (['file_issues.py', '--bugs', bugs_path, '--slug', 'cglosner/edk2',
                 '--no-evidence', '--run-id', '1'] + list(extra))
    tool.call = hub.call
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            code = tool.main()
    finally:
        sys.argv, tool.call = saved_argv, saved_call
    return code, buf.getvalue()


def write_bugs(path, cands):
    with open(path, 'w') as handle:
        json.dump({'candidates': cands}, handle)


# Four candidates chosen to exercise the parts of the key that are easy to get wrong:
# two sibling sites that share a canonical key and are told apart only by `~N`; one
# unattributed finding, which matches any module's site in the same class and file; and
# one in a DIFFERENT module with the same class and file, which is a separate bug.
CANDS = [
    {'id': 'VariableSmm.efi|double-fetch|VariableSmm.c~0', 'module': 'VariableSmm.efi',
     'class': 'double-fetch', 'site': 'VariableSmm.c:1204', 'severity': 3, 'hits': 9,
     'detail': 'double fetch at 0x1B56802C'},
    {'id': 'VariableSmm.efi|double-fetch|VariableSmm.c~1', 'module': 'VariableSmm.efi',
     'class': 'double-fetch', 'site': 'VariableSmm.c:1337', 'severity': 3, 'hits': 4,
     'detail': 'double fetch at 0x1B568040'},
    {'id': '|heap-buffer-overflow|SmmSpi.c', 'module': '',
     'class': 'heap-buffer-overflow', 'site': 'SmmSpi.c:88', 'severity': 4, 'hits': 2,
     'detail': 'write of size 8'},
    {'id': 'SmmLockBox.efi|double-fetch|VariableSmm.c~0', 'module': 'SmmLockBox.efi',
     'class': 'double-fetch', 'site': 'VariableSmm.c:1204', 'severity': 2, 'hits': 1,
     'detail': 'double fetch at 0x1B568018'},
]


def main():
    tool = load('file_issues')
    os.environ['GH_TOKEN'] = 'x' * 8
    os.environ.pop('GITHUB_OUTPUT', None)

    print('the canonical key: what it keeps and what it drops')
    canon, canon_of, source_of = tool.canon, tool.canon_of, tool.source_of
    check('sibling sites under one module, class and file share a key',
          canon('M.efi|double-fetch|V.c~0') == canon('M.efi|double-fetch|V.c~7'),
          'the ~N disambiguator must not reach the key, or every rebuild that renumbers '
          'the siblings refiles all of them')
    check('a ~N in the module is NOT stripped',
          canon('M~0|c|f.c') != canon('M~1|c|f.c'),
          'only the third field carries the disambiguator')
    check('a ~ that is not a trailing number survives',
          canon('M|c|f.c~1x').endswith('f.c~1x'),
          'TILDE is anchored, so a filename containing ~1x is left alone')
    check('a short fingerprint is padded rather than raising',
          canon('M').count('|') == 2 and canon('').count('|') == 2)
    check('two different modules in the same class and file are different keys',
          canon_of(CANDS[0]) != canon_of(CANDS[3]),
          'two modules reporting one class from one file are two bugs, never one')
    check('source_of keeps the disambiguator the title needs',
          source_of(CANDS[0]) == 'VariableSmm.c~0',
          'three distinct sites got one identical title when this was split off `site`')
    check('source_of falls back to `site` when the id carries no source',
          source_of({'id': 'M|c', 'site': 'Foo.c:12'}) == 'Foo.c')

    print('\nthe key ignores the report text entirely')
    rich = copy.deepcopy(CANDS[0])
    rich['detail'] = ('RW_VARIABLE_INFO.VarGuid.Data2 at payload offset 0x14, 2 byte(s), '
                      'read twice from 0x1FE0CD02 and 0x1FFC9B37')
    check('enriching a double-fetch report does not change its site key',
          canon_of(rich) == canon_of(CANDS[0]),
          'the key is module|class|source; deriving it from the report would have '
          'refiled every finding the moment the report gained detail')

    print('\nthe ledger accounts for one candidate per filed issue')
    ledger = tool.Ledger({canon_of(CANDS[0]): ['issue-a']})
    first, second = ledger.take_exact(canon_of(CANDS[0])), ledger.take_exact(canon_of(CANDS[1]))
    check('one filed issue covers exactly one of two sibling candidates',
          first == 'issue-a' and second is None,
          f'got {first!r} then {second!r} -- a list keyed by site cannot be matched by '
          f'identity, so it is matched by count')
    ledger = tool.Ledger({canon_of(CANDS[0]): ['attributed']})
    held, loose = ledger.take(canon_of(CANDS[2]))
    check('an unattributed candidate may take an attributed sibling, and says so',
          held is None or loose is True,
          f'got {held!r} loose={loose!r}')
    ledger = tool.Ledger({canon_of(CANDS[0]): ['theirs']})
    held, loose = ledger.take(canon_of(CANDS[3]))
    check('an attributed candidate never takes another module\'s issue',
          held is None,
          f'took {held!r}: SmmLockBox.efi and VariableSmm.efi reporting double-fetch '
          f'from VariableSmm.c are two findings')

    with tempfile.TemporaryDirectory() as work:
        bugs = os.path.join(work, 'bugs.json')
        write_bugs(bugs, CANDS)

        print('\nrun 1: an empty repository')
        hub = FakeHub()
        code, text = run_filer(tool, hub, bugs)
        check('every candidate is filed', code == 0 and len(hub.labelled()) == len(CANDS),
              f'exit {code}, {len(hub.labelled())} issue(s) of {len(CANDS)}:\n{text[-600:]}')
        check('each issue carries its fingerprint for the next run to read',
              all(tool.MARK in i['body'] for i in hub.issues),
              'without the marker in the body nothing can be deduplicated at all')

        print('\nrun 2: the same findings again')
        before = len(hub.issues)
        code, text = run_filer(tool, hub, bugs)
        check('nothing is filed a second time',
              code == 0 and len(hub.issues) == before,
              f'{len(hub.issues) - before} duplicate(s) filed:\n{text[-800:]}')

        print('\nrun 3: the same findings, with the reports enriched')
        enriched = copy.deepcopy(CANDS)
        for cand in enriched:
            cand['detail'] = ('RW_VARIABLE_INFO.VarGuid.Data2 at payload offset 0x14, '
                              '2 byte(s), read twice from 0x1FE0CD02 and 0x1FFC9B37')
        rich_bugs = os.path.join(work, 'bugs-rich.json')
        write_bugs(rich_bugs, enriched)
        code, text = run_filer(tool, hub, rich_bugs)
        check('a changed report is not a new finding',
              code == 0 and len(hub.issues) == before,
              f'{len(hub.issues) - before} refiled after the report text changed:'
              f'\n{text[-800:]}')

        print('\nrun 4: the same findings after a rebuild renumbered the siblings')
        # The reason canon() strips `~N` at all. Triage numbers sibling sites in the order
        # it meets them, so a rebuild that shifts a line or reorders a module's reports
        # hands the same two bugs back as ~3 and ~4. Keyed on the raw fingerprint those are
        # two keys nothing has filed, and the pair is filed again on every run that renumbers
        # them -- which is the shape a scheduled filer accumulates duplicates in.
        renumbered = copy.deepcopy(CANDS)
        renumbered[0]['id'] = 'VariableSmm.efi|double-fetch|VariableSmm.c~3'
        renumbered[1]['id'] = 'VariableSmm.efi|double-fetch|VariableSmm.c~4'
        renum_bugs = os.path.join(work, 'bugs-renumbered.json')
        write_bugs(renum_bugs, renumbered)
        code, text = run_filer(tool, hub, renum_bugs)
        check('renumbered sibling sites are not new findings',
              code == 0 and len(hub.issues) == before,
              f'{len(hub.issues) - before} refiled after ~0/~1 became ~3/~4:'
              f'\n{text[-800:]}')

        print('\nrun 5: after the issues are closed')
        for issue in list(hub.issues):
            hub.close(issue['number'])
        code, text = run_filer(tool, hub, bugs)
        check('a closed issue still holds its site key',
              code == 0 and len(hub.issues) == before,
              f'{len(hub.issues) - before} refiled -- closing is how a human says "seen", '
              f'and refiling on the next schedule is what makes this unusable')

        print('\nrun 6: after one label is removed')
        freed = canon_of(CANDS[2])
        target = next(i for i in hub.issues
                      if tool.canon(i['body'].split(tool.MARK, 1)[1]
                                    .splitlines()[0].strip().rstrip('->').strip()) == freed)
        hub.unlabel(target['number'])
        code, text = run_filer(tool, hub, bugs)
        check('unlabelling frees exactly that one key',
              code == 0 and len(hub.issues) == before + 1,
              f'{len(hub.issues) - before} filed, expected 1 -- --unlabel is how the '
              f'slate is wiped, and it has to be what frees a key')

        print('\nrun 7: the listing fails')
        hub = FakeHub(list_status=403)
        code, text = run_filer(tool, hub, bugs)
        check('a listing that failed is not an empty slate',
              code == 0 and not hub.issues and 'nothing was filed' in text,
              f'filed {len(hub.issues)} against a repository it could not read:'
              f'\n{text[-500:]}')

        print('\nwhat the listing asks for')
        hub = FakeHub()
        seen = {}

        def record(token, method, path, body=None, dry=False):
            if method == 'GET' and path.endswith('/issues') or '/issues?' in path:
                seen.update(parse_qs(urlparse(path).query))
            return hub.call(token, method, path, body, dry)

        saved = tool.call
        try:
            tool.call = record
            tool.already_filed('x' * 8, 'cglosner/edk2')
        finally:
            tool.call = saved
        check('state=all, so a closed issue is seen',
              seen.get('state') == ['all'],
              f'query was {seen} -- close_issues.py --unlabel exists because of this')
        check('filtered by the finding label',
              seen.get('labels') == [tool.LABEL_FINDING], f'query was {seen}')

        print('\na stale label filter does not count as tracked')
        hub = FakeHub()
        hub.issues.append({'number': 1, 'state': 'open', 'title': 't',
                           'body': f'{tool.MARK} {canon_of(CANDS[0])} -->',
                           'labels': [], 'html_url': 'u'})
        saved = tool.call
        try:
            tool.call = hub.call
            filed_by_key, listed = tool.already_filed('x' * 8, 'cglosner/edk2')
        finally:
            tool.call = saved
        check('an issue the filter returns without the label is not counted',
              listed is True and not filed_by_key,
              f'counted {filed_by_key} -- GitHub answers ?labels=<deleted name> with the '
              f'issues that used to carry it, and counting those reports a cleared '
              f'repository as fully tracked')

        print('\nmore issues than one page holds')
        hub = FakeHub()
        many = [dict(CANDS[0], id=f'M{n}.efi|c|f.c', module=f'M{n}.efi')
                for n in range(140)]
        big = os.path.join(work, 'bugs-many.json')
        write_bugs(big, many)
        code, _ = run_filer(tool, hub, big, extra=['--max-issues', '200'])
        filed_1 = len(hub.issues)
        code, text = run_filer(tool, hub, big, extra=['--max-issues', '200'])
        check('a second page of existing issues is read, not truncated',
              filed_1 == 140 and len(hub.issues) == 140,
              f'{filed_1} filed, then {len(hub.issues) - filed_1} refiled -- a listing '
              f'that stopped at one page would refile everything past it')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
