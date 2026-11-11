#!/usr/bin/env python3
"""Assert the issue cleanup removes the label before it closes, and guards what it closes.

The ordering is the whole point and it is invisible from the outside. already_filed()
queries `state=all` BY DESIGN, so a closed issue still holds its site key and the site is
not refiled every week. Closing first and unlabelling after would leave the key held by an
issue nobody will look at again; unlabelling first frees it. Nothing about the code reads
as order-dependent, so it is asserted here against a recorded call sequence.

The guards matter as much: this tool closes things. It must refuse upstream edk2 like every
other entry point, and it must not close an issue it did not file.

Run: python3 scripts/close_issues_check.py
"""
import importlib.util
import os
import sys

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

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
