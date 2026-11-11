#!/usr/bin/env python3
"""Close findings this tool filed that the code no longer produces.

A fixed generator leaves its old issues behind. Ten of them -- #37 to #46 on
BreakingBoot/eval1_edk2 -- were one DEBUG statement in our own SMI dispatch narration
printing the caller's GUID through %g, which is ten reads, so the sanitizer filed ten
issues against firmware that was fine; the narration was fixed and the issues were not.
One more, #51, was titled with a whole sanitizer report line by an extractor defect that
is also fixed.

Closing is not enough on its own. already_filed() queries `state=all` BY DESIGN, so that
a closed issue still holds its site key and a site is not refiled every week. That is the
right default and it means closing alone does not free the key: the label has to come off
FIRST, which is what --unlabel does, in that order.

Two guards, because this closes things:

  * the upstream refusal every other entry point has. A fuzzing finding is never filed at
    upstream edk2, and it is never closed there either.
  * an issue is only closed when it carries the finding label, so a number typo cannot
    close someone's unrelated issue. --force is the deliberate way past that, and it says
    so in the output.

Run: python3 scripts/close_issues.py --slug owner/repo --issues 37-46,51 \
          --reason "..." [--unlabel] [--dry-run]
The token comes from GITHUB_TOKEN or GH_TOKEN; a run without one is --dry-run whatever
else was asked for.
"""
import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_file_issues():
    spec = importlib.util.spec_from_file_location(
        'file_issues', os.path.join(HERE, 'file_issues.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAX_ISSUES = 50


def parse_issues(text):
    """"37-46,51" -> [37, ..., 46, 51]. Ranges are inclusive and order is kept."""
    out = []
    for piece in (text or '').split(','):
        piece = piece.strip()
        if not piece:
            continue
        if '-' in piece.lstrip('-'):
            first, _, last = piece.partition('-')
            start, stop = int(first), int(last)
            if stop < start:
                raise ValueError(f'{piece} counts backwards')
            if stop - start >= MAX_ISSUES:
                raise ValueError(f'{piece} is more than {MAX_ISSUES} issues')
            out.extend(range(start, stop + 1))
        else:
            out.append(int(piece))
    seen, unique = set(), []
    for number in out:
        if number <= 0:
            raise ValueError(f'#{number} is not an issue number')
        if number not in seen:
            seen.add(number)
            unique.append(number)
    if len(unique) > MAX_ISSUES:
        raise ValueError(f'{len(unique)} issues is more than {MAX_ISSUES}')
    return unique


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--slug', required=True)
    parser.add_argument('--issues', required=True,
                        help='numbers and inclusive ranges, e.g. 37-46,51')
    parser.add_argument('--reason', default='',
                        help='posted as a comment before the close, so the issue says why')
    parser.add_argument('--unlabel', action='store_true',
                        help=f'remove the finding label first, which frees the site key')
    parser.add_argument('--force', action='store_true',
                        help='close even without the finding label')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    tool = load_file_issues()
    tool.refuse_upstream(args.slug, 'close issues')

    try:
        numbers = parse_issues(args.issues)
    except ValueError as err:
        print(f'::error::--issues {args.issues}: {err}')
        return 2

    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN') or ''
    dry = args.dry_run or not token
    if dry and not args.dry_run:
        print('::warning::no GITHUB_TOKEN, so this is a dry run')

    closed = skipped = failed = 0
    for number in numbers:
        status, issue = tool.call(token, 'GET', f'/repos/{args.slug}/issues/{number}',
                                  dry=dry)
        if status != 200 or not isinstance(issue, dict):
            # call() still performs a GET in dry mode, because already_filed has to read.
            # Without a token that is a 404 on a private repo, which is not a failure of
            # the thing being rehearsed.
            if dry:
                print(f'  would close #{number}'
                      + (' after removing the label' if args.unlabel else '')
                      + f' -- cannot read it here: {tool.why(issue)}')
                skipped += 1
            else:
                print(f'  [skip] #{number}: {tool.why(issue)}')
                failed += 1
            continue
        title = (issue.get('title') or '')[:60]
        labels = [l.get('name', '') if isinstance(l, dict) else str(l)
                  for l in (issue.get('labels') or [])]
        if issue.get('state') == 'closed' and not args.unlabel:
            print(f'  [skip] #{number} is already closed -- {title}')
            skipped += 1
            continue
        if tool.LABEL_FINDING not in labels and not args.force:
            print(f'  [skip] #{number} does not carry {tool.LABEL_FINDING}, so this tool '
                  f'did not file it -- {title}. Pass --force to close it anyway.')
            skipped += 1
            continue
        if args.unlabel and tool.LABEL_FINDING in labels:
            # Before the close, not after: a closed issue keeps its site key, and the key
            # is what stops the site being refiled.
            remove, body = tool.call(
                token, 'DELETE',
                f'/repos/{args.slug}/issues/{number}/labels/{tool.LABEL_FINDING}', dry=dry)
            if remove not in (200, 204):
                print(f'  [fail] #{number}: the label would not come off: '
                      f'{tool.why(body)}')
                failed += 1
                continue
        if args.reason:
            tool.call(token, 'POST', f'/repos/{args.slug}/issues/{number}/comments',
                      {'body': args.reason}, dry=dry)
        state, body = tool.call(token, 'PATCH', f'/repos/{args.slug}/issues/{number}',
                                {'state': 'closed', 'state_reason': 'not_planned'}, dry=dry)
        if state == 200:
            print(f'  closed #{number}'
                  + (' and freed its site key' if args.unlabel else '')
                  + f' -- {title}')
            closed += 1
        else:
            print(f'  [fail] #{number}: {tool.why(body)}')
            failed += 1

    print(f'{closed} closed, {skipped} skipped, {failed} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
