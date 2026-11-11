#!/usr/bin/env python3
"""Close findings this tool filed, by number or by label, and free their site keys.

Two modes, and they exist for two different jobs:

  --issues 37-46,51   a NAMED list. For retiring findings whose defect the code no longer
                      produces. Ten of them -- #37 to #46 on BreakingBoot/eval1_edk2 --
                      were one DEBUG statement in our own SMI dispatch narration printing
                      the caller's GUID through %g, which is ten reads, so the sanitizer
                      filed ten issues against firmware that was fine; the narration was
                      fixed and the issues were not. One more, #51, was titled with a
                      whole sanitizer report line by an extractor defect that is also
                      fixed.

  --all-labelled      EVERYTHING the label holds, open and closed, enumerated from the
                      API. For wiping the slate so the next campaign refiles from
                      scratch, which is how the find -> triage -> file -> link pipeline
                      gets proved end to end. The numbers are not known up front, which
                      is the whole reason this mode exists.

Closing is not enough on its own, in either mode. already_filed() queries `state=all` BY
DESIGN, so that a closed issue still holds its site key and a site is not refiled every
week. That is the right default and it means closing alone does not free the key: the
label has to come off FIRST, which is what --unlabel does, in that order. A slate wipe
that only closes looks like it worked and then the next campaign files nothing, so
--all-labelled refuses to run without --unlabel unless --keep-keys says so deliberately.

Both modes enumerate and act on OPEN AND CLOSED issues. A closed issue that still carries
the label is exactly what blocks a refile, so it is the most important thing a slate wipe
has to find -- listing only open issues would leave the slate looking clean and still
blocked.

Three guards, because this closes things:

  * the upstream refusal every other entry point has. A fuzzing finding is never filed at
    upstream edk2, and it is never closed there either.
  * an issue is only closed when it carries the finding label, so a number typo cannot
    close someone's unrelated issue. --force is the deliberate way past that, and it says
    so in the output. The enumerated mode satisfies this by construction and still checks
    each issue's own labels rather than trusting the query -- see enumerate_labelled.
  * --limit, so a repository with more findings than expected stops the run and says the
    count instead of wiping a slate nobody meant to wipe. It never truncates silently.

Run: python3 scripts/close_issues.py --slug owner/repo --issues 37-46,51 \
          --reason "..." [--unlabel] [--dry-run]
     python3 scripts/close_issues.py --slug owner/repo --all-labelled --unlabel \
          --reason "..." [--limit 200] [--dry-run]
The token comes from GITHUB_TOKEN or GH_TOKEN; a run without one is --dry-run whatever
else was asked for.

The last line of the output is machine readable and is what a CI gate should read:

    result: mode=<m> list=<ok|failed|skipped> enumerated=N unlabelled=N closed=N \
            skipped=N failed=N

`failed=0` alone is NOT success -- a run in which every issue was skipped also ends in
`failed=0`, and so does a run whose enumeration returned nothing because the listing
failed. A gate has to compare the acted-on counts against `enumerated`, and check
`list=ok`.
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

# GitHub's list endpoint serves 30 per page when per_page is absent and caps it at 100.
# Both numbers matter: the default is what truncates a slate wipe on a repository with 31
# findings into a wipe of the first 30, and the cap is why MAX_PAGES has to be generous
# rather than clever.
PER_PAGE = 100
MAX_PAGES = 50
DEFAULT_LIMIT = 200


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


def labels_of(issue):
    """The label names on an issue, however the API spelled them."""
    return [l.get('name', '') if isinstance(l, dict) else str(l)
            for l in ((issue or {}).get('labels') or [])]


def enumerate_labelled(tool, token, slug, limit=DEFAULT_LIMIT, dry=False):
    """Every issue carrying the finding label -> [(number, issue), ...], ascending.

    Returns (pairs, ok, reason). `ok` is False for anything that would make the list
    short, and the caller must not treat a short list as a clean slate: acting on half a
    slate leaves the other half holding its site keys, and the next campaign then refiles
    half the findings and silently drops the rest.

    state=all, deliberately. A CLOSED issue that still carries the label is the one that
    blocks a refile -- already_filed() matches closed issues on purpose -- so an
    open-only enumeration would report a clean slate over a blocked one.

    per_page is spelled out. Without it GitHub serves 30 and a repository with 31
    findings loses one to a page nobody asked for.

    The label on each issue is checked against the issue's OWN labels rather than trusted
    from the query, for the same measured reason already_filed() does it: asking for
    ?labels=<name> after that label has been DELETED keeps answering with the issues that
    used to carry it -- 24 came back while the label itself was a 404, every one of them
    reporting labels: []. Here that would mean unlabelling and closing two dozen issues
    whose key was already free, i.e. closing a pile of real findings for nothing.
    """
    pairs, seen = [], set()
    page = 1
    while True:
        if page > MAX_PAGES:
            return pairs, False, (f'more than {MAX_PAGES * PER_PAGE} labelled issues; '
                                  f'this is past anything expected, so nothing was '
                                  f'touched')
        status, body = tool.call(
            token, 'GET',
            f'/repos/{slug}/issues?labels={tool.LABEL_FINDING}&state=all'
            f'&per_page={PER_PAGE}&page={page}', dry=dry)
        if status != 200 or not isinstance(body, list):
            return pairs, False, f'listing page {page} failed ({status}): {tool.why(body)}'
        if not body:
            break
        for issue in body:
            if 'pull_request' in issue:      # the issues endpoint returns PRs too
                continue
            if tool.LABEL_FINDING not in labels_of(issue):
                continue
            number = issue.get('number')
            if isinstance(number, int) and number > 0 and number not in seen:
                seen.add(number)
                pairs.append((number, issue))
        if len(body) < PER_PAGE:             # a short page is the last page
            break
        page += 1
    pairs.sort(key=lambda p: p[0])
    if limit and len(pairs) > limit:
        return pairs, False, (f'{len(pairs)} issues carry {tool.LABEL_FINDING}, which is '
                              f'more than --limit {limit}. Nothing was touched. Raise '
                              f'--limit if that count is really what you meant to wipe.')
    return pairs, True, ''


def act_on(tool, token, slug, number, issue, args, dry):
    """Unlabel, comment and close one issue. Returns (outcome, unlabelled).

    outcome is 'closed', 'freed' (the label came off an issue that was already closed),
    'skipped' or 'failed'.
    """
    title = (issue.get('title') or '')[:60]
    labels = labels_of(issue)
    was_closed = issue.get('state') == 'closed'
    said = 'would close' if dry else 'closed'

    if was_closed and not args.unlabel:
        print(f'  [skip] #{number} is already closed -- {title}')
        return 'skipped', False
    if tool.LABEL_FINDING not in labels and not args.force:
        print(f'  [skip] #{number} does not carry {tool.LABEL_FINDING}, so this tool '
              f'did not file it -- {title}. Pass --force to close it anyway.')
        return 'skipped', False

    # call() returns status 0 for a non-GET in dry-run mode, and ALSO for a timeout or a
    # DNS failure in a real run. Those are opposite outcomes, so the dry case is accepted
    # explicitly rather than by adding 0 to the list of good statuses -- which would read
    # a network failure as a successful close.
    def went(status, good):
        return status in good or (dry and status == 0)

    unlabelled = False
    if args.unlabel and tool.LABEL_FINDING in labels:
        # Before the close, not after: a closed issue keeps its site key, and the key is
        # what stops the site being refiled.
        remove, body = tool.call(
            token, 'DELETE',
            f'/repos/{slug}/issues/{number}/labels/{tool.LABEL_FINDING}', dry=dry)
        if not went(remove, (200, 204)):
            print(f'  [fail] #{number}: the label would not come off: {tool.why(body)}')
            return 'failed', False
        unlabelled = True

    if was_closed:
        # Its key is free now and the issue was already closed, so there is nothing left
        # to do to it. Commenting and re-closing would add a second identical comment to
        # every issue on each re-run, which is what makes a slate wipe non-idempotent in
        # the only way anybody notices.
        print(f'  {"would free" if dry else "freed"} #{number} -- already closed, label '
              f'{"would come" if dry else "came"} off -- {title}')
        return 'freed', unlabelled

    if args.reason:
        tool.call(token, 'POST', f'/repos/{slug}/issues/{number}/comments',
                  {'body': args.reason}, dry=dry)
    state, body = tool.call(token, 'PATCH', f'/repos/{slug}/issues/{number}',
                            {'state': 'closed', 'state_reason': 'not_planned'}, dry=dry)
    if went(state, (200,)):
        print(f'  {said} #{number}'
              + (' and freed its site key' if unlabelled else '')
              + f' -- {title}')
        return 'closed', unlabelled
    print(f'  [fail] #{number}: {tool.why(body)}')
    return 'failed', unlabelled


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--slug', required=True)
    parser.add_argument('--issues', default='',
                        help='numbers and inclusive ranges, e.g. 37-46,51')
    parser.add_argument('--all-labelled', action='store_true',
                        help='every issue carrying the finding label, open AND closed, '
                             'enumerated from the API -- a slate wipe')
    parser.add_argument('--limit', type=int, default=DEFAULT_LIMIT,
                        help=f'--all-labelled stops rather than wipe more than this many '
                             f'(default {DEFAULT_LIMIT}; 0 for no limit)')
    parser.add_argument('--reason', default='',
                        help='posted as a comment before the close, so the issue says why')
    parser.add_argument('--unlabel', action='store_true',
                        help='remove the finding label first, which frees the site key')
    parser.add_argument('--keep-keys', action='store_true',
                        help='--all-labelled without --unlabel: close everything and KEEP '
                             'the site keys, so nothing is refiled')
    parser.add_argument('--force', action='store_true',
                        help='close even without the finding label')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    tool = load_file_issues()
    # First, ahead of every request and of the argument checks that can fail: a dry run is
    # no exemption, and neither is a usage error.
    tool.refuse_upstream(args.slug, 'close issues')

    if bool(args.issues) == bool(args.all_labelled):
        print('::error::pass either --issues <numbers> or --all-labelled, not both and '
              'not neither. --all-labelled is for a slate wipe, where the numbers are not '
              'known up front.')
        return 2
    if args.all_labelled and not args.unlabel and not args.keep_keys:
        print(f'::error::--all-labelled without --unlabel would close every finding and '
              f'leave each one holding its site key. already_filed() reads '
              f'state=all, so the next campaign would refile NOTHING and the wipe would '
              f'look like it worked. Add --unlabel, or --keep-keys if closing without '
              f'freeing the keys is really what you want.')
        return 2

    numbers = []
    if args.issues:
        try:
            numbers = parse_issues(args.issues)
        except ValueError as err:
            print(f'::error::--issues {args.issues}: {err}')
            return 2

    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN') or ''
    dry = args.dry_run or not token
    if dry and not args.dry_run:
        print('::warning::no GITHUB_TOKEN, so this is a dry run')

    mode = 'all-labelled' if args.all_labelled else 'issues'
    listed = 'skipped'
    work = []
    if args.all_labelled:
        pairs, ok, reason = enumerate_labelled(tool, token, args.slug, args.limit, dry)
        listed = 'ok' if ok else 'failed'
        if not ok:
            # NOT a clean slate, and the difference has to survive into the exit code.
            # call() performs GETs even in dry-run mode, so a rehearsal without a token
            # against a private repository 404s here -- that is the rehearsal being unable
            # to read, not a failure of the thing being rehearsed, and it must not be
            # reported as "nothing needed wiping".
            level = 'warning' if dry else 'error'
            print(f'::{level}::cannot enumerate {tool.LABEL_FINDING} on {args.slug}: '
                  f'{reason}')
            print(f'result: mode={mode} list=failed enumerated=0 unlabelled=0 closed=0 '
                  f'skipped=0 failed=0')
            return 0 if dry else 1
        work = pairs
        print(f'{len(work)} issue(s) carry {tool.LABEL_FINDING} on {args.slug} '
              f'(open and closed)')
        if not work:
            print('nothing carries the label, so there is nothing to wipe -- which is '
                  'also what a second run of a completed wipe looks like')
    else:
        # One GET each, because a number typed on the command line carries no issue with
        # it. --all-labelled needs none of these: the listing already returned the whole
        # issue, and re-reading each one would both cost a request per issue and
        # reintroduce the 404-per-issue noise that the dry-run path below exists to
        # absorb.
        for number in numbers:
            status, issue = tool.call(token, 'GET',
                                      f'/repos/{args.slug}/issues/{number}', dry=dry)
            work.append((number, issue if (status == 200 and isinstance(issue, dict))
                         else ('unreadable', issue)))

    closed = freed = skipped = failed = unlabelled = 0
    for number, payload in work:
        if isinstance(payload, tuple):
            # call() still performs a GET in dry mode, because already_filed has to read.
            # Without a token that is a 404 on a private repo, which is not a failure of
            # the thing being rehearsed -- 11 of these were once reported as failures.
            if dry:
                print(f'  would close #{number}'
                      + (' after removing the label' if args.unlabel else '')
                      + f' -- cannot read it here: {tool.why(payload[1])}')
                skipped += 1
            else:
                print(f'  [skip] #{number}: {tool.why(payload[1])}')
                failed += 1
            continue
        outcome, took_label = act_on(tool, token, args.slug, number, payload, args, dry)
        unlabelled += 1 if took_label else 0
        if outcome == 'closed':
            closed += 1
        elif outcome == 'freed':
            freed += 1
        elif outcome == 'skipped':
            skipped += 1
        else:
            failed += 1

    print(f'{closed} closed, {freed} already closed and freed, {skipped} skipped, '
          f'{failed} failed')
    print(f'result: mode={mode} list={listed} enumerated={len(work)} '
          f'unlabelled={unlabelled} closed={closed + freed} skipped={skipped} '
          f'failed={failed}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
