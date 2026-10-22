#!/usr/bin/env python3
"""File one issue per triage candidate, plus one issue for the run.

A pull request was the wrong shape for this. The findings are not a change to the tree --
nothing in them is something to merge -- and putting eight unrelated reports behind one
review means they are read, or ignored, together. An issue each is what you can assign,
close, and argue with individually.

Re-runnable by design: every issue carries its candidate's fingerprint in an HTML comment,
and a run that finds the same site again adds nothing. The fingerprint is bugs.json's own
`id` -- module, bug class and source file -- which deliberately leaves out the offset in
`site`, because that moves with every build and would file a fresh issue each week for a
defect already open.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = 'https://api.github.com'
MARK = 'fuzzuer-fingerprint:'
LABEL_FINDING = 'fuzzuer-finding'
LABEL_RUN = 'fuzzuer-run'


def call(token, method, path, body=None, dry=False):
    """One REST call. Returns (status, parsed-body-or-None)."""
    url = path if path.startswith('http') else f'{API}{path}'
    if dry and method != 'GET':
        print(f'  would {method} {url}')
        return 0, {}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    # Only when there is one: reading a public repository's issues needs no credentials,
    # and sending "Bearer " with nothing after it is a 401 rather than an anonymous read,
    # which made --dry-run impossible to use without a token.
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('X-GitHub-Api-Version', '2022-11-28')
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as err:
        raw = err.read().decode('utf-8', 'replace')
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, {'message': raw[:200]}
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, {'message': str(err)}


def why(payload):
    """The message GitHub actually gave, errors included."""
    if not isinstance(payload, dict):
        return 'unparseable response'
    extra = '; '.join(e.get('message', '') for e in payload.get('errors', [])
                      if e.get('message'))
    said = (payload.get('message', '') + (f' -- {extra}' if extra else '')) or 'no detail'
    # 410 on this endpoint means one thing only, and the bare "Issues are disabled"
    # does not say where to turn them on.
    if 'disabled' in said.lower():
        said += ' (Settings -> General -> Features -> Issues; off by default on a fork)'
    return said


def already_filed(token, slug, dry=False):
    """Fingerprint -> issue, for every issue this tool has filed before.

    Open AND closed: a closed issue means someone has already looked, and re-filing it
    because the next run saw the same site again is the one behaviour that would make this
    unusable on a schedule.
    """
    seen = {}
    page = 1
    while page <= 20:
        status, body = call(token, 'GET',
                            f'/repos/{slug}/issues?labels={LABEL_FINDING}'
                            f'&state=all&per_page=100&page={page}')
        if status != 200 or not isinstance(body, list):
            if status not in (200, 0) or page == 1:
                print(f'  could not list existing issues ({status}): {why(body)}')
            return seen, status == 200
        if not body:
            break
        for issue in body:
            if 'pull_request' in issue:       # the issues endpoint returns PRs too
                continue
            for line in (issue.get('body') or '').splitlines():
                if MARK in line:
                    seen[line.split(MARK, 1)[1].strip().rstrip('->').strip()] = issue
                    break
        page += 1
    return seen, True


def source_of(cand):
    """The source file as triage identified it, disambiguator included.

    Taken from `id` rather than from `site`: where one module reports the same bug class
    from several distinct sites, triage separates them as `fwsan~0`, `fwsan~1` and so on,
    and splitting `site` on the colon throws that away -- three different sites then got
    one identical issue title.
    """
    parts = (cand.get('id') or '').split('|')
    if len(parts) >= 3 and parts[2]:
        return parts[2]
    return (cand.get('site') or '?').split(':')[0]


def body_for(cand, ref, run_id, run_url, artifact):
    reached = ', '.join(cand.get('protocols') or []) or 'not attributed to a protocol'
    rows = [
        ('module', f"`{cand.get('module') or '(unattributed)'}`"),
        ('bug type', cand.get('class', '?')),
        ('source', f'`{source_of(cand)}`'),
        ('site', f"`{cand.get('site', '?')}`"),
        ('reports at this site', str(cand.get('hits', '?'))),
        ('reached by', reached),
        ('detail', cand.get('detail', '')),
    ]
    out = ['| | |', '|---|---|']
    out += [f'| {k} | {v} |' for k, v in rows]
    out += [
        '',
        f'Found by FuzzUEr fuzzing `{ref}` in [run {run_id}]({run_url}).',
        '',
        f'The reproducer inputs are in that run\'s `{artifact}` artifact, under '
        '`reproducers/<protocol>/`, together with the full `bugs.md` and the stage logs.',
        '',
        '### Read this before acting',
        '',
        'A candidate is something to read, not a confirmed defect.',
        '',
        '- The **module** is what matters. A report against the harness, or against a '
        'library the firmware never calls, says nothing about this firmware.',
        '- **Reports are not bugs.** The count above is how often this site reported, not '
        'how many defects are here: one site with thousands of hits is a loop or a '
        'scanner, not thousands of problems.',
        '- The offset in `site` moves with every build, so this issue is keyed to '
        'module + bug type + source instead. A later run that finds the same site again '
        'adds nothing here.',
        '',
        f'<!-- {MARK} {cand.get("id", "")} -->',
    ]
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bugs', required=True, help='bugs.json from the run')
    ap.add_argument('--slug', required=True, help='owner/repo to file against')
    ap.add_argument('--ref', default='', help='the ref that was fuzzed')
    ap.add_argument('--run-id', default='', help='the Actions run id')
    ap.add_argument('--server', default='https://github.com')
    ap.add_argument('--max-issues', type=int, default=50,
                    help='stop after this many NEW issues (0: no limit)')
    ap.add_argument('--dry-run', action='store_true',
                    help='say what would be filed; make no changes')
    args = ap.parse_args()

    token = os.environ.get('GH_TOKEN', '')
    if not token and not args.dry_run:
        print('no GH_TOKEN in the environment', file=sys.stderr)
        return 2
    try:
        cands = json.load(open(args.bugs)).get('candidates') or []
    except Exception as exc:
        print(f'cannot read {args.bugs}: {exc}', file=sys.stderr)
        return 2
    if not cands:
        print('no candidates, so nothing to file')
        return 0

    # Worst first, so that a --max-issues cut keeps the ones worth reading.
    cands.sort(key=lambda c: (-(c.get('severity') or 0), -(c.get('hits') or 0)))
    run_url = f'{args.server}/{args.slug}/actions/runs/{args.run_id}'
    artifact = f'fuzzuer-{args.run_id}'

    # Before anything else, because GitHub turns Issues OFF by default on a FORK and a
    # fork is exactly what this tool is pointed at. Without this check every POST comes
    # back 410 and the run reports "could not file" eight times for a setting nobody
    # thought to look at -- while the listing above still answers 200 with an empty array,
    # so nothing earlier gives it away.
    status, repo = call(token, 'GET', f'/repos/{args.slug}')
    if status == 200 and repo.get('has_issues') is False:
        print(f'::warning::{args.slug} has Issues disabled, so none can be filed there. '
              f'GitHub disables Issues by default on a fork: turn it on under Settings -> '
              f'General -> Features -> Issues. The findings are in the run artifact '
              f'meanwhile, and re-running after enabling it files them.')
        return 0
    if status not in (200, 0):
        print(f'::warning::cannot read {args.slug} ({status}): {why(repo)}')

    seen, listed = already_filed(token, args.slug, args.dry_run)
    if not listed:
        # Filing on top of a list that failed to load would duplicate everything already
        # open, which is worse than filing nothing.
        print('::warning::could not read the existing issues, so nothing was filed -- '
              'the token needs Issues: read/write on this repository')
        return 0
    print(f'{len(cands)} candidate(s); {len(seen)} fingerprint(s) already filed')

    for label, colour, desc in ((LABEL_FINDING, 'B60205', 'A site FuzzUEr attributed to firmware code'),
                                (LABEL_RUN, '0E8A16', 'One FuzzUEr run')):
        call(token, 'POST', f'/repos/{args.slug}/labels',
             {'name': label, 'color': colour, 'description': desc}, args.dry_run)

    filed, skipped, failed, capped = [], [], 0, 0
    for cand in cands:
        fp = cand.get('id', '')
        if fp and fp in seen:
            skipped.append((cand, seen[fp]))
            continue
        if args.max_issues and len(filed) >= args.max_issues:
            capped += 1
            continue
        title = (f"{cand.get('module') or '(unattributed)'}: {cand.get('class', '?')}"
                 f" in {source_of(cand)}")
        status, resp = call(token, 'POST', f'/repos/{args.slug}/issues',
                            {'title': title[:250],
                             'body': body_for(cand, args.ref, args.run_id, run_url, artifact),
                             'labels': [LABEL_FINDING]}, args.dry_run)
        if args.dry_run:
            print(f'  would file: {title}')
            filed.append((cand, {'html_url': '(dry run)', 'number': 0}))
            continue
        if status == 201:
            print(f"  filed #{resp.get('number')} {title}")
            filed.append((cand, resp))
        else:
            failed += 1
            print(f'::warning::could not file "{title}" ({status}): {why(resp)}')

    if failed and not filed:
        print('::warning::no issue could be filed -- the workflow needs '
              '`permissions: issues: write`, or a findings-token with Issues: write')
        return 0

    # One issue for the run itself, so the per-finding issues have somewhere to be read
    # together and a clean run still leaves a record of what was fuzzed.
    lines = [f'FuzzUEr fuzzed `{args.ref}` in [run {args.run_id}]({run_url}).', '',
             f'{len(cands)} candidate(s) attributed to firmware code: '
             f'{len(filed)} newly filed, {len(skipped)} already tracked.', '']
    if filed:
        lines += ['### Filed by this run', '']
        lines += [f"- #{r.get('number')} — `{c.get('module') or '(unattributed)'}` "
                  f"{c.get('class','?')} in `{source_of(c)}` "
                  f"({c.get('hits','?')} report(s))"
                  for c, r in filed] + ['']
    if skipped:
        lines += ['### Already tracked', '']
        lines += [f"- #{r.get('number')} — `{c.get('module') or '(unattributed)'}` "
                  f"{c.get('class','?')} in `{source_of(c)}` "
                  f"(seen again: {c.get('hits','?')} report(s))"
                  for c, r in skipped] + ['']
    if capped:
        lines += [f'### {capped} candidate(s) not filed', '',
                  f'`max-issues` is {args.max_issues}. The ones left out are the '
                  f'lowest severity of the run; all of them are in `bugs.md` in the '
                  f'`{artifact}` artifact.', '']
    lines += [f'Everything else the run produced -- `bugs.md`, every reproducer input, '
              f'the per-stage logs -- is in the `{artifact}` artifact.']
    status, resp = call(token, 'POST', f'/repos/{args.slug}/issues',
                        {'title': f'FuzzUEr run {args.run_id}: '
                                  f'{len(cands)} candidate(s)',
                         'body': '\n'.join(lines),
                         'labels': [LABEL_RUN]}, args.dry_run)
    summary = ''
    if args.dry_run:
        print('  would file the run summary issue')
    elif status == 201:
        summary = resp.get('html_url', '')
        print(f"  filed #{resp.get('number')} (run summary) {summary}")
    else:
        print(f'::warning::could not file the run summary ({status}): {why(resp)}')

    out = os.environ.get('GITHUB_OUTPUT')
    if out:
        with open(out, 'a') as handle:
            handle.write(f'run-issue={summary}\n')
            handle.write('issues=' + ' '.join(r.get('html_url', '') for _, r in filed) + '\n')
            handle.write(f'issues-filed={len(filed)}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
