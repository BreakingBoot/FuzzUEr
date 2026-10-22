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
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

import issue_evidence as ev

API = 'https://api.github.com'
EVIDENCE_BRANCH = 'fuzzuer-evidence'
MARK = 'fuzzuer-fingerprint:'
LABEL_FINDING = 'fuzzuer-finding'


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


def git(repo, *args, env=None):
    return subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True,
                          env=env)


def push_evidence(source, slug, token, run_id, files, server):
    """Commit the harness, the inputs and the logs to a branch, and return its blob base.

    An issue cannot hold a file, so the evidence has to live somewhere a link can point at.
    It goes on a branch of its own, built with plumbing -- hash-object, update-index,
    commit-tree -- so the caller's working tree and checked-out branch are never touched.
    Each run adds a directory; nothing is ever rewritten.

    Returns '' when it cannot push, which is not fatal: the issues then carry the inline
    excerpts and the artifact, and say the links are missing.
    """
    if not files or not token:
        return ''
    url = f'https://x-access-token:{token}@github.com/{slug}.git'
    index = os.path.join(tempfile.mkdtemp(), 'index')
    env = dict(os.environ, GIT_INDEX_FILE=index,
               GIT_AUTHOR_NAME='github-actions[bot]',
               GIT_AUTHOR_EMAIL='github-actions[bot]@users.noreply.github.com',
               GIT_COMMITTER_NAME='github-actions[bot]',
               GIT_COMMITTER_EMAIL='github-actions[bot]@users.noreply.github.com')
    # Whatever is already on the branch, so earlier runs are kept. The URL carries the
    # token, so nothing here echoes the command.
    parent = ''
    if git(source, 'fetch', '--depth=1', url, EVIDENCE_BRANCH, env=env).returncode == 0:
        parent = git(source, 'rev-parse', 'FETCH_HEAD', env=env).stdout.strip()
    if parent:
        git(source, 'read-tree', parent, env=env)
    else:
        git(source, 'read-tree', '--empty', env=env)
    staged = 0
    for published, local in sorted(files.items()):
        blob = git(source, 'hash-object', '-w', '--', local, env=env)
        if blob.returncode or not blob.stdout.strip():
            continue
        if git(source, 'update-index', '--add', '--cacheinfo',
               f'100644,{blob.stdout.strip()},{published}', env=env).returncode == 0:
            staged += 1
    if not staged:
        return ''
    tree = git(source, 'write-tree', env=env).stdout.strip()
    if not tree:
        return ''
    args = ['commit-tree', tree, '-m', f'Evidence for fuzzing run {run_id}']
    if parent:
        args += ['-p', parent]
    commit = git(source, *args, env=env).stdout.strip()
    if not commit:
        return ''
    pushed = git(source, 'push', url, f'{commit}:refs/heads/{EVIDENCE_BRANCH}', env=env)
    if pushed.returncode:
        # The remote's own words, minus the URL, which has the token in it.
        said = (pushed.stderr or '').replace(url, '<remote>').strip().splitlines()
        print(f'::warning::could not push the evidence branch: '
              f'{said[-1][:120] if said else "no detail"} -- the token needs Contents: '
              f'write. The issues will carry the inline excerpts only.')
        return ''
    print(f'pushed {staged} evidence file(s) to {EVIDENCE_BRANCH}')
    return f'{server}/{slug}/blob/{EVIDENCE_BRANCH}'


def collect_evidence(results, campaigns):
    """published path -> local file, for every campaign that produced a finding."""
    files = {}
    for campaign in sorted(campaigns):
        base = os.path.join(results, 'campaigns', campaign)
        for name in ('FirnessHarnesses.c', 'FirnessHarnesses.h', 'FirnessHarnesses.inf'):
            local = os.path.join(base, 'Firness', name)
            if os.path.isfile(local):
                files[f'{{run}}/{campaign}/harness/{name}'] = local
        for name in ('fuzz.txt', 'crashes.csv', 'run.log'):
            local = os.path.join(base, name)
            if os.path.isfile(local):
                files[f'{{run}}/{campaign}/crash/{name}'] = local
        for local in ev.inputs_for(results, campaign, most=8):
            files[f'{{run}}/{campaign}/inputs/{os.path.basename(local)}'] = local
    return files


def body_for(cand, ref, run_id, run_url, artifact, source, results, base):
    """Everything known about one site, derived from the run -- never per bug class."""
    rows = ev.rows_for(cand, ev.crash_rows(results))
    first = rows[0] if rows else {}
    campaign = (cand.get('protocols') or [first.get('_campaign', '')])[0]
    recorded = first.get('File') or ''
    rel = ev.resolve(source, recorded) if source else None
    line = first.get('Line') or (cand.get('site') or ':').split(':')[-1]
    phase = (first.get('Phase') or '?').strip()
    at_boot = (first.get('AtBoot') or '').strip()

    out = ['| | |', '|---|---|',
           f"| module | `{cand.get('module') or '(unattributed)'}` |",
           f"| bug type | {cand.get('class', '?')} |",
           f"| reported by | `{first.get('Asan Msg') or cand.get('class', '?')}` |",
           f"| site | `{cand.get('site', '?')}` |"]
    if rel:
        out.append(f'| source | `{rel}` line {line} |')
    out += [f"| reports at this site | {cand.get('hits', '?')} |",
            f"| phase | {'on every boot' if at_boot else phase} |",
            f"| reached by | {', '.join(cand.get('protocols') or []) or 'not attributed'} |",
            f"| detail | {first.get('Message') or cand.get('detail', '')} |", '']

    # --- the code -------------------------------------------------------------------
    out += ['### The code at that line', '']
    text = ev.snippet(source, rel, line) if (source and rel) else None
    if text:
        lang = 'c' if rel.endswith(('.c', '.h')) else ''
        out += [f'`{rel}`:', '', f'```{lang}', text, '```', '']
    elif recorded and '/' in recorded:
        out += [f'The build recorded `{recorded}`, which is not in this tree at any '
                f'matching path -- the file is generated, or came from a submodule the '
                f'checkout does not have.', '']
    else:
        out += [f'No source line to show: the report names `{recorded or "?"}`, which is '
                f'the instrumentation reporting against itself rather than a file in this '
                f'tree. The address and the instruction pointer in `detail` are what '
                f'locate it -- resolve the ip against the build\'s DEBUG directory.', '']

    # --- how a testcase got there ---------------------------------------------------
    entries = ev.harness_entries(results, campaign) if campaign else []
    out += ['### How a testcase reached it', '']
    if at_boot:
        out += ['This one fires **on a plain boot**, with no testcase involved. It is not '
                'reached through the harness at all, so there is no input to replay.', '']
    else:
        out += [f'The fuzzer drove the `{campaign}` harness, which is generated against '
                f'that protocol and takes the testcase as its arguments. '
                + (f'It exposes {len(entries)} entry point(s) -- '
                   + ', '.join(f'`{e}`' for e in entries) + ' -- and the fuzzer picks '
                   'among them, so the input below reached one of these and not '
                   'necessarily the same one each time: which entry a given report came '
                   'through is not recorded.'
                   if entries else 'Its entry points could not be read back.'), '']
    if rows:
        out += [f'{len(rows)} raw report row(s) carry this site; the campaign recorded '
                f'`{first.get("ErrorType") or "?"}`.', '']

    # --- the log --------------------------------------------------------------------
    excerpt = ev.log_excerpt(results, campaign, rows) if campaign else None
    if excerpt:
        out += ['<details><summary>The serial log where it reported</summary>', '',
                '```', excerpt, '```', '', '</details>', '']

    # --- the bytes ------------------------------------------------------------------
    found = ev.inputs_for(results, campaign) if campaign else []
    if found and not at_boot:
        dump = ev.hexdump(found[0])
        if dump:
            out += [f'<details><summary>A crashing input for this harness '
                    f'({os.path.getsize(found[0])} bytes)</summary>', '',
                    '```', dump, '```', '', '</details>', '']

    # --- links ----------------------------------------------------------------------
    out += ['### Files', '']
    if base and campaign:
        where = f'{base}/{run_id}/{campaign}'
        out += [f'- harness: [`FirnessHarnesses.c`]({where}/harness/FirnessHarnesses.c)'
                f' — the generated driver the testcase was fed to',
                f'- crash log: [`fuzz.txt`]({where}/crash/fuzz.txt),'
                f' [`crashes.csv`]({where}/crash/crashes.csv)']
        if found:
            out.append('- inputs: ' + ', '.join(
                f'[`{os.path.basename(f)}`]({where}/inputs/{os.path.basename(f)})'
                for f in found))
    else:
        out += ['The harness, the inputs and the logs are in the run artifact '
                f'`{artifact}` -- they could not be published to a branch, so there is '
                'nothing to link here.']
    out += [f'- run: [{run_id}]({run_url}) on `{ref}`',
            f'- everything else: the `{artifact}` artifact', '']

    out += ['### Read this before acting', '',
            'A candidate is something to read, not a confirmed defect.', '',
            '- The **module** is what matters. A report against the harness, or against '
            'a library the firmware never calls, says nothing about this firmware.',
            '- **Reports are not bugs.** The count above is how often this site '
            'reported, not how many defects are here: one site with thousands of hits is '
            'a loop or a scanner, not thousands of problems.',
            '- The offset in `site` moves with every build, so this issue is keyed to '
            'module + bug type + source instead. A later run that finds the same site '
            'again adds nothing here.', '',
            f'<!-- {MARK} {cand.get("id", "")} -->']
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bugs', required=True, help='bugs.json from the run')
    ap.add_argument('--slug', required=True, help='owner/repo to file against')
    ap.add_argument('--results', default='',
                    help='the run results directory, for the campaigns (default: the '
                         'directory holding --bugs)')
    ap.add_argument('--source', default='',
                    help='the fuzzed checkout, read to quote the code at each site')
    ap.add_argument('--no-evidence', action='store_true',
                    help='do not push the harness, inputs and logs to a branch')
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
    results = args.results or os.path.dirname(os.path.abspath(args.bugs))

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

    call(token, 'POST', f'/repos/{args.slug}/labels',
         {'name': LABEL_FINDING, 'color': 'B60205',
          'description': 'A site FuzzUEr attributed to firmware code'}, args.dry_run)

    base = ''
    if not args.no_evidence and not args.dry_run and args.source:
        campaigns = {c for cand in cands for c in (cand.get('protocols') or [])}
        files = {k.replace('{run}', str(args.run_id)): v
                 for k, v in collect_evidence(results, campaigns).items()}
        base = push_evidence(args.source, args.slug, token, args.run_id, files,
                             args.server)

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
                             'body': body_for(cand, args.ref, args.run_id, run_url,
                                              artifact, args.source, results, base),
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

    # No issue for the run as a whole. One was filed at first, listing every finding,
    # and it is the wrong unit: it duplicates what the per-site issues already say,
    # becomes stale the moment one of them is closed, and files a fresh copy of itself on
    # every run -- the one thing in here that is guaranteed to be noise. What the run did
    # is in the artifact and in the job summary.
    print(f'{len(filed)} filed, {len(skipped)} already tracked'
          + (f', {capped} over the cap' if capped else '')
          + (f', {failed} failed' if failed else ''))
    if capped:
        print(f'::warning::{capped} candidate(s) were not filed: max-issues is '
              f'{args.max_issues}. They are the lowest severity of the run and all of '
              f'them are in bugs.md in the {artifact} artifact.')

    out = os.environ.get('GITHUB_OUTPUT')
    if out:
        with open(out, 'a') as handle:
            handle.write('issues=' + ' '.join(r.get('html_url', '') for _, r in filed) + '\n')
            handle.write(f'issues-filed={len(filed)}\n')
            handle.write(f'issues-tracked={len(skipped)}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
