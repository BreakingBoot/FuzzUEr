#!/usr/bin/env python3
"""File one issue per triage candidate.

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
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

import issue_evidence as ev

# Two parts of a triage key are not stable between runs, and both filed the same bug twice
# before this was handled.
#
# The `~N` on a source is POSITIONAL. bug_report.py splits a module's reports into runs of
# nearby lines and keys them `fwsan~0`, `fwsan~1` ... -- by enumerate() order, over lines
# whose offsets move with every build -- and it drops the suffix entirely when a run finds
# only one. So one site is `fwsan~1` in a run that finds three and plain `fwsan` in a run
# that finds one.
#
# The MODULE comes back empty whenever no map covers the report's address, so the same site
# is `SmbiosDxe.efi|...` on one run and `|...` on the next.
#
# Both are therefore matched loosely: the suffix is stripped, a missing module matches a
# present one, and sibling sites are told apart by COUNT -- a key with three issues already
# filed accounts for three candidates, and only a fourth is new.
TILDE = re.compile(r'~\d+$')

API = 'https://api.github.com'
EVIDENCE_BRANCH = 'fuzzuer-evidence'
MARK = 'fuzzuer-fingerprint:'
LABEL_FINDING = 'fuzzuer-finding'

# GitHub rejects a push containing any single file over 100 MB -- the whole push, not just
# that blob -- and warns at 50 MB. fuzz.txt is the raw libafl capture and it is routinely
# bigger than both: 191 MB on run 42933720452 and 214 MB on 42703964006, and both pushes
# were rejected with "See https://gh.io/lfs". 42703964006 had already filed five issues,
# which are live today with no harness, no input and no log, because losing the push loses
# the evidence for EVERY issue in the run. The runs that pushed 14 files had a 96 MB
# capture and a 0 MB one.
#
# 40 MiB sits under the 50 MB warning, not just under the 100 MB wall: the wall is the
# limit, and the gap is for git's own per-blob overhead, for a capture that grows between
# the stat and the read, and for the day the limit is lowered.
MAX_EVIDENCE_FILE = 40 * 1024 * 1024

# One oversized file is not the only way to lose the push. The branch takes a directory per
# run and this stages three logs, three harness sources and up to eight inputs PER
# CAMPAIGN, so twenty campaigns at the per-file ceiling is a branch nobody can clone. The
# total is spent SMALLEST FIRST, so a 2 KiB harness source is never evicted by a 40 MiB
# capture -- the files that cost almost nothing are the ones a reader opens first.
MAX_EVIDENCE_TOTAL = 80 * 1024 * 1024

# Below this there is no point publishing a capture at all: a reader who follows the link
# and gets 20 KiB of a 200 MB log is worse off than one told the file was dropped, because
# the first looks complete.
MIN_EVIDENCE_CLIP = 64 * 1024

# Head and tail, not tail alone, and the head gets the larger share. Measured on run
# 42933720452's 191 MB DiscoveredSmi capture: it holds 28 distinct `bug_descr=` lines, and
# EVERY ONE of them -- including all 8 ASan findings, the 464 "ASAN MEMORY ACCESS check
# fail" lines among them, which are all inside the first 153 KB -- first appears in the
# first 3.6% of the file. The other 96.4% is the same fwsan-double-fetch sites repeating
# half a million times. So keeping the tail alone loses 8 of the 28 distinct reports, every
# ASan one of them; keeping only lines that match the report markers does not help either,
# because those lines are themselves 137 MB of the 191. The tail is kept at all because the
# end of a run holds whatever stopped it, which the head cannot show.
EVIDENCE_HEAD_SHARE = 0.75

# Room reserved inside the per-file budget for the truncation notice itself, so the
# published size still comes in under the cap once the banner and the elision marker are
# counted. The notices are fixed text plus three decimal numbers.
EVIDENCE_NOTE_ROOM = 2048

# The one rule in this tool that has no exception: a fuzzing finding is never filed at, and
# nothing is ever pushed to, upstream edk2. A candidate list is not a disclosure, and
# sending one unasked is not ours to do.
#
# This check is DELIBERATELY REDUNDANT. action.yml has its own, and that one used to be the
# whole of the enforcement -- a single shell `case` in a YAML file, bypassed by anything the
# pattern did not literally spell: `TianoCore/edk2` (GitHub owner and repo names are
# case-insensitive), `tianocore//edk2`, and any tianocore repository whose name does not
# begin `edk2`, `tianocore/full-disclosure` among them. Nothing downstream looked at --slug
# at all: it went straight into the issues endpoint and into the force-push URL in
# push_evidence.
#
# One enforcement point for a rule like this is one typo away from being none, and this
# script is also run by hand, where there is no YAML in the path at all. So the slug is
# checked here as well, before the POST and before the push, and the two checks agree on
# what counts as upstream: the tianocore ORG on any host, or a tianocore.org host.
#
# Keyed on the ORG, not on a repository name, in both directions. `tianocore/edk2-platforms`
# is upstream and must be refused; `my-tianocore-fork/edk2` and `acme/tianocore-edk2` are
# somebody's fork, which is the whole point of this tool, and must not be.
UPSTREAM_ORGS = ('tianocore',)
UPSTREAM_HOSTS = ('tianocore.org',)
SCHEME = re.compile(r'^[A-Za-z0-9+.-]*://')


def canon_slug(slug):
    """A slug reduced to what identifies the repository, however it was written.

    Accepts what action.yml hands over (`owner/repo`) and also a whole remote URL, because
    this script is run by hand too and `--slug https://github.com/Owner/repo.git` is the
    obvious thing to type. Lowercased, since GitHub resolves owner and repo names without
    regard to case -- that was the bypass -- and with the scheme, any credentials, repeated
    slashes and a trailing `.git` taken off.

    A URL and an scp-form remote are handled separately, because the colon means something
    different in each and treating both alike is its own bypass:
    `ssh://git@ssh.github.com:443/tianocore/edk2.git` -- the remote GitHub documents for
    networks that block port 22 -- has a PORT there, and turning that colon into a
    separator makes `443` the owner and tianocore a mere directory. In scp form,
    `git@host:path`, no port is possible, so the colon is always the separator and a
    numeric first segment is an owner.
    """
    text = (slug or '').strip().lower()
    if '://' in text:
        text = SCHEME.sub('', text)
        text = re.sub(r'^[^/]*@', '', text)        # user:token@host
        text = re.sub(r'^([^/:]*):[0-9]{1,5}', r'\1', text)  # host:port -> host
    else:
        text = re.sub(r'^[^/]*@', '', text)        # scp-form git@host
        text = re.sub(r'^([^/:]*):', r'\1/', text)  # host:owner -> host/owner
    text = re.sub(r'/{2,}', '/', text)             # tianocore//edk2 -> tianocore/edk2
    return re.sub(r'/+$', '', re.sub(r'\.git$', '', re.sub(r'/+$', '', text)))


def upstream_reason(slug):
    """Why this slug is upstream edk2, in words, or '' when it is not.

    The first segment is a HOST when it has a dot in it: GitHub owner names are
    alphanumeric and hyphens only, so no owner can be mistaken for one. Repository names
    *can* contain dots, which is why only the first segment is tested.
    """
    parts = [p for p in canon_slug(slug).split('/') if p]
    host = parts.pop(0) if parts and ('.' in parts[0] or parts[0] == 'localhost') else ''
    owner = parts[0] if parts else ''
    if host and (host in UPSTREAM_HOSTS
                 or any(host.endswith('.' + h) for h in UPSTREAM_HOSTS)):
        return f'{host} is an upstream edk2 host'
    if owner in UPSTREAM_ORGS:
        return f'the {owner} org owns it'
    return ''


def refuse_upstream(slug, what):
    """Stop the process rather than touch upstream edk2 with it.

    It exits instead of returning a status because one of its two callers -- push_evidence
    -- reports every other failure by returning '' and carrying on, which is right for a
    push that did not work and exactly wrong here: a run must not quietly continue after
    being pointed at upstream. Non-zero, so the step that invoked it goes red; the warning
    the action prints when ITS check fires is a deliberate `exit 0`, because findings in
    the artifact beat a failed job, but by the time control is here that check has been
    bypassed and silence is no longer the safe answer.
    """
    reason = upstream_reason(slug)
    if not reason:
        return
    print(f'::error::refusing to {what} at {slug}: {reason}, and fuzzing findings are '
          f'never sent to upstream edk2. If this is a fork, give --slug the fork; if it '
          f'is really upstream, the findings are in the run artifact and disclosing them '
          f'is a decision for a person, not for a scheduled job.')
    sys.exit(3)


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
    """Canonical key -> the issues filed under it, for everything filed before.

    A list per key, not one issue: sibling sites in the same module, class and file share
    a canonical key, and each issue already filed accounts for one of them.

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
            # Trust the issue, not the filter. Asking for ?labels=<name> after that label
            # has been deleted keeps answering with the issues that USED to carry it --
            # measured: 24 returned while the label was 404 and every one of those issues
            # reported labels: []. Counting them would make the filer believe a cleared
            # repository was fully tracked and file nothing, which looks exactly like the
            # dedupe misfiring.
            if not any(l.get('name') == LABEL_FINDING
                       for l in (issue.get('labels') or [])):
                continue
            for line in (issue.get('body') or '').splitlines():
                if MARK in line:
                    key = canon(line.split(MARK, 1)[1].strip().rstrip('->').strip())
                    # A list, not one issue: several sibling sites share a canonical key
                    # and each one filed accounts for one candidate.
                    seen.setdefault(key, []).append(issue)
                    break
        page += 1
    return seen, True


def canon(fingerprint):
    """A triage key reduced to what is actually stable across runs."""
    parts = (fingerprint or '').split('|')
    while len(parts) < 3:
        parts.append('')
    return f'{parts[0]}|{parts[1]}|{TILDE.sub("", parts[2])}'


def canon_of(cand):
    return canon(cand.get('id') or
                 f"{cand.get('module', '')}|{cand.get('class', '')}|{source_of(cand)}")


class Ledger:
    """Which filed issues can account for which candidates.

    Keyed on the canonical key, and matched by count rather than identity, because the
    sibling sites under one key cannot be told apart by anything that survives a rebuild.
    """

    def __init__(self, filed):
        self.filed = filed                      # canonical key -> [issue, ...]
        self.used = {}
        self.by_rest = {}
        for key in filed:
            self.by_rest.setdefault(key.split('|', 1)[1], []).append(key)

    def take_exact(self, key):
        """An issue filed under this very key, or None. Consumes a slot."""
        seen = self.used.get(key, 0)
        if seen < len(self.filed.get(key, [])):
            self.used[key] = seen + 1
            return self.filed[key][seen]
        return None

    def take(self, key):
        """As take_exact, falling back to a key that differs only in attribution."""
        held = self.take_exact(key)
        if held is not None:
            return held, False
        module, rest = key.split('|', 1)
        # An unattributed key has nothing to distinguish it from any other module's site
        # in the same file and class, so prefer one that is also unattributed and only
        # then an attributed sibling. Two DIFFERENT modules reporting the same class from
        # the same file are two bugs, never one.
        options = [o for o in self.by_rest.get(rest, [])
                   if o != key and (not module or not o.split('|', 1)[0])]
        for option in sorted(options, key=lambda o: bool(o.split('|', 1)[0])):
            held = self.take_exact(option)
            if held is not None:
                return held, True
        return None, False


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


def clip_evidence(local, limit, into):
    """What to stage for one evidence file: the file itself, or a clipped copy of it.

    Returns (path, original size, staged size). The path is None when the file cannot be
    read, or when `limit` leaves less room than a capture is worth publishing in.

    A file over the cap must not be dropped silently and must not be published as if it
    were whole, so the copy keeps the head and the tail with the middle elided, and SAYS SO
    in its own first line, with the original byte count. See EVIDENCE_HEAD_SHARE for why
    the head carries the reports and the tail is kept anyway.
    """
    try:
        original = os.path.getsize(local)
    except OSError:
        return None, 0, 0
    if original <= limit:
        return local, original, original
    if limit < MIN_EVIDENCE_CLIP:
        return None, original, 0

    room = limit - EVIDENCE_NOTE_ROOM
    head_room = int(room * EVIDENCE_HEAD_SHARE)
    tail_room = room - head_room
    try:
        with open(local, 'rb') as handle:
            head = handle.read(head_room)
            handle.seek(original - tail_room)
            tail = handle.read(tail_room)
    except OSError:
        return None, original, 0
    # Cut on line boundaries where there are any, so a report is not split down the middle
    # and the elision marker lands on its own line. A file with no newline in the window --
    # an input, not a log -- keeps the raw bytes.
    cut = head.rfind(b'\n')
    if cut > 0:
        head = head[:cut + 1]
    cut = tail.find(b'\n')
    if 0 <= cut < len(tail) - 1:
        tail = tail[cut + 1:]
    elided = original - len(head) - len(tail)

    name = os.path.basename(local)
    marker = (
        f'\n*** FuzzUEr: {elided} bytes elided here -- offsets {len(head)} to '
        f'{original - len(tail)} of the original {original}-byte {name}. ***\n'
        f'*** Everything after this line is the LAST {len(tail)} bytes of that file. ***\n'
        f'\n').encode()

    def banner_for(total):
        """The first thing in the published file, so nobody reads a clip as a capture."""
        return (
            f'*** FuzzUEr TRUNCATED this file to publish it. NOT THE WHOLE CAPTURE. ***\n'
            f'*** original {name}: {original} bytes. published here: {total} bytes. ***\n'
            f'*** GitHub rejects a push holding any file over 100 MB, and the rejection\n'
            f'*** loses the evidence for every issue in the run, so the head and the tail\n'
            f'*** are kept and the middle is elided. The distinct sanitizer reports are at\n'
            f'*** the HEAD: on the 191 MB capture this was measured against, all 28\n'
            f'*** distinct bug_descr lines first appear in the first 3.6% and the rest of\n'
            f'*** the file is the same sites repeating. A count in crashes.csv may\n'
            f'*** therefore exceed what is quoted here.\n'
            f'***\n').encode()

    # The banner states its own output size, and the width of that number is part of it, so
    # settle the two against each other rather than letting the file claim a byte count it
    # does not have. One pass is enough in practice; the loop is there so it cannot lie.
    staged = len(banner_for(0)) + len(head) + len(marker) + len(tail)
    banner = banner_for(staged)
    for _ in range(4):
        settled = len(banner) + len(head) + len(marker) + len(tail)
        if settled == staged:
            break
        staged, banner = settled, banner_for(settled)
    if staged > limit:          # belt and braces: the cap is the one hard promise here
        banner = banner_for(limit)
        tail = tail[len(banner) + len(head) + len(marker) + len(tail) - limit:]
        staged = len(banner) + len(head) + len(marker) + len(tail)

    path = os.path.join(into, name)
    try:
        # Per-file directory: every campaign's capture is called fuzz.txt, so a flat
        # scratch would have the second one overwrite the first's clipped copy.
        os.makedirs(into, exist_ok=True)
        with open(path, 'wb') as handle:
            handle.write(banner)
            handle.write(head)
            handle.write(marker)
            handle.write(tail)
    except OSError:
        return None, original, 0
    return path, original, staged


def push_evidence(source, slug, token, run_id, files, server):
    """Commit the harness, the inputs and the logs to a branch, and return its blob base.

    An issue cannot hold a file, so the evidence has to live somewhere a link can point at.
    It goes on a branch of its own, built with plumbing -- hash-object, update-index,
    commit-tree -- so the caller's working tree and checked-out branch are never touched.
    Each run adds a directory; nothing is ever rewritten.

    Returns '' when it cannot push, which is not fatal: the issues then carry the inline
    excerpts and the artifact, and say the links are missing.
    """
    # Before the early return and before the URL is built, because this is the one failure
    # here that must not be shrugged off: everything else in this function degrades to
    # "no links in the issue", and a force-push to upstream does not degrade to anything.
    refuse_upstream(slug, 'push an evidence branch')
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
    #
    # ls-remote first, because the two ways this can go wrong are indistinguishable
    # afterwards. If the branch exists and we commit without its tip as our parent, the
    # push is a non-fast-forward and the remote rejects it -- which prints "failed to push
    # some refs", exactly what a permission failure prints. Run 42703964006 lost the
    # evidence for five issues to that and reported it as a token scope.
    listed = git(source, 'ls-remote', url, f'refs/heads/{EVIDENCE_BRANCH}', env=env)
    tip = listed.stdout.split()[0] if listed.returncode == 0 and listed.stdout.split() \
        else ''
    parent = ''
    fetched = git(source, 'fetch', '--depth=1', url, EVIDENCE_BRANCH, env=env)
    if fetched.returncode == 0:
        parent = git(source, 'rev-parse', 'FETCH_HEAD', env=env).stdout.strip()
    if tip and parent != tip:
        # --depth=1 is the cheap path, not the required one. A shallow fetch of a single
        # ref can fail where a full one works, and this branch is one small commit per
        # run, so pay for the full fetch rather than lose the evidence.
        fetched = git(source, 'fetch', url, EVIDENCE_BRANCH, env=env)
        if fetched.returncode == 0:
            parent = git(source, 'rev-parse', 'FETCH_HEAD', env=env).stdout.strip()
    if tip and parent != tip:
        why = (fetched.stderr or '').replace(url, '<remote>').strip().splitlines()
        print(f'::warning::the evidence branch is at {tip[:12]} but fetching it '
              f'{"failed" if fetched.returncode else f"gave {parent[:12] or chr(63)}"}; '
              f'committing without it would be a non-fast-forward and the remote would '
              f'reject it{": " + why[-1][:100] if why else ""}. '
              f'The issues will carry the inline excerpts only.')
        return ''
    if parent:
        git(source, 'read-tree', parent, env=env)
    else:
        git(source, 'read-tree', '--empty', env=env)
    # Smallest first, and never more than MAX_EVIDENCE_TOTAL in all. Size order is what
    # makes the budget safe to spend: the harness sources and the inputs are kilobytes and
    # they are what a reader needs, so they are staged before any capture can eat the
    # budget. Ties go to the published path, so two runs of the same results stage the same
    # bytes.
    def by_cost(item):
        try:
            return os.path.getsize(item[1]), item[0]
        except OSError:
            return 0, item[0]

    scratch = os.path.join(os.path.dirname(index), 'clipped')
    staged, budget, dropped = 0, MAX_EVIDENCE_TOTAL, []
    for seen, (published, local) in enumerate(sorted(files.items(), key=by_cost)):
        # The remaining total is as binding as the per-file cap, so clip to whichever is
        # smaller rather than letting the last file decide whether the push survives.
        path, original, kept = clip_evidence(local, min(MAX_EVIDENCE_FILE, budget),
                                             os.path.join(scratch, str(seen)))
        if path is None:
            dropped.append((published, original))
            continue
        blob = git(source, 'hash-object', '-w', '--', path, env=env)
        if blob.returncode or not blob.stdout.strip():
            continue
        if git(source, 'update-index', '--add', '--cacheinfo',
               f'100644,{blob.stdout.strip()},{published}', env=env).returncode == 0:
            staged += 1
            budget -= kept
            if kept < original:
                print(f'clipped {published} from {original} to {kept} byte(s); the file '
                      f'says so in its first line')
    if dropped:
        print('::warning::left {} evidence file(s) off the branch to keep the push under '
              '{} MiB in all: {}. The issues name the artifact, which has them whole.'
              .format(len(dropped), MAX_EVIDENCE_TOTAL // (1024 * 1024),
                      ', '.join(f'{p} ({n} bytes)' for p, n in dropped[:4])))
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
        # The remote's own words, minus the URL, which has the token in it. The LAST line
        # is git's "failed to push some refs" summary or an advice hint -- the same text
        # whatever went wrong. The line that names the cause starts with "!" (the per-ref
        # rejection) or "remote:" (what the server said), so prefer those and do not
        # append a cause of our own: claiming "the token needs Contents: write" when the
        # real reason was a non-fast-forward sent run 42703964006's reader after a
        # permission that was already granted.
        said = [line.strip() for line
                in (pushed.stderr or '').replace(url, '<remote>').strip().splitlines()
                if line.strip()]
        named = [line for line in said
                 if line.startswith('!') or line.startswith('remote:')]
        detail = ' / '.join(named[:2]) if named else (said[-1] if said else 'no detail')
        print(f'::warning::could not push the evidence branch: {detail[:220]} '
              f'(a rejection here is usually a non-fast-forward or a missing Contents: '
              f'write; the line above says which). '
              f'The issues will carry the inline excerpts only.')
        return ''
    print(f'pushed {staged} evidence file(s) to {EVIDENCE_BRANCH}')
    return f'{server}/{slug}/blob/{EVIDENCE_BRANCH}'


def collect_evidence(results, campaigns):
    """published path -> local file, for every campaign that produced a finding.

    Paths only: how much of each file is publishable is push_evidence's business, because
    the budget is shared across every campaign and only the staging loop knows what is
    left. fuzz.txt in particular is the raw libafl capture and is regularly over GitHub's
    100 MB per-file limit -- see MAX_EVIDENCE_FILE and clip_evidence.
    """
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


def named_source(named):
    """('path', 'line') out of triage's "Function -- path:line:col", else (None, None).

    symbolise_offset strips trailing ":0" components, so the tail is any of path,
    path:line, or path:line:col -- take the first numeric component as the line and
    nothing on faith.
    """
    path = (named or '').split(' -- ')[-1].strip()
    bits = path.split(':')
    if not bits or not bits[0] or '/' not in bits[0]:
        return None, None
    line = bits[1] if len(bits) > 1 and bits[1].isdigit() else None
    return bits[0], line


def body_for(cand, ref, run_id, run_url, artifact, source, results, base):
    """Everything known about one site, derived from the run -- never per bug class."""
    rows = ev.rows_for(cand, ev.crash_rows(results))
    first = rows[0] if rows else {}
    campaign = (cand.get('protocols') or [first.get('_campaign', '')])[0]
    recorded = first.get('File') or ''
    rel = ev.resolve(source, recorded) if source else None
    line = first.get('Line') or (cand.get('site') or ':').split(':')[-1]
    # A CPU exception's row has no File: the handler knows the faulting address and
    # nothing else. Triage resolved it against the build's .debug and persisted it, so
    # read that rather than printing "no source line to show" about a site we did name.
    # The routine the address falls in, which firness.py takes from the symbol table.
    # Preferred over anything derived below because it is the one location that was
    # measured right: on run 43280109497 the line table put four SMI handlers in
    # UefiDriverModel.c and the symbol table named SmmSpiHandler, RWVariableHandler and
    # SmmLockBoxHandler. An issue that names the handler is actionable; one that names a
    # driver-binding installer that cannot run during an SMI sends the reader to the wrong
    # file entirely.
    function = (first.get('Function') or '').strip()
    if not rel:
        path, found_line = named_source(cand.get('source'))
        resolved = ev.resolve(source, path) if (source and path) else None
        if resolved:
            rel = resolved
            function = function or (cand.get('source') or '').split(' -- ')[0]
            if found_line:
                line = found_line
    # Last, and only on a site that still has no file. The sanitizer's outline
    # instrumentation reports against itself, so a heap overflow it catches records no
    # path at all -- which on this project is the whole SMI handler class, the findings
    # most worth reading. The routine name survives that, because firness.py takes it from
    # the symbol table, and edk2's style makes a definition findable from a name. The line
    # it gives is the definition, not the access, so `line` is replaced with it and the
    # section heading below says which of the two the reader is looking at.
    #
    # A line of 0 counts as no line, not as line zero. The line table puts one there for an
    # access the compiler could not attribute -- on run 43452927684 that was Font.c:0,
    # Handle.c:0 and Timer.c:0 -- and resolve() still finds the file, so the reader was
    # told "that path is not in this tree", which is both wrong and unhelpful about a path
    # that plainly is. Treat it the same as having no file: the routine is what is left.
    defined_at = False
    located = str(line).isdigit() and int(line) >= 1
    if (not rel or not located) and function:
        found, at = ev.define_site(source, function)
        if found:
            rel, line, defined_at = found, at, True
    phase = (first.get('Phase') or '?').strip()
    at_boot = (first.get('AtBoot') or '').strip()

    out = ['| | |', '|---|---|',
           f"| module | `{cand.get('module') or '(unattributed)'}` |",
           f"| bug type | {cand.get('class', '?')} |",
           f"| reported by | `{first.get('Asan Msg') or cand.get('class', '?')}` |",
           f"| site | `{cand.get('site', '?')}` |"]
    if rel:
        out.append(f'| source | `{rel}` line {line}'
                   + (' (the definition; the report carries no line)' if defined_at else '')
                   + ' |')
    if function:
        out.append(f'| function | `{function}` |')
    out += [f"| reports at this site | {cand.get('hits', '?')} |",
            f"| phase | {'on every boot' if at_boot else phase} |",
            f"| reached by | {', '.join(cand.get('protocols') or []) or 'not attributed'} |",
            f"| detail | {first.get('Message') or cand.get('detail', '')} |", '']

    # --- the code -------------------------------------------------------------------
    out += ['### Where this routine is defined' if defined_at else '### The code at that line',
            '']
    if defined_at:
        out += [f'The sanitizer reported this against `{recorded or "its own instrumentation"}` '
                f'rather than a source file, so there is no crashing line to quote. What it '
                f'does carry is the routine, read out of the symbol table, and this is where '
                f'that routine is defined -- the access is somewhere inside it. The '
                f'instruction pointer in `detail` narrows it further against the build\'s '
                f'DEBUG directory.', '']
    text = ev.snippet(source, rel, line) if (source and rel) else None
    if text:
        lang = 'c' if rel.endswith(('.c', '.h')) else ''
        out += [f'`{rel}`:', '', f'```{lang}', text, '```', '']
    elif rel:
        out += [f'The build resolved this site to `{rel}`, but recorded no usable line '
                f'number for it -- the line table attributes this access to line '
                f'{line}, which is the table saying it does not know. There is a file to '
                f'read and no line in it to point at.', '']
    elif recorded and '/' in recorded:
        out += [f'The build recorded `{recorded}`, which is not in this tree at any '
                f'matching path -- the file is generated, or came from a submodule the '
                f'checkout does not have.', '']
    else:
        named = cand.get('source') or ''
        if named and 'symbolise' not in named:
            out += [f'The build resolved this site to `{named}`, but that path is not in '
                    f'this tree at any matching depth, so there is no file to quote.', '']
        else:
            out += [f'No source line to show: the report names `{recorded or "?"}`, which '
                    f'is the instrumentation reporting against itself rather than a file '
                    f'in this tree. The address and the instruction pointer in `detail` '
                    f'are what locate it -- resolve the ip against the build\'s DEBUG '
                    f'directory.', '']

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
            f'<!-- {MARK} {canon_of(cand)} -->']
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

    # First, ahead of the token check and of every request: --dry-run is no exemption,
    # since a dry run that says "would file 8 issues at tianocore/edk2" is a sentence
    # nobody should ever have to read and argue with.
    refuse_upstream(args.slug, 'file issues')

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

    filed_by_key, listed = already_filed(token, args.slug, args.dry_run)
    if not listed:
        # Filing on top of a list that failed to load would duplicate everything already
        # open, which is worse than filing nothing.
        print('::warning::could not read the existing issues, so nothing was filed -- '
              'the token needs Issues: read/write on this repository')
        return 0
    ledger = Ledger(filed_by_key)
    print(f'{len(cands)} candidate(s); '
          f'{sum(len(v) for v in filed_by_key.values())} issue(s) already filed over '
          f'{len(filed_by_key)} distinct site key(s)')

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

    # Attributed candidates first, against their exact key only. Otherwise an
    # unattributed candidate -- which matches any module's site in the same file and class
    # -- can consume a slot belonging to a sibling that knows its own module, and that
    # sibling is then filed again as if it were new.
    held_by = {}
    for index, cand in enumerate(cands):
        if (cand.get('module') or '').strip():
            found = ledger.take_exact(canon_of(cand))
            if found is not None:
                held_by[index] = (found, False)
    for index, cand in enumerate(cands):
        if index not in held_by:
            found, loose = ledger.take(canon_of(cand))
            if found is not None:
                held_by[index] = (found, loose)

    filed, skipped, failed, capped = [], [], 0, 0
    for index, cand in enumerate(cands):
        held, loose = held_by.get(index, (None, False))
        if held is not None:
            if loose:
                print(f"  #{held.get('number')} already covers {cand.get('site')} "
                      f"(matched without the module: attribution differed between runs)")
            skipped.append((cand, held))
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
