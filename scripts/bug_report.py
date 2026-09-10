"""Turn a campaign's sanitizer reports into a list of bugs.

A matrix produces thousands of report rows and a handful of actual defects. The 2026-09-09
run was 2328 rows, 58 sites and, after triage, zero new firmware bugs -- everything was
either a known site, firmware background, or the harness tripping over an input it had
constructed itself. Doing that triage by hand takes an afternoon and is the step most
likely to be skipped, which is how a solution count gets quoted as a bug count.

This is that step, written down. It does what afl-cmin and the crash-exploration triage do
for a native target, adapted to what a UEFI campaign actually records:

  cluster   reports that differ only by line, or by which protocol provoked them, are one
            bug. Nine adjacent pointer-overflow sites in ExportPackageList are one defect,
            not nine.
  filter    a report attributed to the harness image, to a library linked into the harness
            and never called, or to a known scanner is not a firmware bug.
  rank      what is left is ordered by how much it looks like a memory-safety defect
            rather than a contract violation.

Nothing is dropped silently. Every filtered cluster is printed with the reason, because a
filter that hides a real bug is worse than no filter, and the reasons are the part that
needs review when the firmware changes.

  python3 scripts/bug_report.py -r <matrix dir> [--json out.json] [--show-filtered]
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict

IP_RE = re.compile(r'ip (0x[0-9A-Fa-f]+)')
ADDR_RE = re.compile(r'address (0x[0-9A-Fa-f]+)')
SIZE_RE = re.compile(r'size (0x[0-9A-Fa-f]+)')
WRITE_RE = re.compile(r'is_write (0x[0-9A-Fa-f]+)')

# Lines within this many of each other, in the same file and the same class, are one bug.
# ExportPackageList raises the identical construct at 3277, 3290, 3303 ... 13 lines apart,
# once per Export*Packages call; they are one defect with one fix.
CLUSTER_WINDOW = 32

# Reports that are the harness, not the firmware. Each entry is (match, reason).
HARNESS_SOURCES = [
    ('FirnessHarnesses', 'generated harness source'),
    ('FirnessHelpers', 'generated harness source'),
    ('FirnessMain', 'generated harness source'),
    ('BootScriptSave', 'S3BootScriptLib is linked into the harness, never called, and '
                       'PcdAcpiS3Enable is FALSE, so its state is never initialised'),
    ('UefiHandleParsingLib', 'shell library linked into the harness'),
]

# Firmware code whose reports are an artefact of how it works, not a defect.
KNOWN_ARTEFACTS = [
    ('PeCoffGetEntryPoint', 'PeCoffSearchImageBase scans memory backwards for the PE '
                            'signature, so reading past an allocation is what it does'),
    ('Mem/Page.c', 'the DXE page allocator walking its own poisoned free lists'),
    ('Mem/Pool.c', 'the DXE pool allocator walking its own poisoned free lists'),
    ('VbeShim', 'QemuVideoDxe writes its int10h shim into reserved low memory on purpose'),
]

# The interceptor reports at its own source line, so the file says CopyMemWrapper.c for
# every out-of-bounds copy in the image. Cluster those by caller instead.
INTERCEPTOR_SOURCES = ('CopyMemWrapper', 'SetMemWrapper', 'ScanMem', 'CompareMemWrapper',
                       'ZeroMemWrapper', 'MemLibGuid')


def match_reason(text, table):
    for needle, reason in table:
        if needle in text:
            return reason
    return ''


class Report:
    __slots__ = ('protocol', 'phase', 'module', 'path', 'line', 'asan', 'kind',
                 'message', 'count')

    def __init__(self, row, protocol):
        self.protocol = protocol
        self.phase = (row.get('Phase') or '').strip().lower()
        self.module = (row.get('Module') or '').strip()
        self.path = (row.get('File') or '').strip()
        self.line = (row.get('Line') or '').strip()
        self.asan = (row.get('Asan Msg') or '').strip()
        self.kind = (row.get('ErrorType') or '').strip() or 'ubsan'
        self.message = (row.get('Message') or '').strip()
        try:
            self.count = int(row.get('Count') or 0)
        except ValueError:
            self.count = 0

    @property
    def basename(self):
        return os.path.basename(self.path)

    @property
    def ip(self):
        found = IP_RE.search(self.message)
        return found.group(1) if found else ''

    def line_number(self):
        try:
            return int(self.line, 0)
        except (TypeError, ValueError):
            return -1

    def group_key(self):
        """Reports that could be the same bug, before proximity is considered.

        An interceptor reports at its own source line, so the file is always the wrapper
        and the caller is the only thing that separates two different overflows.
        """
        klass = self.asan or self.kind
        if any(name in self.basename for name in INTERCEPTOR_SOURCES):
            return (self.module, klass, 'via:' + (self.ip or self.basename))
        return (self.module, klass, self.basename)


class Cluster:
    def __init__(self, key):
        self.key = key
        self.reports = []
        self.protocols = set()
        self.lines = set()
        self.phases = set()
        self.hits = 0

    def add(self, report):
        self.reports.append(report)
        self.protocols.add(report.protocol)
        if report.line:
            self.lines.add(report.line)
        self.phases.add(report.phase)
        self.hits += report.count

    @property
    def module(self):
        return self.key[0]

    @property
    def klass(self):
        return self.key[1]

    @property
    def site(self):
        first = self.reports[0]
        nums = sorted(r.line_number() for r in self.reports if r.line_number() >= 0)
        if not nums:
            return first.basename
        if len(set(nums)) == 1:
            return f'{first.basename}:{nums[0]}'
        return f'{first.basename}:{nums[0]}-{nums[-1]} ({len(set(nums))} sites)'

    def severity(self):
        """Higher is more likely to be a memory-safety defect worth chasing.

        The class string decides, and the distinction that matters is which sanitizer
        raised it. `__ubsan_handle_pointer_overflow` contains the word "overflow" and is
        nothing like a heap-buffer-overflow: the first is arithmetic on a pointer, usually
        NULL plus an offset that is never dereferenced, the second is a real access past
        an allocation.
        """
        klass = self.klass.lower()
        ubsan = klass.startswith('__ubsan') or klass == 'ubsan'
        if ubsan:
            return 2 if 'pointer_overflow' in klass else 1
        writing = 'write of' in self.detail().lower()
        if 'heap-buffer-overflow' in klass or 'unknown-crash' in klass:
            return 5 if writing else 4
        if 'use-after-free' in klass or 'double' in klass:
            return 4
        return 3

    def detail(self):
        for report in self.reports:
            if report.message:
                size = SIZE_RE.search(report.message)
                write = WRITE_RE.search(report.message)
                addr = ADDR_RE.search(report.message)
                if size and write:
                    direction = 'write' if int(write.group(1), 16) else 'read'
                    return (f'{direction} of {int(size.group(1), 16)} bytes'
                            f'{" at " + addr.group(1) if addr else ""}')
                return report.message[:90]
        return ''


def load(root):
    """Read every crashes.csv, then merge reports that sit close together.

    Proximity has to be single linkage, not a fixed bucket. ExportPackageList raises the
    same construct every 13 lines from 3277 to 3368; bucketing by line // 32 split that
    one defect across four clusters purely on where the boundaries fell, which is the
    opposite of what this is for.
    """
    groups = defaultdict(list)
    rows = 0
    for protocol in sorted(os.listdir(root)):
        path = os.path.join(root, protocol, 'crashes.csv')
        if not os.path.isfile(path):
            continue
        with open(path, newline='') as handle:
            for row in csv.DictReader(handle):
                report = Report(row, protocol)
                rows += 1
                groups[report.group_key()].append(report)

    clusters = {}
    for base, reports in groups.items():
        runs, current, previous = [], [], None
        for report in sorted(reports, key=lambda r: r.line_number()):
            line = report.line_number()
            if current and previous is not None and line >= 0 and previous >= 0 \
                    and line - previous > CLUSTER_WINDOW:
                runs.append(current)
                current = []
            current.append(report)
            previous = line
        if current:
            runs.append(current)
        for index, run in enumerate(runs):
            key = base if len(runs) == 1 else (base[0], base[1], f'{base[2]}~{index}')
            cluster = Cluster(key)
            for report in run:
                cluster.add(report)
            clusters[key] = cluster
    return clusters, rows


def verdict(cluster, boot_keys, ubiquity):
    """Why a cluster is or is not a candidate firmware bug."""
    sample = cluster.reports[0]
    reason = match_reason(sample.module, HARNESS_SOURCES) or \
        match_reason(sample.path, HARNESS_SOURCES)
    if 'Firness' in sample.module:
        return 'harness', 'raised inside the harness image itself'
    if reason:
        return 'harness', reason
    reason = match_reason(sample.path, KNOWN_ARTEFACTS)
    if reason:
        return 'artefact', reason
    if cluster.key in boot_keys and cluster.phases == {'boot'}:
        return 'background', 'only ever seen during boot, with no input in play'
    if len(cluster.protocols) >= ubiquity:
        # Not a drop. A real defect can be ubiquitous: the ExportPackageList pointer
        # overflow fires under every protocol that touches HII, and it is still a defect.
        # Ubiquity says the input did not provoke it, which changes how it is
        # investigated, not whether it counts.
        return 'ubiquitous', (f'seen under {len(cluster.protocols)} unrelated protocols, '
                              f'so it is not input driven -- review, do not dismiss')
    return 'candidate', ''


def main():
    parser = argparse.ArgumentParser(
        description='Cluster sanitizer reports into bugs and drop the harness ones')
    parser.add_argument('-r', '--root', required=True,
                        help='directory holding one subdirectory per protocol')
    parser.add_argument('--ubiquity', type=int, default=8,
                        help='a cluster under this many protocols or more is background '
                             '(default 8)')
    parser.add_argument('--json', default='', help='write the full result here')
    parser.add_argument('--show-filtered', action='store_true',
                        help='list every filtered cluster, not just the counts')
    parser.add_argument('--known', default='',
                        help='a json list of cluster ids already accounted for; anything '
                             'not in it is reported as new')
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        print(f'no such directory: {args.root}', file=sys.stderr)
        return 2
    clusters, rows = load(args.root)
    if not clusters:
        print(f'no crashes.csv under {args.root}')
        return 1

    boot_keys = {k for k, c in clusters.items() if 'boot' in c.phases}
    buckets = defaultdict(list)
    for cluster in clusters.values():
        kind, reason = verdict(cluster, boot_keys, args.ubiquity)
        buckets[kind].append((cluster, reason))

    known = set()
    if args.known and os.path.isfile(args.known):
        with open(args.known) as handle:
            known = set(json.load(handle))

    print(f'{rows} report row(s) -> {len(clusters)} cluster(s)')
    for kind in ('harness', 'artefact', 'background'):
        print(f'  filtered as {kind:11} {len(buckets[kind]):4}')
    print(f'  not input driven      {len(buckets["ubiquitous"]):4}  (reported below)')
    print(f'  candidates            {len(buckets["candidate"]):4}')

    def cluster_id(cluster):
        return f'{cluster.module}|{cluster.klass}|{cluster.key[2]}'

    print('\n=== candidate bugs, most severe first ===')
    candidates = sorted(buckets['candidate'],
                        key=lambda pair: (-pair[0].severity(), -pair[0].hits))
    if not candidates:
        print('  (none)')
    new_ids = []
    for cluster, _ in candidates:
        ident = cluster_id(cluster)
        flag = ''
        if known:
            flag = '  [NEW]' if ident not in known else '  [known]'
            if ident not in known:
                new_ids.append(ident)
        detail = cluster.detail()
        print(f'  sev{cluster.severity()} x{cluster.hits:<5} {cluster.module:22} '
              f'{cluster.site:34} {cluster.klass:22}{flag}')
        if detail:
            print(f'          {detail}')
        print(f'          protocols: {", ".join(sorted(cluster.protocols)[:6])}'
              f'{" ..." if len(cluster.protocols) > 6 else ""}')

    if buckets['ubiquitous']:
        print('\n=== present regardless of the input, most severe first ===')
        print('    These are in firmware code and were not provoked by a testcase. A real')
        print('    defect can sit here -- confirm by reading the source, not by rerunning.')
        for cluster, reason in sorted(buckets['ubiquitous'],
                                      key=lambda p: (-p[0].severity(), -p[0].hits)):
            print(f'  sev{cluster.severity()} x{cluster.hits:<5} {cluster.module:22} '
                  f'{cluster.site:34} {cluster.klass}')
            print(f'          {len(cluster.protocols)} protocols')

    if args.show_filtered:
        for kind in ('harness', 'artefact', 'background'):
            if not buckets[kind]:
                continue
            print(f'\n=== filtered as {kind} ===')
            for cluster, reason in sorted(buckets[kind], key=lambda p: -p[0].hits):
                print(f'  x{cluster.hits:<5} {cluster.module:22} {cluster.site:34} '
                      f'{cluster.klass}')
                print(f'          {reason}')

    if known:
        print(f'\nnew clusters against the known set: {len(new_ids)}')
        for ident in new_ids:
            print(f'  {ident}')

    if args.json:
        payload = {
            'rows': rows,
            'clusters': len(clusters),
            'candidates': [
                {'id': cluster_id(c), 'module': c.module, 'site': c.site,
                 'class': c.klass, 'hits': c.hits, 'severity': c.severity(),
                 'detail': c.detail(), 'protocols': sorted(c.protocols)}
                for c, _ in candidates],
            'ubiquitous': [
                {'id': cluster_id(c), 'module': c.module, 'site': c.site,
                 'class': c.klass, 'hits': c.hits, 'severity': c.severity(),
                 'protocols': sorted(c.protocols)}
                for c, _ in buckets['ubiquitous']],
            'filtered': {
                kind: [{'id': cluster_id(c), 'module': c.module, 'site': c.site,
                        'class': c.klass, 'hits': c.hits, 'reason': reason}
                       for c, reason in buckets[kind]]
                for kind in ('harness', 'artefact', 'background')},
        }
        with open(args.json, 'w') as handle:
            json.dump(payload, handle, indent=2)
        print(f'\nWrote {args.json}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
