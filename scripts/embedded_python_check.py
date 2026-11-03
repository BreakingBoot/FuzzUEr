"""Parse the Python that is embedded in action.yml and the workflows.

    python3 scripts/embedded_python_check.py

Several steps carry their assertions as a heredoc'd Python script:

    python3 - "$RESULTS" <<'PY'
    import json, ...
    PY

Nothing checked those. `scripts/*.py` are parsed by the Checks workflow and these are
not, even though they are the gates -- a typo in one is found by the job it is supposed to
gate, after that job has spent an hour building firmware, and it reports as the pipeline
failing rather than as the check being broken. The YAML parse in the same workflow does
not see it either: a heredoc body is a string to YAML, valid whatever it contains.

Reports each block's file, step name and first line so a failure points at the source.
"""

import ast
import glob
import sys

try:
    import yaml
except ImportError:                                   # same stance as the YAML parse step
    print('PyYAML absent; skipping the embedded-Python parse')
    sys.exit(0)

# The heredoc word this repository uses for an embedded Python block. Matched on its own
# line so a 'PY' inside the script's own text cannot end the block early.
MARKERS = ("<<'PY'", '<<"PY"', '<<PY')


def blocks(run):
    """Yield (first line number within the step, source) for each heredoc'd script."""
    lines = run.split('\n')
    i = 0
    while i < len(lines):
        if any(m in lines[i] for m in MARKERS) and 'python' in lines[i]:
            start = i + 1
            body = []
            i += 1
            while i < len(lines) and lines[i].strip() != 'PY':
                body.append(lines[i])
                i += 1
            yield start + 1, '\n'.join(body)
        i += 1


def steps_of(doc):
    runs = doc.get('runs')
    if isinstance(runs, dict):                        # an action
        for step in runs.get('steps') or []:
            yield step
    for job in (doc.get('jobs') or {}).values():      # a workflow
        for step in (job or {}).get('steps') or []:
            yield step


def main():
    bad = checked = 0
    for path in ['action.yml'] + sorted(glob.glob('.github/workflows/*.yml')):
        try:
            doc = yaml.safe_load(open(path, encoding='utf-8'))
        except Exception as exc:
            print(f'::error file={path}::{exc}')
            bad = 1
            continue
        for step in steps_of(doc or {}):
            run = step.get('run')
            if not isinstance(run, str):
                continue
            name = step.get('name') or step.get('id') or '<unnamed step>'
            for line, src in blocks(run):
                if not src.strip():
                    print(f'::error file={path}::{name}: an empty PY heredoc')
                    bad = 1
                    continue
                checked += 1
                try:
                    ast.parse(src)
                    print(f'  ok {path}: {name} (block at step line {line}, '
                          f'{len(src.splitlines())} lines)')
                except SyntaxError as exc:
                    print(f'::error file={path}::{name}: embedded Python does not parse '
                          f'at block line {exc.lineno}: {exc.msg}')
                    bad = 1
    if not checked:
        # There are several of these in the tree; finding none means this stopped looking
        # rather than that they are all fine.
        print('::error::found no embedded Python at all -- this check has gone blind')
        return 1
    print(f'  {checked} embedded script(s) parsed')
    return bad


if __name__ == '__main__':
    sys.exit(main())
