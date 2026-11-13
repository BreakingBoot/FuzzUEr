#!/usr/bin/env python3
"""Assert a campaign that produced nothing says why, and that like causes are counted.

Measured on run 43454245046, a 138-campaign sweep. EdkiiVariableLock stopped before it
fuzzed anything, because the generated harness did not compile:

    FirnessHarnesses.c:67:9: error: incompatible integer to pointer conversion passing
    'UINT16' to parameter of type 'CHAR16 *'
    : error F002: Failed to build module

The run reported that campaign in the same breath as a boot that merely ran out of time --
`N produced nothing: A, B, C...` -- and those two need opposite fixes. One is a defect in
the code generator that will repeat on every tree with a CHAR16 * parameter; the other is a
budget or a contention setting. A sweep is exactly where the difference cannot be seen by
eye, because the name of a protocol says nothing about which happened to it.

firness.py refuses with a line that starts `Error: `, in more than twenty places, so the
last such line is the campaign's own account of where it stopped. Grouping by it turns six
names into "nine at this cause, one at that one", which is the actionable shape.
"""

import importlib.util
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Asserting on raw text whose comments explain the defect finds the defect's name in the
    explanation rather than in the statements.
    """
    found = re.search(r'"""', text)
    while found:
        try:
            closing = text.index('"""', found.end())
        except ValueError:
            break
        text = text[:found.start()] + text[closing + 3:]
        found = re.search(r'"""', text)
    kept = []
    for line in text.splitlines():
        if not line.strip().startswith('#'):
            kept.append(line.split('  #')[0])
    return '\n'.join(kept)


def classify(logs):
    """Run fuzz_edk2's own classification over fabricated run.log text.

    The loop lives inside fuzz()'s closure and cannot be imported, so it is lifted out of
    the source and executed on its own. Lifting rather than reimplementing is the point:
    a copy here would keep passing after the real loop changed.
    """
    text = source('fuzz_edk2')
    # From the constants, not from LINE. They used to be handed in from here, and the
    # moment fuzz_edk2 grew a second one the lifted loop raised NameError on a constant
    # this file could not see -- a check that crashes is not a check. Lift them with the
    # loop and there is only ever one spelling.
    start = text.index("        NO_CALL_SITES = 'no target functions")
    end = text.index('        # How good the coverage signal', start)
    body = text[start:end]
    # The loop reads os.listdir(campaigns) and opens each run.log; feed it a directory.
    import tempfile
    holder = tempfile.TemporaryDirectory()
    for name, content in logs.items():
        os.makedirs(os.path.join(holder.name, name), exist_ok=True)
        with open(os.path.join(holder.name, name, 'run.log'), 'w') as handle:
            handle.write(content)
    namespace = {'re': re, 'os': os, 'campaigns': holder.name}
    exec('\n'.join(line[8:] for line in body.splitlines()), namespace)
    holder.cleanup()
    return namespace


def report(silent):
    """Run fuzz_edk2's own grouping over a silent list."""
    text = source('fuzz_edk2')
    start = text.index('            causes = {}')
    end = text.index('            # Degraded, not failed.', start)
    body = '\n'.join(line[12:] for line in text[start:end].splitlines())
    namespace = {'silent': silent}
    exec(body, namespace)
    return '; '.join(namespace['said'])


FUZZED = ('Fuzzed 1200 iteration(s), 340 edge(s), 2 solution(s)\n')
COMPILE = ('generating harness\n'
           'FirnessHarnesses.c:67:9: error: incompatible integer to pointer conversion\n'
           'Error: the harness did not compile -- Build/Firness/DEBUG_CLANGSAN/X64/'
           'Firness.efi is missing or older than the harness just generated.\n')
FVSMALL = ('Error: the firmware volume is too small for the harness and the resize '
           'failed\n')
QUIET = ('booting\n[Bds]UnregisterKeyNotify\n')
ABSENT = ('no target functions were resolved\n')


def main():
    print('a campaign that stopped at a refusal carries that refusal')
    got = classify({'Good': FUZZED, 'Broken': COMPILE})
    silent = got['silent']
    check('the campaign that fuzzed is not called silent',
          [n for n, _ in silent] == ['Broken'], f'{silent}')
    check('the silent entry is a (name, reason) pair, not a bare name',
          silent and isinstance(silent[0], tuple) and len(silent[0]) == 2,
          f'{silent[0] if silent else None} -- a bare name is what loses the cause')
    check('the reason is the campaign\'s own refusal',
          silent and 'did not compile' in silent[0][1], f'{silent}')
    check('the "Error: " prefix is stripped, not repeated',
          silent and not silent[0][1].startswith('Error: '))
    check('the campaign that fuzzed is still counted as fuzzed', got['fuzzed'] == 1)

    print('\nthe last refusal wins, because earlier ones can be recovered from')
    got = classify({'Two': 'Error: first thing\nrecovered\nError: the real stop\n'})
    check('the final Error line is the one kept',
          got['silent'] and got['silent'][0][1] == 'the real stop',
          f'{got["silent"]}')

    print('\na campaign that simply ran out of time says so by saying nothing')
    got = classify({'Quiet': QUIET})
    check('it is still silent', [n for n, _ in got['silent']] == ['Quiet'])
    check('and carries an empty reason rather than an invented one',
          got['silent'][0][1] == '', f'{got["silent"]}')

    print('\nthe other classifications are untouched')
    check('a protocol nothing calls is absent, not silent',
          classify({'Gone': ABSENT})['absent'] == ['Gone'])
    check('and absent does not leak into silent',
          classify({'Gone': ABSENT})['silent'] == [])
    stuck = classify({'Stuck': 'Fuzzed 40 iteration(s), 0 edge(s), 40 solution(s)\n'})
    check('a campaign that never came back out of the call is stuck, not silent',
          stuck['stuck'] == ['Stuck'] and stuck['silent'] == [])
    check('iterations are still summed across campaigns',
          classify({'A': FUZZED, 'B': FUZZED})['iterations'] == 2400,
          f"{classify({'A': FUZZED, 'B': FUZZED})['iterations']}")

    print('\nlike causes are counted together')
    said = report([('A', 'the harness did not compile -- x'),
                   ('B', 'the harness did not compile -- x'),
                   ('C', 'the harness did not compile -- x'),
                   ('D', 'the firmware volume is too small')])
    check('the shared cause is reported once with its count',
          said.count('the harness did not compile') == 1 and '3 at' in said, said)
    check('the lone cause is reported too', '1 at' in said, said)
    check('the biggest group is named first',
          said.index('3 at') < said.index('1 at'), said)
    check('names are shown so a reader can go and look',
          'A' in said and 'D' in said, said)
    check('a long list is elided rather than printed whole',
          '...' in report([(f'C{n}', 'same') for n in range(9)]),
          report([(f'C{n}', 'same') for n in range(9)]))
    check('a campaign with no refusal is described as having none',
          'no refusal in the log' in report([('E', '')]), report([('E', '')]))
    check('a very long refusal is truncated',
          len(report([('F', 'x' * 400)])) < 200, str(len(report([('F', 'x' * 400)]))))

    print('\nthe behaviour is in the code, not only in this check')
    body = code(source('fuzz_edk2'))
    check('the classifier reads the refusal out of the log',
          "startswith('Error: ')" in body)
    check('the report groups rather than listing',
          'causes.setdefault' in body or 'causes[' in body)
    check('the run still degrades rather than failing over it',
          'return WARN, (detail + f\' -- {len(silent)} produced nothing' in body,
          'a campaign that produced nothing must not discard the ones that did')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
