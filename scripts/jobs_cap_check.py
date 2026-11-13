#!/usr/bin/env python3
"""Assert the default campaign concurrency is capped, and that the cap is the one measured.

Measured on a 72-core box, same tree, same image, same budget, same icount setting:

    --jobs  4    4 campaigns in 46m38s = 5.15/h, boots 132-330s, 4 of 4 reached the harness
    --jobs 18    7.76/h gross, but only 10 of 18 ever reached one, so 4.3/h useful

So a quarter of the cores -- 18 here -- produced FEWER results per hour than four, while
appearing to produce more. The CPU-bound stages barely moved (analysis+generation+build
677s mean at 4 against 750-777s at 18) and the box was 91% idle at 18, so this is not a
core shortage; the emulator degrades, boots go from ~230s to past 3000s, and a campaign
whose boot outruns its allowance spends its whole slot producing nothing at all.

On sweep 43454245046 that is what happened: 138 targets at 18-way, and three hours in the
completion rate was tracking to finish about a day past the job timeout -- at which point
GitHub kills the job and NOTHING is triaged, because triage is the last stage.

8 is the knee the two measured points bracket, not an optimum anyone measured directly;
the docstring says so and the comment in action.yml says so. The floor of 4 and the
quarter-of-cores rule are unchanged, so only a box with more than 32 cores sees the cap.
"""

import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ACTION = os.path.join(HERE, '..', 'action.yml')
FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def shell_block():
    """The JOBS resolution out of action.yml, as runnable shell.

    Lifted rather than restated: a copy here would keep passing after the real block
    changed, which is the whole failure mode a check like this exists to prevent.
    """
    text = io.open(ACTION, encoding='utf-8').read()
    start = text.find('        JOBS="${IN_JOBS:-}"')
    if start < 0:
        return None
    end = text.find('\n\n', start)
    body = text[start:end if end > 0 else len(text)]
    return '\n'.join(line[8:] if line.startswith('        ') else line
                     for line in body.splitlines())


def resolve(nproc, given=''):
    """What the action would choose for this core count and this input."""
    body = shell_block()
    if body is None:
        return None
    script = (f'nproc() {{ echo {nproc}; }}\nIN_JOBS="{given}"\n{body}\necho "$JOBS"')
    done = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    out = done.stdout.strip().splitlines()
    return out[-1] if out else None


def main():
    print('the resolution block is still there to read')
    check('action.yml has a JOBS resolution block', shell_block() is not None,
          'if this fails every number below is vacuous')

    print('\nthe quarter-of-cores rule and the floor are unchanged')
    check('a small box still gets the floor', resolve(4) == '4', f'{resolve(4)}')
    check('16 cores give 4', resolve(16) == '4', f'{resolve(16)}')
    check('a quarter is used while it is under the cap', resolve(24) == '6',
          f'{resolve(24)} -- 24/4 = 6, below the cap, so the rule applies unchanged')

    print('\nand the cap binds above it')
    check('32 cores give 8', resolve(32) == '8', f'{resolve(32)}')
    check('the 72-core box this was measured on gives 8', resolve(72) == '8',
          f'{resolve(72)} -- 18 is the value that produced 4.3 useful campaigns/h')
    check('a much larger box is still capped', resolve(256) == '8', f'{resolve(256)}')
    check('the cap is 8 and not some other number',
          resolve(1000) == '8', f'{resolve(1000)}')

    print('\nan explicit request still wins, because a caller may know their box')
    check('an explicit 18 is honoured', resolve(72, '18') == '18', f'{resolve(72, "18")}')
    check('an explicit 1 is honoured', resolve(72, '1') == '1', f'{resolve(72, "1")}')
    check('an explicit value below the floor is not raised to it',
          resolve(4, '2') == '2',
          f'{resolve(4, "2")} -- the floor is a default, not a minimum')

    print('\nthe number is justified where a reader will look')
    text = io.open(ACTION, encoding='utf-8').read()
    comment = text[max(0, text.find('        JOBS="${IN_JOBS:-}"') - 1800):
                   text.find('        JOBS="${IN_JOBS:-}"')]
    check('the comment gives both measured points, not just the conclusion',
          '5.15/h' in comment and '4.3/h' in comment,
          'a cap with no measurement beside it is a number someone will raise again')
    check('it says why it is not a core shortage',
          '91% idle' in comment or 'idle' in comment)
    check('it admits 8 is a bracket, not a measured optimum',
          'knee' in comment,
          'overclaiming here invites the next person to trust it further than it goes')
    check('it names the consequence of getting it wrong',
          'job timeout' in comment and 'triaged' in comment,
          'the cost is not slowness, it is a run killed before triage')
    check('the input description tells a caller the cap exists',
          'cap 8' in text,
          'a caller who passes nothing should not have to read the shell to learn it')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
