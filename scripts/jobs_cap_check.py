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


def declares(name):
    """True when the step that resolves JOBS also declares `name` in its own env."""
    import yaml
    try:
        parsed = yaml.safe_load(io.open(ACTION, encoding='utf-8').read())
        for step in parsed['runs']['steps']:
            if 'JOBS="${IN_JOBS' in str(step.get('run') or ''):
                return name in (step.get('env') or {})
    except Exception:
        return False
    return False


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


def resolve(nproc, given='', timing='application', smm='false', smi='false'):
    """What the action would choose for this core count, input, timing and build.

    The build arguments default OFF, because the cap belongs to an SMM_REQUIRE build and
    the plain build is the one that must stay uncapped. `timing` is still passed so a
    reader can see it does NOT decide the cap: the slow sweep this was measured on ran its
    protocol campaigns at the application timing -- 136 of its 137 generated harness INFs
    are UEFI_APPLICATION -- so what the 2923s boots shared was SMM_REQUIRE, not the dxe
    placement. Keying on dxe also missed `smi` without `dxe`, which builds SMM_REQUIRE just
    the same.
    """
    body = shell_block()
    if body is None:
        return None
    script = (f'nproc() {{ echo {nproc}; }}\nIN_JOBS="{given}"\n'
              f'FIRNESS_HARNESS_TIMING="{timing}"\n'
              f'IN_SMM="{smm}"\nIN_SMI="{smi}"\n{body}\necho "$JOBS"')
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
    check('a quarter is used while it is under the cap',
          resolve(24, smm='true') == '6',
          f'{resolve(24, smm="true")} -- 24/4 = 6, below the cap, so even an SMM build '
          f'takes the quarter-of-cores rule unchanged')

    print('\nand the cap binds above it')
    check('32 cores give 8', resolve(32) == '8', f'{resolve(32)}')
    # smm='true' on every one of these: the cap belongs to an SMM_REQUIRE build, so a
    # cap assertion has to name the build it is asserting. These three read 18, 64 and 250
    # against a plain build, which is the correct answer for a plain build and the reason
    # this check now states the configuration rather than relying on a default.
    check('the 72-core box this was measured on gives 8',
          resolve(72, smm='true') == '8',
          f'{resolve(72, smm="true")} -- 18 is the value that produced 4.3 useful '
          f'campaigns/h')
    check('a much larger box is still capped',
          resolve(256, smm='true') == '8', f'{resolve(256, smm="true")}')
    check('the cap is 8 and not some other number',
          resolve(1000, smm='true') == '8', f'{resolve(1000, smm="true")}')

    print('\nan explicit request still wins, because a caller may know their box')
    check('an explicit 18 is honoured', resolve(72, '18') == '18', f'{resolve(72, "18")}')
    check('an explicit 1 is honoured', resolve(72, '1') == '1', f'{resolve(72, "1")}')
    check('an explicit value below the floor is not raised to it',
          resolve(4, '2') == '2',
          f'{resolve(4, "2")} -- the floor is a default, not a minimum')

    print('\nand it binds only on the workload its numbers came from: an SMM_REQUIRE build')
    check('a plain build is not capped',
          resolve(72) == '18',
          f'{resolve(72)} -- its median boot is 663s against the SMM build\'s 2923s and '
          f'80% of its campaigns reach the harness, so there is no collapse to protect it '
          f'from; this repository measured 31h at 8 jobs against 6.4h at 20 for its own '
          f'four-ref sweep')
    check('a large plain box still takes a quarter', resolve(256) == '64')
    check('an smm build is capped', resolve(72, smm='true') == '8')
    check('an smi build is capped too, because smi implies smm',
          resolve(72, smi='true') == '8',
          'this is the case keying on the dxe timing missed, and it is the configuration '
          'that reached 48%')
    check('and smi is capped even at the application timing',
          resolve(72, timing='application', smi='true') == '8',
          f'{resolve(72, timing="application", smi="true")} -- the 2923s boots WERE '
          f'application-timed; SMM_REQUIRE is what they shared')
    check('the dxe timing is still covered, since dxe requires smi',
          resolve(72, timing='dxe', smi='true') == '8')
    check('the timing alone does not cap a plain build',
          resolve(72, timing='dxe') == '18',
          'dxe cannot occur without smi, so this configuration is unreachable in practice '
          '-- asserted so the cap is seen to key on the build and not on the placement')
    check('the floor still applies to both builds',
          resolve(4, smm='true') == '4' and resolve(4) == '4')
    check('and the cap reads variables this step actually declares',
          declares('IN_SMM') and declares('IN_SMI'),
          'an undeclared name reads as empty, the test never matches, and the cap is a '
          'silent no-op indistinguishable from a working one')

    print('\nthe number is justified where a reader will look')
    text = io.open(ACTION, encoding='utf-8').read()
    # 3200, not 1800: the comment grew when the cap was scoped to one timing mode, and a
    # window sized to the old text silently stops covering the measurements at its head.
    comment = text[max(0, text.find('        JOBS="${IN_JOBS:-}"') - 3200):
                   text.find('        JOBS="${IN_JOBS:-}"')]
    check('the comment gives both measured points, not just the conclusion',
          '5.15/h' in comment and '4.3/h' in comment,
          'a cap with no measurement beside it is a number someone will raise again')
    check('the comment carries BOTH sweeps that justify scoping it',
          '2923' in comment and '663' in comment,
          'the two median boots are the whole reason the cap is conditional; without them '
          'the next reader sees an unexplained exception and makes it unconditional again')
    # The COUNT beside the type, not either alone: both tokens appear elsewhere in this
    # comment, so testing for them separately passed while the sentence that carries the
    # measurement was edited away. The claim is "136 of 137 INFs are UEFI_APPLICATION";
    # that is what overturns the dxe attribution, and it is what has to survive.
    import re as _re
    counted = _re.search(r'136 of (its )?137 generated harness INFs\s*(are|\n[^\n]*are)',
                         comment) is not None
    check('and it records that the cause is the build, not the harness placement',
          counted and 'UEFI_APPLICATION' in comment,
          'this condition keyed on the dxe timing until the INFs were counted -- 136 of '
          '137 are UEFI_APPLICATION -- and a reader who does not know that will re-key it')
    check('the condition itself names the build it keys on',
          'AN SMM_REQUIRE BUILD' in comment,
          'the heading is what a reader scans; without it the exception reads as arbitrary')
    check('and the reach rates beside them',
          '69 reached' in comment and '76 reached' in comment,
          'four times the boot is only half the argument -- half the reach is the other')
    check('it says why it is not a core shortage',
          '91% idle' in comment or 'idle' in comment)
    check('it admits 8 is a bracket, not a measured optimum',
          'knee' in comment,
          'overclaiming here invites the next person to trust it further than it goes')
    check('it names the consequence of getting it wrong',
          'job timeout' in comment and 'triaged' in comment,
          'the cost is not slowness, it is a run killed before triage')
    check('the input description tells a caller the cap exists and when it binds',
          'capped at 8 on an SMM_REQUIRE build only' in text,
          'a caller who passes nothing should not have to read the shell to learn it, and '
          '"cap 8" alone would read as unconditional')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
