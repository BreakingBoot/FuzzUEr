#!/usr/bin/env python3
"""Assert a campaign that fuzzed without finding its protocol is told from the other two.

Three things were wrong at once in firness.py's boot wait, and all three were measured on
run 43454245046, a live 138-campaign sweep whose first 20 campaigns produced 8 productive
ones.

  1. "The harness was reached" was decided by HARNESS_MARKER and nothing else. The
     generator emits FirnessSanitizer(TRUE) -- which is what prints that marker -- AFTER
     the LocateProtocol early return of every Fuzz<Member>(), so a harness whose protocol
     is not installed boots, starts, fuzzes, counts executions and never prints it.
     EdkiiSmmCpuRendezvous had run 18882 inputs and EdkiiSmmMemoryAttribute 5092 with zero
     markers between them. Because such a guest keeps narrating, the stall check never
     fired either, and the slot was held to the extension ceiling: 3 x 5863s = 17589s, a
     boot failure reported for a campaign that fuzzed.

     Redefining "reached" as "executions >= 1" would fix the clock and destroy the
     evidence, because `no marker AND iterations > 0` is already a perfect signature for
     "the harness ran and LocateProtocol never succeeded". So there are three outcomes
     now, and this file's job is to keep them three. The assertion that matters most is
     the pair at the bottom: two campaigns identical in every number, differing only in
     whether the protocol was located, must not produce the same report.

  2. The stall check asked `now >= soft AND quiet >= stall_grace`, so a guest that died in
     the first minute still held its slot for the whole 5863s allowance -- some 111
     minutes of it, on EfiAcpiTable, for zero iterations. The grace that replaces it is
     asserted against a measurement rather than a guess. The longest silence a boot of
     that sweep came BACK from is 505s, and the longest any campaign reported having sat
     in when its allowance ran out is 1203s -- so a grace anywhere near those is a
     campaign-killer, and the assertion below pins the default above both.

  3. Movement was `size > seen`, which never recovers from a truncation. The emulator
     truncates the serial capture when it restarts the guest, and it does:
     EdkiiFormDisplayEngine's serial went 53087 -> 0 -> 489 -> 12476 while it was writing.
     Past the first truncation every later poll reads as silence.

Why a new file rather than more cases in boot_wait_check.py: that file is a stopwatch. It
drives the wait loop in milliseconds and scores each case on outcome, substring and
elapsed time, and it has no check()/summary convention at all. Half of what is asserted
here is not about time -- it is about whether fuzz_edk2.py's classifier, its detail line
and its verdict still tell the three outcomes apart, which is the silent_campaign_check.py
shape. So the timing cases stay there (extended, not duplicated: this file imports its
lift, its fake processes and its writer thread rather than restating them) and the
discrimination lives here.

Run: python3 scripts/harness_outcome_check.py
"""

import os
import re
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Reused, not restated. boot_wait_check already lifts the wait loop out of firness.py and
# already has the fake processes and the narrating thread; a second copy of either would
# be one more thing to keep in step with the real source.
from boot_wait_check import Alive, Dead, lift, writer
# Likewise: silent_campaign_check already executes fuzz_edk2's classification loop over
# fabricated run.logs, and that loop is exactly what has to keep the buckets apart.
from silent_campaign_check import classify, code, source

FAILED = PASSED = 0

SPACE = lift(['HARNESS_MARKER', 'HARNESS_REACHED', 'HARNESS_UNLOCATABLE',
              'HARNESS_ABSENT', 'UNLOCATABLE_NOTE', 'fuzzer_executions',
              'guest_narrated', 'wait_for_qemu_harness'])
HARNESS_MARKER = SPACE['HARNESS_MARKER']
REACHED = SPACE['HARNESS_REACHED']
UNLOCATABLE = SPACE['HARNESS_UNLOCATABLE']
ABSENT = SPACE['HARNESS_ABSENT']
UNLOCATABLE_NOTE = SPACE['UNLOCATABLE_NOTE']
fuzzer_executions = SPACE['fuzzer_executions']
wait_for_qemu_harness = SPACE['wait_for_qemu_harness']

BOOT = 0.6          # the "boot allowance"
GRACE = 0.25        # quiet for this long past the allowance and it is stuck
LOCATE = 0.25       # running inputs for this long with no marker and it is unlocatable
DEAD = 10.0         # far past every case here, so it never fires by accident
EXTEND = 3          # ceiling = EXTEND x BOOT
TICK = 0.02

CLIENT = b'    (CLIENT) corpus: 15, objectives: 0, executions: 18882, exec/sec: 9.79\n'
GLOBAL = (b'[Broker Heartbeat #0]  (GLOBAL) run time: 30s, clients: 1, corpus: 0, '
          b'objectives: 0, executions: 4242, exec/sec: 0.000\n')


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def truncating_writer(path, every, stop):
    """A guest whose capture is truncated under it, and goes on writing.

    What the emulator does when it restarts the guest. The file is already above every
    size this will reach, so a high-water-mark test sees nothing from here ever again.
    """
    def go():
        n = 0
        while not stop.is_set():
            with open(path, 'ab') as handle:
                handle.write(b'[Bds]Booting\n')
            n += 1
            if n % 3 == 0:
                open(path, 'wb').close()
            time.sleep(every)
    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    return thread


def region(name, opens, closes):
    """The source text between two anchors, or None if either has moved.

    None rather than an exception on purpose. A check that dies on a missing anchor
    reports a traceback and no verdict, which reads from CI as a broken check rather than
    as the behaviour having gone -- and the behaviour having gone is precisely the thing
    being looked for.
    """
    text = source(name)
    start = text.find(opens)
    end = text.find(closes, start + 1) if start >= 0 else -1
    return None if start < 0 or end < 0 else text[start:end]


def announce(outcome, why):
    """What run_qemu_fuzzer prints for an outcome, run from its own source.

    The three sentences are the whole interface between the wait loop and every reader
    downstream -- fuzz_edk2.py classifies a campaign by grepping this text out of run.log
    -- and they live inside run_qemu_fuzzer, which cannot be called without a fuzzer and a
    firmware image. So the branch is lifted out and executed on its own. Restating the
    strings here instead would keep passing after the real ones changed, which is the one
    thing this is for.
    """
    found = region('firness', '        if outcome == HARNESS_REACHED:',
                   '        if outcome != HARNESS_REACHED:')
    if found is None:
        return '<run_qemu_fuzzer no longer announces three outcomes>'
    body = '\n'.join(line[8:] for line in found.splitlines())
    said = []
    names = {'outcome': outcome, 'why': why, 'time': time, 'started_at': time.time() - 42,
             'timeout': 1800, 'HARNESS_REACHED': REACHED,
             'HARNESS_UNLOCATABLE': UNLOCATABLE,
             'print': lambda *a, **k: said.append(' '.join(str(x) for x in a))}
    exec(body, names)
    return '\n'.join(said)


def verdict(**state):
    """fuzz_edk2's detail line and its not-fuzzed verdict, lifted and evaluated.

    It returns from inside the stage closure, so it is wrapped in a function of its own
    here; everything it reads is handed in as a global of the exec namespace.
    """
    found = region('fuzz_edk2', "        detail = (f'{fuzzed}/{planned} campaign(s) fuzzed",
                   '        # Did the guest ever see its testcase?')
    if found is None:
        return None, '<fuzz_edk2 no longer builds a detail line here>'
    body = '\n'.join('    ' + line[8:] for line in found.splitlines())
    names = dict(state)
    exec('def _run():\n' + body + '\n    return None, detail\n', names)
    return names['_run']()


def classified(logs):
    """classify(), with an anchor that moved recorded as a failure, not a traceback."""
    try:
        return classify(logs)
    except Exception as error:
        check('fuzz_edk2 still has a classification loop this can be run against',
              False, f'{error.__class__.__name__}: {error}')
        return {'fuzzed': -1, 'iterations': -1, 'absent': ['?'],
                'silent': [('?', '?')], 'stuck': ['?'], 'unlocatable': None}


def wait(serial, raw, debugcon, **kw):
    """One run of the real wait loop, with this file's millisecond timings."""
    began = time.time()
    kw.setdefault('stall_grace', GRACE)
    kw.setdefault('extend_max', EXTEND)
    kw.setdefault('dead_grace', DEAD)
    kw.setdefault('locate_grace', LOCATE)
    outcome, why = wait_for_qemu_harness(
        kw.pop('process', Alive()), serial, raw, kw.pop('boot_timeout', BOOT),
        debugcon=debugcon, tick=TICK, **kw)
    return outcome, why, time.time() - began


def main():
    root = tempfile.mkdtemp(prefix='harness-outcome-')
    serial = os.path.join(root, 'fuzz.txt')
    raw = os.path.join(root, 'run.txt')
    debugcon = os.path.join(root, 'debugcon.log')

    def blank():
        for path in (serial, raw, debugcon):
            open(path, 'wb').close()

    print('the fuzzer\'s own execution count is readable while the boot is waited on')
    blank()
    check('a run.txt that does not exist yet reads as no executions',
          fuzzer_executions(os.path.join(root, 'nothing.txt')) == 0)
    check('an empty run.txt reads as no executions', fuzzer_executions(raw) == 0)
    open(raw, 'ab').write(GLOBAL)
    check('a GLOBAL broker line is not a client execution count',
          fuzzer_executions(raw) == 0,
          f'{fuzzer_executions(raw)} -- the post-run tally reads CLIENT, so this must too')
    open(raw, 'ab').write(CLIENT)
    check('the CLIENT line is', fuzzer_executions(raw) == 18882,
          f'{fuzzer_executions(raw)}')

    print('\n1. a harness that runs inputs without ever locating its protocol')
    blank()
    open(raw, 'ab').write(CLIENT)
    outcome, why, took = wait(serial, raw, debugcon)
    check('it is not reported as a boot failure', outcome != ABSENT,
          f'{outcome}: {why}')
    check('it is not reported as reached either', outcome != REACHED, f'{outcome}')
    check('it has an outcome of its own', outcome == UNLOCATABLE, f'{outcome}')
    check('the reason names LocateProtocol', UNLOCATABLE_NOTE in why, why)
    check('the reason carries the execution count, so the reader can see it fuzzed',
          '18882' in why, why)
    check('it stops within the locate grace, not at the allowance or the ceiling',
          LOCATE <= took < BOOT, f'{took:.2f}s, allowance {BOOT}s, '
          f'ceiling {BOOT * EXTEND}s')
    UNLOCATABLE_WHY = why

    print('\n...but only once it has run them for long enough to be sure')
    blank()
    open(raw, 'ab').write(CLIENT)
    outcome, why, took = wait(serial, raw, debugcon, locate_grace=10 * BOOT)
    check('executions seen for less than the grace do not decide it',
          outcome == ABSENT, f'{outcome} after {took:.2f}s')
    check('and the guest is then judged on the usual quiet test',
          'last wrote anything' in why, why)

    print('\nthe marker wins over the execution count, in both directions')
    blank()
    open(raw, 'ab').write(CLIENT)
    open(serial, 'ab').write(HARNESS_MARKER + b'\n')
    outcome, why, took = wait(serial, raw, debugcon)
    check('a harness that located its protocol is reached even while it fuzzes',
          outcome == REACHED, f'{outcome}: {why}')
    blank()
    open(raw, 'ab').write(CLIENT + HARNESS_MARKER + b'\n')
    check('the marker on run.txt counts too', wait(serial, raw, debugcon)[0] == REACHED)

    print('\na fuzzer that exits is judged on whether it ran anything')
    blank()
    outcome, why, took = wait(serial, raw, debugcon, process=Dead())
    check('having run nothing, it never reached the harness', outcome == ABSENT, why)
    blank()
    open(raw, 'ab').write(CLIENT)
    outcome, why, took = wait(serial, raw, debugcon, process=Dead())
    check('having run inputs with no marker, it is unlocatable, not a boot failure',
          outcome == UNLOCATABLE, f'{outcome}: {why}')
    check('and it says so at once rather than waiting out a grace it cannot use',
          took < LOCATE, f'{took:.2f}s')

    print('\n2. a guest that has gone completely quiet does not hold its slot')
    blank()
    outcome, why, took = wait(serial, raw, debugcon, boot_timeout=10.0,
                              dead_grace=0.3, stall_grace=GRACE)
    check('it is given up on at the dead grace, not at the allowance',
          outcome == ABSENT and took < 1.0,
          f'{outcome} after {took:.2f}s of a 10s allowance')
    check('and says it stopped rather than that it is slow',
          'has stopped' in why, why)
    blank()
    stop = threading.Event()
    writer(debugcon, TICK, stop)
    time.sleep(TICK * 3)
    outcome, why, took = wait(serial, raw, debugcon, dead_grace=0.3)
    stop.set()
    time.sleep(TICK * 4)
    check('a guest that is still writing is not killed by the dead grace',
          'STILL NARRATING' in why, f'{outcome}: {why}')
    check('the dead grace is independent of the allowance in the source',
          'if quiet >= dead_grace:' in code(source('firness')),
          'it must not be conjoined with now >= soft, which is the defect')
    found = re.search(r'def wait_for_qemu_harness\((.*?)\):', source('firness'), re.S)
    signature = found.group(1) if found else ''
    dead = re.search(r'dead_grace=(\d+)', signature)
    stall = re.search(r'stall_grace=(\d+)', signature)
    check('its default is far above the longest pause a live boot was measured taking',
          bool(dead) and int(dead.group(1)) >= 1500,
          f'{dead.group(1) if dead else "no dead_grace in the signature"}s against the '
          f'1203s EfiBlockIo reported having been quiet, and the 505s '
          f'EdkiiVariablePolicy came back from')
    check('and far above the stall grace, which it must never pre-empt',
          bool(dead) and bool(stall)
          and int(dead.group(1)) >= 4 * int(stall.group(1)), signature)

    print('\n3. a capture that is truncated is movement, not silence')
    blank()
    with open(debugcon, 'wb') as handle:
        handle.write(b'[Bds]' * 1000)          # a high-water mark above all that follows
    stop = threading.Event()
    truncating_writer(debugcon, TICK, stop)
    time.sleep(TICK * 3)
    outcome, why, took = wait(serial, raw, debugcon)
    stop.set()
    time.sleep(TICK * 4)
    check('a guest whose log shrinks keeps its slot to the ceiling',
          'STILL NARRATING' in why,
          f'{outcome}: {why} -- a truncation was read as the guest going quiet')
    check('which takes the whole extension, so it really did keep waiting',
          took >= BOOT * EXTEND, f'{took:.2f}s')
    body = code(source('firness'))
    check('movement is any change in size, not growth', 'if size != seen:' in body)
    check('the high-water-mark test is gone', 'if size > seen:' not in body,
          'size > seen never recovers from a truncation')

    print('\nthe three outcomes survive into fuzz_edk2.py, which is what reports them')
    reached_said = announce(REACHED, '')
    unlocatable_said = announce(UNLOCATABLE, UNLOCATABLE_WHY)
    absent_said = announce(ABSENT, 'the guest last wrote anything 300s ago')
    check('the reached sentence is the one the fuzzed bucket is keyed on',
          'Harness reached' in reached_said, reached_said)
    check('an unlocatable campaign is not announced as reached',
          'Harness reached' not in unlocatable_said, unlocatable_said)
    check('nor as a boot that did not reach the harness',
          'did not reach the harness' not in unlocatable_said, unlocatable_said)
    check('it carries the phrase fuzz_edk2 keys on', UNLOCATABLE_NOTE in unlocatable_said,
          unlocatable_said)
    check('a real boot failure is still announced as one',
          'did not reach the harness' in absent_said, absent_said)
    check('and does not carry that phrase', UNLOCATABLE_NOTE not in absent_said,
          absent_said)

    # Identical in every number. The ONLY difference is the announcement, so an assertion
    # below that passes for one and not the other is about the discriminator and nothing
    # else.
    NUMBERS = 'Fuzzed 18882 iteration(s), 2062 edge(s), 0 solution(s)\n'
    worked = NUMBERS + reached_said + '\n'
    unlocated = NUMBERS + unlocatable_said + '\n'
    got = classified({'Worked': worked, 'Unlocated': unlocated})
    check('the campaign that located its protocol is still counted as fuzzed',
          got['fuzzed'] == 1, f"fuzzed={got['fuzzed']}")
    check('the one that did not is not counted as fuzzed with it',
          got.get('unlocatable') == ['Unlocated'],
          f"unlocatable={got.get('unlocatable')}")
    check('it is not called silent -- it produced plenty, all of it worthless',
          [n for n, _ in got['silent']] == [], f"{got['silent']}")
    check('it is not the protocol-nothing-calls bucket, which is a static absence',
          got['absent'] == [], f"{got['absent']}")
    check('and not the never-came-back-out-of-the-call bucket either',
          got['stuck'] == [], f"{got['stuck']}")
    check('its iterations stay out of the headline total, which claims they were fuzzed',
          got['iterations'] == 18882,
          f"{got['iterations']} -- 18882 is the one campaign that called the protocol")
    check('the two campaigns are not reported the same way',
          got['fuzzed'] == 1 and got.get('unlocatable') == ['Unlocated'])

    print('\nand the run says so in its own words')
    state = dict(fuzzed=1, planned=3, iterations=18882, stability=[],
                 absent=[], stuck=[], silent=[], unlocatable=['Unlocated'],
                 unlocated_runs=18882)
    ok, detail = verdict(**state)
    check('the detail line names the campaigns that never located their protocol',
          'Unlocated' in detail and 'never located their protocol' in detail, detail)
    check('and the iterations they spent, so the number is not simply lost',
          '18882 iteration(s) that never reached the call' in detail, detail)
    check('a run with a working campaign in it is not failed over them', ok is None,
          f'{ok}: {detail}')
    ok, detail = verdict(**dict(state, fuzzed=0, iterations=0))
    check('a run where NOTHING located its protocol fails', ok is False, f'{ok}')
    check('but is not blamed on the boot, which worked',
          'spent its budget without reaching' not in detail, detail)
    check('it points at where the protocol is installed instead',
          'LocateProtocol failed' in detail, detail)
    ok, detail = verdict(**dict(state, fuzzed=0, iterations=0, unlocatable=[],
                                unlocated_runs=0))
    check('a genuine boot failure still reads as one',
          ok is False and 'spent its budget without reaching' in detail, detail)

    print('\nthe two files agree on the phrase they pass between them')
    edk2 = code(source('fuzz_edk2'))
    spelling = re.search(r"NO_PROTOCOL = '([^']+)'", edk2)
    check('fuzz_edk2 defines the phrase it greps for', spelling is not None, edk2[:0])
    check('and it is the one firness.py prints',
          spelling and spelling.group(1) == UNLOCATABLE_NOTE,
          f'{spelling.group(1) if spelling else None!r} vs {UNLOCATABLE_NOTE!r}')
    tested = edk2.find('if NO_PROTOCOL in text:')
    counted = edk2.find('if count and edges:')
    check('the classifier tests it before every count-based guess',
          0 <= tested < counted,
          f'phrase test at {tested}, first count arm at {counted} -- a count-based arm '
          f'reached first would swallow it')
    check('the wait loop reads the execution count, not only the marker',
          'fuzzer_executions(raw)' in body,
          'without it there is no way to tell a running harness from a dead boot')

    for path in (serial, raw, debugcon):
        try:
            os.unlink(path)
        except OSError:
            pass
    os.rmdir(root)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
