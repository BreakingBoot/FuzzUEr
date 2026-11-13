#!/usr/bin/env python3
"""Does the boot wait tell a slow boot from a stuck one?

wait_for_qemu_harness used to be a plain deadline, and the deadline landed in the worst
possible place on the first SMM tree ever fuzzed: all four campaigns were killed 5865s in,
SIXTEEN debug-port lines short of "[Bds]Booting", each at the identical line, while the
detect probe booted the same firmware all the way to the harness. The verdict read "0/4
campaign(s) fuzzed the harness ... the protocol may not be installed", which is what a
boot that stopped dead in early DXE also reads as.

So the allowance became a floor: past it, a guest still writing keeps its slot up to a
ceiling, and a guest that has gone quiet is given up on at once. Six cases, each a few
hundred milliseconds, because every one of them is a property a 2h campaign would
otherwise be the only way to test.

The wait returns an outcome name rather than a bool now, because a harness that runs
inputs its protocol is not installed for is neither reached nor a boot failure. That third
outcome has a check of its own, harness_outcome_check.py; what is asserted here is that
adding it did not move any of the timings below.

The fifth case is the one that matters most. Progress is measured on the GUEST's logs and
not on run.txt, because LibAFL's broker writes a heartbeat into run.txt every 30s whether
the guest moves or not -- count that and every boot looks like it is progressing, the
stall check never fires, and this whole change silently becomes "always wait for the
ceiling".
"""
import ast
import os
import re
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def lift(names):
    """Pull the named top-level definitions out of firness.py and run just those.

    Not an import: firness.py imports matplotlib at module scope, which is not installed
    on a runner and has nothing to do with waiting for a boot. This compiles the real
    source of the real functions, so the check still fails when they change.
    """
    tree = ast.parse(open(os.path.join(HERE, 'firness.py'), encoding='utf-8').read())
    want = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            want.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in node.targets):
            want.append(node)
    missing = set(names) - {getattr(n, 'name', None) or n.targets[0].id for n in want}
    if missing:
        print(f'::error::firness.py no longer defines {", ".join(sorted(missing))} at '
              f'module level; this check has gone blind')
        sys.exit(1)
    space = {'os': os, 're': re, 'time': time, 'print': print}
    exec(compile(ast.Module(body=want, type_ignores=[]), 'firness.py', 'exec'), space)
    return space


SPACE = lift(['HARNESS_MARKER', 'HARNESS_REACHED', 'HARNESS_UNLOCATABLE',
              'HARNESS_ABSENT', 'UNLOCATABLE_NOTE', 'fuzzer_executions',
              'guest_narrated', 'wait_for_qemu_harness'])
HARNESS_MARKER = SPACE['HARNESS_MARKER']
HARNESS_REACHED = SPACE['HARNESS_REACHED']
HARNESS_ABSENT = SPACE['HARNESS_ABSENT']
wait_for_qemu_harness = SPACE['wait_for_qemu_harness']

BOOT = 0.6          # the "boot allowance"
GRACE = 0.25        # quiet for this long past the allowance and it is stuck
EXTEND = 3          # ceiling = EXTEND x BOOT
TICK = 0.02


class Alive:
    """A fuzzer process that is still running."""

    def poll(self):
        return None


class Dead:
    """One that is not."""

    def poll(self):
        return 1


def writer(path, every, stop, chunk=b'SmmCore: dispatch -> Success\n'):
    """Narrate into path until stop is set -- a guest that is still booting."""
    def go():
        while not stop.is_set():
            with open(path, 'ab') as handle:
                handle.write(chunk)
            time.sleep(every)
    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    return thread


def main():
    bad = 0
    root = tempfile.mkdtemp(prefix='boot-wait-')
    serial = os.path.join(root, 'fuzz.txt')
    raw = os.path.join(root, 'run.txt')
    debugcon = os.path.join(root, 'debugcon.log')
    for path in (serial, raw, debugcon):
        open(path, 'wb').close()

    def case(name, want_outcome, want_in, want_min, want_max, **kw):
        nonlocal bad
        began = time.time()
        # DEAD and LOCATE are left at their defaults by every case here except the ones
        # that are about them, and both are far past this file's sub-second timings, so
        # they cannot fire by accident and change what a case is measuring.
        kw.setdefault('dead_grace', 10 * BOOT)
        kw.setdefault('locate_grace', 10 * BOOT)
        outcome, why = wait_for_qemu_harness(
            kw.pop('process', Alive()), serial, raw, BOOT, debugcon=debugcon,
            stall_grace=GRACE, extend_max=EXTEND, tick=TICK, **kw)
        took = time.time() - began
        ok = (outcome == want_outcome and (want_in in why)
              and want_min <= took <= want_max)
        bad |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
        print(f"         outcome={outcome} in {took:.2f}s ({want_min}-{want_max}s) "
              f"why={why[:88] or '-'}")
        return ok

    # 1. The marker on serial is the success path.
    open(serial, 'ab').write(HARNESS_MARKER + b'\n')
    case('the harness marker on serial is seen', HARNESS_REACHED, '', 0, BOOT)
    open(serial, 'wb').close()

    # 2. And on run.txt, which is where the fuzzer prints it.
    open(raw, 'ab').write(HARNESS_MARKER + b'\n')
    case('the harness marker on run.txt is seen', HARNESS_REACHED, '', 0, BOOT)
    open(raw, 'wb').close()

    # 3. A guest that went quiet is given up on AT the allowance, not past it. This is the
    #    ordinary failure -- a protocol the firmware does not install leaves the guest
    #    sitting at the shell -- so it must not cost the grace or the ceiling.
    case('a quiet guest is given up on at the allowance', HARNESS_ABSENT,
         'last wrote anything', BOOT, BOOT + GRACE + 10 * TICK)

    # 4. A guest still narrating keeps its slot past the allowance. 16 lines short.
    stop = threading.Event()
    writer(debugcon, TICK, stop)
    time.sleep(TICK * 3)
    case('a narrating guest is waited for past the allowance', HARNESS_ABSENT,
         'STILL NARRATING', BOOT * EXTEND, BOOT * EXTEND + 20 * TICK)
    stop.set()
    time.sleep(TICK * 4)
    open(debugcon, 'wb').close()

    # 5. THE ONE THAT MATTERS: run.txt growing is not guest progress. A broker heartbeat
    #    every 30s must not keep a stuck boot alive to the ceiling.
    stop = threading.Event()
    writer(raw, TICK, stop, b'[Broker Heartbeat #0] (GLOBAL) executions: 0\n')
    time.sleep(TICK * 3)
    ok = case('a broker heartbeat is not guest progress', HARNESS_ABSENT,
              'last wrote anything', BOOT, BOOT + GRACE + 10 * TICK)
    if not ok:
        print('         run.txt is being counted as progress, which makes the stall '
              'check dead code')
    stop.set()
    time.sleep(TICK * 4)
    open(raw, 'wb').close()

    # 6. FIRNESS_BOOT_EXTEND=1 is the old wall, and it must still diagnose honestly.
    #    With the ceiling equal to the allowance it is the branch order that decides which
    #    message comes out, and the wrong order calls a guest that stopped dead in early
    #    DXE "STILL NARRATING".
    began = time.time()
    outcome, why = wait_for_qemu_harness(Alive(), serial, raw, BOOT, debugcon=debugcon,
                                         stall_grace=GRACE, extend_max=1, tick=TICK,
                                         dead_grace=10 * BOOT, locate_grace=10 * BOOT)
    ok = outcome == HARNESS_ABSENT and 'last wrote anything' in why
    bad |= not ok
    print(f"  [{'OK' if ok else 'FAIL'}] extend_max=1 still calls a quiet guest quiet")
    print(f"         outcome={outcome} in {time.time() - began:.2f}s why={why[:88]}")

    # 7. A fuzzer that died does not get waited on at all.
    case('a dead fuzzer returns at once', HARNESS_ABSENT, 'exited before the harness',
         0, GRACE, process=Dead())

    for path in (serial, raw, debugcon):
        try:
            os.unlink(path)
        except OSError:
            pass
    os.rmdir(root)
    return bad


if __name__ == '__main__':
    sys.exit(main())
