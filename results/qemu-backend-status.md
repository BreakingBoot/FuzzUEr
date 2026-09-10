# QEMU backend

Working as of 2026-09-10. It fuzzes protocols and SMI handlers, and produces the same
report a Simics campaign does.

    python3 scripts/fuzz_batch.py -o out --image fuzzuer-qemucur:latest \
        --backend qemu -p EfiUnicodeCollation -t 600 --max-steps 2

## Measured

Twelve protocols, 600s each, 12 at a time:

| protocol | executions | edges | objectives |
|---|---|---|---|
| EfiHiiString | 211 | 874 | 6 |
| EfiBlockIo2 | 203 | 777 | 39 |
| EfiUnicodeCollation | 193 | 652 | 0 |
| EfiFirmwareVolumeBlock | 182 | 524 | 0 |
| EfiHiiFont | 174 | 1070 | 0 |
| EfiSimpleTextOut | 160 | 743 | 0 |
| EfiGraphicsOutput | 159 | 408 | 0 |
| EfiDiskIo2 | 140 | 1647 | 0 |
| EfiSimpleNetwork | 122 | 116 | 0 |
| EfiShell | 117 | 97 | 0 |
| EfiDevicePathUtilities | 57 | 791 | 3 |
| EfiAcpiSdt | 1 | 0 | 1 |

And an SMI handler, with `--smi` against the SMM firmware:

| target | executions | edges | objectives | exec/s |
|---|---|---|---|---|
| SmiTest | 458 | 673 | 0 | 5.29 |

`EfiAcpiSdt` is the one failure and its shape is worth recognising: one execution, one
objective, no corpus. That is a target whose *first* input crashes, so nothing is ever
imported and the client stops with "No entries in corpus". `EfiHiiDatabase` does the same
-- a fuzzable `EFI_HII_HANDLE` is a raw value, and `IsHiiHandleValid` NULL-checks it and
then dereferences it, so any non-null garbage is a `#GP`. That is the harness violating a
caller contract, not a firmware defect, and it is the same class as the device path
`Length` case.

## What it took

Beyond the five plumbing fixes recorded in the commit history, two changes mattered:

**A guest fault has to end the iteration.** Under Simics the fuzzer watches the machine and
sees an exception itself. Nothing watches under libafl-qemu: the handler dumps registers,
dead loops, and the emulator runs on until the timeout. Every crash was recorded as a
timeout, at 300s each. The default exception handler now emits
`LIBAFL_QEMU_COMMAND_END` with `END_CRASH` first, behind `FIRNESS_QEMU_CRASH`. On
EfiHiiDatabase the objective moved from 5m-11s to 11s.

That switch is deliberately not `ASAN_FUZZER`, because the two want opposite settings.
AsanLib's escalation is per image and nothing gates a firmware module's copy, so
`ASAN_FUZZER=qemu` makes boot-time reports end the run before the harness starts. The
exception hook is only reached by an actual fault.

**The seed has to survive.** The corpus was seeded with `os.urandom(64)`. A fuzzer needs
one input that survives before it has anything to mutate, and random bytes do not: a
random handle is a wild pointer. All zeroes takes the NULL path, which the firmware checks.
This one line was the difference between "the target is not properly instrumented" and 848
executions.

## Against Simics

Not a substitute. Simics reaches far more of the firmware per campaign (36132 edges best,
2300 median on the 2026-09-10 matrix) because it boots the real platform firmware; the
QEMU numbers here are OVMF, a smaller image, at 97-1647 edges. What QEMU gives is speed
without a licence, and a second opinion on the same harness. `scripts/bug_report.py` reads
either, because the report path is shared.
