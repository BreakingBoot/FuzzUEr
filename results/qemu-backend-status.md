# QEMU backend: where it actually is

The Simics matrix of 2026-09-10 has no QEMU column, and this says why rather than
presenting a run that would not mean the same thing.

## What now works

A QEMU campaign produces the same artefacts a Simics one does. `crashes.csv` for
`EfiHiiDatabase` came back with 8 rows carrying the improved detail:

    HiiDatabase.efi  Database.c:3368  __ubsan_handle_pointer_overflow
    NullPointerArithmetic: offset applied to a null pointer base 0x0 result 0x5FB0

Five blockers had to go first, and each failed silently:

| blocker | symptom it produced |
|---|---|
| `FIRNESS_OVMF_CODE` never set | the distribution OVMF, no sanitizer, campaign looks clean |
| rom directory never set | the run died before booting |
| `generate_report` skipped on the QEMU branch | no crashes.csv, no coverage |
| `FIRNESS_TIMEOUT` left at the fuzzer's 10s | every input a timeout objective |
| `fuzz_batch.py` forwarded no environment | a host-side setting never arrived |

## What does not work

**No edge coverage is recorded.** `edges: 0` for the whole run. With an empty coverage
map nothing is ever judged interesting, so no input enters the corpus, and the client
stops after one execution:

    Imported 0 input(s) from disk.
    Failed to run launcher: Empty("No entries in corpus. This often implies the
    target is not properly instrumented.")

The harness is reached -- the boot console shows `Loading driver at 0x7D925000 Firness.efi`
and `emu.start()` returns -- and the firmware is right, so this is between the emulator's
edge module and the guest, not a broken target. A run on 2026-09-08 against the
distribution OVMF did record edges (`325/325`), so something about that configuration
collected coverage and this one does not. That is the thing to chase.

## Why there is no QEMU matrix here

At one execution per protocol, 145 campaigns would report boot-phase findings only. Those
are real, but they are the same findings on every protocol, because no input ever ran --
exactly the "solutions are not bugs" trap, dressed up as a second backend. It would look
like corroboration and be nothing of the kind.

The Simics numbers in `matrix-2026-09-10.md` stand on their own. When coverage collection
works, the same `fuzz_batch.py --backend qemu` produces a directly comparable matrix,
because the report path is now shared.
