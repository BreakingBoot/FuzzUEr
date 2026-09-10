# Can it still find things, and can it find new ones?

Two different questions, and a campaign that reports nothing answers neither on its own.
`scripts/detect_check.py` runs both.

## Previously known, still found

| check | result |
|---|---|
| ASan detection classes | PASS -- double free, 4 store reports, length-driven overread; control silent |
| network peer PXE boot | PASS -- DHCP, ARP, TFTP transfer complete, image executed |
| bug triage | PASS -- 35 clusters from 2328 rows, 6 filtered as harness, none new against the known set |

The control case matters as much as the rest: a runtime that reports everything is as
broken as one that reports nothing, and only the control tells them apart.

## New ones

Two things were confirmed separately, because "finds new bugs" can mean either.

**A defect class the suite had never covered is detected.** Every earlier self test case is
caught by a load or store check, which only fires in a module compiled with
instrumentation -- and most firmware is not. `BaseMemoryLib` resolves to
`AsanMemoryLibRepStr` platform wide, so an out of bounds `CopyMem` is caught in any DXE
driver either way. Case 5 is that shape, a fixed allocation and a copy sized from the
input, and it reports:

    address 0x7DA0B0A8, size 0xC8, is_write 0x0  in CopyMemWrapper.c

200 bytes read from a 64 byte allocation. This is not a hypothetical shape: it is exactly
what `DevicePathDxe` produced in the 2026-09-09 matrix.

**An unseen finding is surfaced and flagged, not buried.** `bug_report.py --known` diffs
against `results/known-bugs.json`. Verified by hiding one accounted-for cluster and
confirming it comes back as `[NEW]`, with the other 27 still silent -- so the mechanism
fails loudly rather than quietly.

The matrix itself is the standing evidence: it surfaced two findings that were in no prior
known set, ranked them above 60,000 hits of pointer arithmetic, and triage traced one to a
real defect in the generator, now fixed. See `results/matrix-2026-09-09.md`.

## What this does not claim

No deliberate vulnerability was planted in a shipping firmware driver. The positive
control lives in `AsanSelfTest`, which is the module whose documented purpose is to commit
known errors, and is gated behind its own build option. A defect left in `HiiDatabaseDxe`
or `DevicePathDxe` would be a real vulnerability in any image built from this tree.
