# Fuzzing your own EDK2 in CI

This runs FuzzUEr against an edk2 tree you control — a platform branch, a vendor fork, a
release candidate — and tells you which of its protocol and SMI handlers a sanitizer reports
on. Your repository is only ever read: the sanitizer integration comes from FuzzUEr's own
fork and is applied to a throwaway worktree of your ref.

There are two ways in. Pick the first one.

| | you run it from | changes to your edk2 repo | good for |
|---|---|---|---|
| **A — dispatch** | FuzzUEr | none | trying it out, a release check, a one-off |
| **B — your own workflow** | your edk2 repo | one workflow file | every PR, every nightly |

---

## Before either: a runner

FuzzUEr needs a **self-hosted Linux x64 runner**. This is not a preference. A run builds
LLVM-instrumented OVMF and a QEMU that libafl compiles from source; a hosted runner has
neither the disk nor the job time for it.

On a machine with Docker, 16+ cores and ~100 GB free. You also need `sudo`: the runner
installs itself as a systemd service, and your user must be in the `docker` group or
every container step fails with a permission error on the socket.

```bash
git clone --recurse-submodules https://github.com/<you>/FuzzUEr.git
cd FuzzUEr
scripts/setup_gh_runner.sh <registration-token>   # Settings -> Actions -> Runners -> New
scripts/bootstrap_runner.sh                       # the images, once per machine
```

That is a **registration** token, not a personal access token, and it expires about an hour
after it is issued. Copy the `--token` value GitHub shows you, or:

```bash
gh api -X POST repos/<owner>/<repo>/actions/runners/registration-token --jq .token
```

By default the runner registers against whatever this checkout's `origin` points at. Pass a
second argument to attach it elsewhere -- for shape B, that is your edk2 repository:

```bash
scripts/setup_gh_runner.sh <token> https://github.com/acme/edk2-platform
```

A registration token is scoped to one repository, so a token issued for repo A with a URL for
repo B fails inside `config.sh` with `Invalid configuration provided for url` -- which reads
like a bad token rather than a wrong target.

`bootstrap_runner.sh` is idempotent — seconds on a warm machine. The **first** run is hours,
because it builds LLVM 15 from source and a QEMU through libafl. Do it before you need it,
and check `Settings -> Actions -> Runners` shows one **idle** before trusting a schedule: a
workflow with no runner never starts, and there is no failed run to notice either.

---

## A — run it from FuzzUEr, against your private repo

Nothing is added to your edk2 repository.

**1. Give FuzzUEr read access to it.** Only needed if it is private. Make a fine-grained PAT
with **Contents: read** on that repository, and store it in FuzzUEr under
`Settings -> Secrets and variables -> Actions` as **`EDK2_TOKEN`**. A job's built-in
`GITHUB_TOKEN` is scoped to the repository it runs in and cannot read another one, so
without this a private checkout fails with a 404 that looks like a wrong repository name.

**2. Run it.** In FuzzUEr: `Actions -> Fuzz a private EDK2 -> Run workflow`.

```
repository    acme/edk2-platform
ref           my-platform-branch
qualify_only  ✓            <- leave this on for the first run
```

**Leave `qualify_only` on the first time.** It runs every stage except the fuzzing: the port,
the build, the instrumentation check, protocol discovery, the campaign image, and a self test
that provokes real errors in *your* firmware. Minutes instead of hours, and it is how you find
out your tree is wired up correctly before spending a budget on it. Measured on a branch of clean `edk2-stable202605` with one package added: **11 stages, about
8 minutes.** That fixture was temporary, so no artifact for it ships in the repository --
the figure is what to expect, not a stored result.

Turn it off for a real sweep, and expect hours — one tree at a 600-second budget is most of a
day, because the budget is *per target* and a tree has a couple of hundred of them.

---

## B — a workflow in your own edk2 repository

Put this in your edk2 repo as `.github/workflows/fuzz.yml`:

```yaml
name: Fuzz
on:
  workflow_dispatch:
  pull_request:

jobs:
  fuzz:
    runs-on: [self-hosted, linux, x64]
    timeout-minutes: 240
    steps:
      # your tree
      - uses: actions/checkout@v4
        with:
          path: edk2
          fetch-depth: 0          # the ref is resolved out of git history
          submodules: recursive   # edk2 vendors its dependencies

      # FuzzUEr itself, as a directory you can call as an action
      - uses: actions/checkout@v4
        with:
          repository: <you>/FuzzUEr
          path: fuzzuer
          submodules: recursive   # without these the images build empty
          token: ${{ secrets.FUZZUER_TOKEN }}   # only if FuzzUEr is private

      - id: fuzz
        uses: ./fuzzuer
        with:
          source: edk2
          qualify-only: true      # on a PR, prove it still builds and instruments
          # budget: 600           # drop qualify-only and set this for a real sweep
          # targets: EfiHiiFont EfiAcpiTable   # or just a few

      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: fuzzuer
          path: ${{ steps.fuzz.outputs.results }}
```

`uses: ./fuzzuer` runs the action out of the directory you just checked out, and it has to be
done this way. `uses: <you>/FuzzUEr@main` does **not** work: GitHub fetches a referenced
action as an archive with no git history, so its submodules arrive empty -- and the harness
generator, the sanitizer and the Simics backend are three of them. The action detects that
and stops with `firness is empty and this checkout is not a git repository` rather than
building images with nothing in them. Checking it out explicitly also pins the version you
ran, which a floating `@main` does not.

**On pull requests, use `qualify-only: true`.** A fuzzing budget does not belong in a PR gate:
the result is not deterministic, so the same diff can pass and then fail. What *is* worth
gating is that your change still ports, still builds instrumented, and still discovers its
protocols — which is exactly what qualify checks.

### Inputs worth knowing

| input | default | |
|---|---|---|
| `source` | — | required; path to your checkout |
| `ref` | the checked-out commit | tag, branch or SHA |
| `budget` | `600` | seconds **per target** |
| `jobs` | a quarter of the cores | targets fuzzed at once |
| `targets` | everything discovered | space separated protocol names |
| `qualify-only` | `false` | every stage except the fuzzing |
| `smm` | `false` | see below |
| `fail-on-findings` | `false` | fail the step when triage reports candidates |

Outputs: `results` (the directory), `candidates`, `stages`.

`candidates` is **empty**, not `0`, on a `qualify-only` run — triage did not run, and "0
candidates" would read as a clean sweep when nothing was fuzzed at all.

`fail-on-findings` is off by default on purpose. A candidate is something to read, not a
confirmed defect, and a sweep that goes red on the first one stops reporting the rest.

---

## What you get

The step writes a stage table into the job summary, and the artifact holds:

* **`bugs.md`** — the triaged table: module, source location, bug class, hits, and which
  protocol reached it. Start here.
* **`bugs.json`** — the same thing structured, if you want to gate on it.
* **`run.json`** — every stage, its verdict and how long it took.
* **`presence.csv`** — which protocols your firmware actually installs. A protocol the build
  does not install is skipped rather than fuzzed, and this is the record of that decision.
* **`campaigns/<protocol>/`** — per target: `crashes.csv`, the fuzzer's `run.log`, the guest's
  `fuzz.txt`.

### Reading it honestly

A row in `bugs.md` is a **candidate**, not a bug. Three things to check before believing one:

1. **The module column.** Reports attributed to the harness are not findings about your
   firmware.
2. **Whether it is input driven.** `bugs.md` separates reports provoked by a testcase from
   ones that fire on every boot. Both can be real; they mean different things.
3. **One site, many hits.** A single location with thousands of hits is a loop or a scanner,
   not thousands of bugs.

`results/findings.md` in FuzzUEr is a worked example of that triage: five defects in upstream
edk2 written up with mechanism and reachability, and one class of 24 reports recorded as *not*
defects, with the reasoning.

### A campaign that reports zero executions

Usually contention, not a broken harness — the boot competes with every other campaign
starting beside it. Lower `jobs`, or raise `boot-timeout`.

### Executions but zero objectives

Often means the protocol is not installed in your build. Every generated harness calls
`LocateProtocol` and returns **before** reading any input, so an absent protocol still burns
iterations and still grows coverage while calling nothing. Check `presence.csv`.

---

## SMI handlers

`smm: true` builds the firmware with an SMM core, which is what SMI handlers answer. Driving
them is **not yet end to end**: `fuzz_edk2.py --smi` passes through to the analyser correctly,
but the generator needs `smi-function-guid-map.json`, which is built from the campaign image's
compilation database -- and that database is baked once from a build with no SMM modules, so
the handler registrations are not in it and the SMI harness does not generate. Protocol
fuzzing is unaffected. The remaining step is building the campaign image's database with
`SMM_REQUIRE=TRUE`.

The handler count FuzzUEr reports is a lower bound -- discovery matches
registration call sites, so a handler registered via a function pointer stored in a structure
is not seen. Without it the firmware contains no SMM core at all, so an SMI harness has
nothing to answer it — even though the guest is started with `q35,smm=on`. Verified on
`edk2-stable202502`: 0 SMM modules by default, 45 with it.

If an `--smm` build of a newer edk2 stops in `MdeModulePkg/Core/PiSmmCore/PiSmmCore.c` with
`use of undeclared identifier 'IsOverUnderflow'`, update FuzzUEr: that was a trace this port
carried forward which named a local upstream had removed, fixed on 2026-10-19. It is not an
upstream bug -- a clean checkout of those versions has no such trace.

Note what `smm: true` does and does not buy: SMM modules resolve `AsanLibNull`, so they carry
instrumentation whose handlers are no-ops. It gets SMI fuzzing to real SMM code; it does not
give memory-safety *detection* inside SMM, which needs a shadow mapping reachable from SMRAM.

---

## When a stage fails

The run stops at the first failure, deliberately: every stage after a failed one would report
a number that looks like a result and is not one. The stage name tells you where to look.

| stage | what it failing means |
|---|---|
| `fetch` | the ref is not in the checkout and could not be fetched. `fetch-depth: 0`? |
| `submodules` | edk2 vendors its dependencies and some are missing. `submodules: recursive` |
| `port` | the sanitizer integration did not apply to your tree. The detail counts what merged |
| `vendor` | your branch ships something that breaks `AutoGen` — an unresolvable library class |
| `build` | ordinary edk2 build failure, in `build.log` |
| `instrumented` | it built but the modules carry no ASan checks, so a clean sweep would mean nothing |
| `discover` | no protocols found in your tree's headers |
| `image` | the campaign image did not build |
| `detects` | the sanitizer did **not** report a deliberately planted error in your firmware. Treat a clean sweep from a tree that fails this as meaningless |

`port` reporting some count as *resolved* rather than *clean* is normal and not a warning:
it means the integration needed adjusting to your tree, and it did.
