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

A registration token is scoped to the thing that issued it, so a token issued for repo A with
a URL for repo B fails inside `config.sh` with `Invalid configuration provided for url` --
which reads like a bad token rather than a wrong target.

An **organisation** URL (`https://github.com/<org>`, no repository) registers one runner for
every repository in the org, which is usually what you want for more than one edk2 tree. One
extra step comes with it: org runners belong to a runner group, and a group can be limited to
selected repositories. If a job sits in "Queued" with an idle runner on the machine, check
Organisation Settings -> Actions -> Runner groups and confirm the repository is allowed.

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
          # No submodules: FuzzUEr makes a worktree of the ref and inits them itself,
          # non-recursively. Do NOT use `recursive` on an edk2 -- it descends into
          # OpenSSL's own submodules (fuzz-corpora, krb5, tlsfuzzer) and the job dies in
          # checkout, gigabytes later, before any fuzzing.

      # FuzzUEr itself, as a directory you can call as an action
      - uses: actions/checkout@v4
        with:
          repository: <you>/FuzzUEr
          path: fuzzuer
          submodules: true        # NOT recursive: one of them is an edk2, see above
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

### Adapting it to your codebase

A platform branch is not stock OVMF, and the knobs below are there so the action fits one
without a change here. Everything is optional; the defaults are what the pipeline uses on
stock edk2.

| input | default | |
|---|---|---|
| `extra-defines` | — | extra `-D` macros, one per line or space separated |
| `extra-pcds` | — | extra `--pcd` overrides, `TokenSpaceGuid.PcdName=Value` |
| `port-from` | the bundled port | a tree that carries its own sanitizer port |
| `port-base` | the port's own base | the commit the port's patches were written against |
| `cores` | a quarter of the box, max 8 | cores per firmware build |
| `smi` | `false` | also fuzz the SMI handlers; implies `smm` |
| `standalone-mm` | `false` | with `smm`, the StandaloneMM model rather than PiSmmCore |
| `bench` | `false` | build the SanBench drivers, which measure the fuzzer |

`extra-defines` and `extra-pcds` are passed **last**, after the defines and PCDs the action
sets itself. edk2 keeps command line macros in a dict and applies `--pcd` in order, so last
wins: these override ours rather than only adding to them. Both are checked for form before
anything is fetched or built, because edk2 rejects a malformed macro name only once
`build.py` is running — several minutes of fetch, submodules, port and BaseTools later.

```yaml
          extra-defines: |
            TPM2_ENABLE=TRUE
            SECURE_BOOT_ENABLE=TRUE
          extra-pcds: |
            gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange=FALSE
```

Quoting survives, so a value with a space in it (`Some.Pcd=L"two words"`) arrives as one
token.

Outputs: `results` (the directory), `bugs`, `reproducers`, `candidates`, `stages`, and from
the filing step `issues`, `issues-filed` and `issues-tracked`.

`candidates` is **empty**, not `0`, on a `qualify-only` run — triage did not run, and "0
candidates" would read as a clean sweep when nothing was fuzzed at all.

`fail-on-findings` is off by default on purpose. A candidate is something to read, not a
confirmed defect, and a sweep that goes red on the first one stops reporting the rest.

---

## Findings come back as issues, in your repository

When triage attributes candidates to firmware code, the action files **one issue per
candidate** in the repository whose tree was fuzzed -- the checkout `source` points at. Not
upstream edk2, and not FuzzUEr: the findings are about your firmware, and a candidate is not
a confirmed defect that upstream asked for. Pointing `source` at a tianocore remote is
refused outright, with the findings left in the artifact.

One issue per site and nothing else: no issue collecting them all, which only duplicates
what they say and goes stale as they are closed. Issues rather than a pull request, because
nothing in a findings report is a change to merge, and several unrelated reports behind one
review get read, or ignored, together.

Each issue is written to be read without opening anything else, and all of it is derived
from the run rather than written per bug class:

| | |
|---|---|
| the code | the lines around the crash site, with the line marked, quoted out of the tree that was fuzzed |
| how it was reached | which protocol's harness the fuzzer drove and which entry points that harness exposes |
| the report | the serial log where it fired, anchored on the instruction pointer |
| the bytes | a hexdump of a crashing input for that harness |
| the files | links to the harness, every kept input, `fuzz.txt` and `crashes.csv` |

A site with no real source file -- the sanitizer's own outline instrumentation, or FWSAN,
which report against themselves -- says so instead of quoting a misleading snippet, and
names the instruction pointer to resolve against the build's DEBUG directory.

Those links point at a branch called `fuzzuer-evidence`, which the action pushes to the
fuzzed repository: a directory per run, holding the harness, the inputs and the logs. An
issue cannot hold a file, so there has to be somewhere for a link to point. Nothing is ever
rewritten -- each run adds a directory -- and the branch is built with git plumbing, so your
working tree and checked-out branch are untouched. If the push fails the issues still get
filed, carrying the inline excerpts and naming the artifact instead.

**Re-running files nothing already open.** Every issue carries its candidate's fingerprint --
module, bug class and source, which is bugs.json's own `id` -- in an HTML comment, and the
next run skips what it finds there, open or closed. Without that a weekly schedule would file
the same eight issues every week. The offset in `site` is deliberately *not* part of the
fingerprint: it moves with every build.

**A clean run files nothing.** That gate is deliberate: a sweep produces candidates, and in
one sweep here 24 of 25 clusters were pattern locations in the harness's own buffer rather
than defects.

Three knobs:

| input | default | |
|---|---|---|
| `open-issues` | `true` | set `false` to leave findings in the artifact only |
| `max-issues` | `50` | stop after this many new issues, worst severity first; the rest are named in the job log and stay in the artifact. `0`: no limit |
| `findings-token` | the job token | needed when `source` is a *different* repository: `Issues: write` and `Contents: write` on that one |

With the job token, the workflow needs `permissions: issues: write` to file, and
`contents: write` to push the evidence branch the issues link into. Shape A (dispatch from
FuzzUEr) passes `secrets.EDK2_TOKEN`, so the same secret that reads a private tree also
carries the findings back to it. Shape B needs nothing extra when the workflow runs in the
edk2 repository itself.

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
| `submodules` | edk2 vendors its dependencies and some are missing. The pipeline inits them itself; if this fails the tree has no git history to init from |
| `port` | the sanitizer integration did not apply to your tree. The detail counts what merged |
| `vendor` | your branch ships something that breaks `AutoGen` — an unresolvable library class |
| `build` | ordinary edk2 build failure, in `build.log` |
| `instrumented` | it built but the modules carry no ASan checks, so a clean sweep would mean nothing |
| `discover` | no protocols found in your tree's headers |
| `image` | the campaign image did not build |
| `detects` | the sanitizer did **not** report a deliberately planted error in your firmware. Treat a clean sweep from a tree that fails this as meaningless |

`port` reporting some count as *resolved* rather than *clean* is normal and not a warning:
it means the integration needed adjusting to your tree, and it did.
