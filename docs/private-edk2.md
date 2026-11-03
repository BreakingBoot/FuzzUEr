# Fuzzing your own EDK2 in CI

This runs FuzzUEr against an edk2 tree you control — a platform branch, a vendor fork, a
release candidate — and tells you which of its protocol and SMI handlers a sanitizer reports
on. Your repository is only ever read: the sanitizer integration comes from FuzzUEr's own
fork and is applied to a throwaway worktree of your ref.

**It builds exactly one platform.** OVMF X64, from `OvmfPkg/OvmfPkgX64.dsc` at
`-a X64 -t CLANGSAN`. No other DSC, architecture or toolchain is built, whatever else your
tree ships. If your branch's `OvmfPkgX64.dsc` does not build, there is nothing here to fuzz.

**It writes back to your repository by default.** `open-issues` defaults to `true`, so when
triage attributes a candidate to firmware code the action files **one issue per candidate**
in the repository whose tree it fuzzed, and pushes a **`fuzzuer-evidence`** branch there for
those issues to link into. Both need granting -- `issues: write` and `contents: write` -- and
Issues have to be enabled on the repository, which GitHub turns off by default on a fork.
Set `open-issues: false` to leave every finding in the run artifact instead. The detail is
under [Findings come back as issues](#findings-come-back-as-issues-in-your-repository).

There are two ways in. Pick the first one.

| | you run it from | added to your edk2 repo | good for |
|---|---|---|---|
| **A — dispatch** | FuzzUEr | no files. Findings still arrive as issues and an evidence branch unless you turn that off | trying it out, a release check, a one-off |
| **B — your own workflow** | your edk2 repo | one workflow file, plus the same findings | every PR, every nightly |

Neither shape modifies the *tree*: the sanitizer port is applied to a throwaway worktree of
your ref and your working branches are untouched. What both shapes add, by default, are
issues and the `fuzzuer-evidence` branch.

---

## Before either: a runner

FuzzUEr needs a **self-hosted Linux x64 runner**. This is not a preference. A run builds
LLVM-instrumented OVMF and a QEMU that libafl compiles from source; a hosted runner has
neither the disk nor the job time for it.

It also has to be a **dedicated** machine, or at least one you are willing to let a sweep
have. The numbers below are not a comfortable minimum; they are what one run uses.

| | | why |
|---|---|---|
| OS | Linux x64 | the only runner platform this is built or tested on |
| Docker | a daemon this user can talk to | every build and every campaign is a container. Your user must be in the `docker` group, or each step fails with a permission error on the socket -- FuzzUEr's own `checks.yml` fails the run outright on `docker version` |
| `sudo` | once, at registration | `setup_gh_runner.sh` installs the runner as a systemd service. Without sudo it registers and then has no service, which looks like total failure |
| cores | 16 or more | nothing enforces a number. `jobs` defaults to a quarter of the cores with a floor of 4, and `cores` (per firmware build) to a quarter capped at 8 -- so below 16 the defaults stop distinguishing machines. The runner these figures come from has 72 |
| RAM | ~2 GiB per concurrent campaign, plus the bootstrap | each campaign boots one QEMU at `FIRNESS_MEMORY`, default 2048 MB. At the default `jobs` on a 72-core box that is 18 guests, so ~36 GiB of guest memory alone. The bootstrap is the other peak: it builds LLVM 15 at `NJOBS=$(nproc)` and clang/lld link steps want roughly 2 GB each, so cap it with `NJOBS=` on a smaller box rather than discovering the OOM killer |
| disk | ~100 GB free | see the breakdown below |
| `python3`, `git` | on the runner itself | the action calls `scripts/fuzz_edk2.py` directly, not inside a container. Standard library only -- no pip install |

Where the ~100 GB goes, measured on this runner rather than estimated:

| | |
|---|---|
| the recursive clone of FuzzUEr | ~24 GB. edk2 vendors OpenSSL, which vendors its own corpora |
| `fuzzuer-base` (LLVM 15 + Simics) | 26.5 GB |
| `fuzzuer-ci` and `fuzzuer-fuzzer` on top of it | ~4 GB more, most layers shared with the base |
| one campaign image **per ref fuzzed** | ~2.5 GB each on top of `fuzzuer-ci` |
| the worktree, build output and results of a run | single-digit GB, under `$RUNNER_TEMP` unless you set `out` |

An earlier figure of ~60 GB appeared alongside the 100 GB one and neither was wrong: 60 GB
was the Docker side once the clone existed. Budget 100 GB and expect Docker to hold
considerably more than that over time: campaign containers are removed as they finish, but
rebuilt images leave untagged layers that only `docker image prune` clears.

One thing worth knowing before you start the bootstrap: the base image downloads and
installs Intel Simics from Intel's download centre, non-interactively, even though the
pipeline fuzzes under QEMU and never starts Simics. There is no build flag to skip it. See
[THIRD-PARTY.md](../THIRD-PARTY.md) before building on a machine where that matters.

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

No *files* are added to your edk2 repository -- no workflow, nothing committed to a branch
you use. Findings still come back to it as issues and a `fuzzuer-evidence` branch, because
that is where they belong; `open-issues: false` turns that off.

**1. Give FuzzUEr access to it.** Make a fine-grained PAT on that repository and store it
in FuzzUEr under `Settings -> Secrets and variables -> Actions` as **`EDK2_TOKEN`**. A job's
built-in `GITHUB_TOKEN` is scoped to the repository it runs in and cannot touch another one,
so without this a private checkout fails with a 404 that looks like a wrong repository name.

The scopes it needs are **not** just read, and this is the one place the old instructions
here were actively harmful:

| scope | for |
|---|---|
| **Contents: write** | checking the tree out *and* pushing the `fuzzuer-evidence` branch the issues link into. Read alone is enough for the checkout, which is why this looked fine |
| **Issues: write** | filing the findings |

`fuzz-private-edk2.yml` passes this same secret as `findings-token`, so the token that reads
your tree is also the one that carries the findings back to it. Granted only
`Contents: read`, the fuzzing runs, the report is produced, and the filing then fails with a
warning in a step log while the job stays green -- the findings are in the artifact, so
nothing goes red. If you genuinely want read-only, set `open-issues: false` as well, so the
failure is a decision rather than a surprise. A public edk2 still needs the token for the
filing; only a fully read-only `qualify-only` run needs no secret at all.

**2. Run it.** In FuzzUEr: `Actions -> Fuzz a private EDK2 -> Run workflow`.

```
repository    acme/edk2-platform
ref           my-platform-branch
qualify_only  ✓            <- leave this on for the first run
```

**Leave `qualify_only` on the first time.** It runs every stage except the fuzzing: the port,
the build, the instrumentation check, protocol discovery, the campaign image, and a self test
that provokes real errors in *your* firmware. Minutes instead of hours, and it is how you find
out your tree is wired up correctly before spending a budget on it. Measured on a branch of
clean `edk2-stable202605` with one package added: **11 stages, about 8 minutes** -- eleven
because `fuzz` and `triage` are skipped out of the pipeline's thirteen. That fixture was temporary, so no artifact for it ships in the repository --
the figure is what to expect, not a stored result.

Turn it off for a real sweep, and expect hours, because the budget is *per target* and a
tree has a couple of hundred of them -- 242 to 250 across the versions measured here. One
tree, everything discovered, at the default 600-second budget has taken between **6.5 and
11.5 hours** in the runs stored under `results/`: `results/fuzz-master-fixed` is 243 targets
in 6.5 h and `results/sweep-v2` is 245 in 10.9 h, both on the same 72-core runner. The
spread is parallelism and boot contention, not the budget -- individual campaigns in those
sweeps ran 16 to 42 minutes of wall clock against budgets of 600 to 900 seconds, because the
budget is counted from the harness being *reached* and the instrumented boot is not free.

---

## B — a workflow in your own edk2 repository

[`examples/fuzzuer.yml`](../examples/fuzzuer.yml) is a complete, working version of this --
dispatch inputs, the weekly schedule, the artifact upload and the job summary. Copy that
one. What follows is the same thing cut down to the parts that matter.

Put this in your edk2 repo as `.github/workflows/fuzz.yml`:

```yaml
name: Fuzz
on:
  workflow_dispatch:
  pull_request:

# Not optional with the default open-issues: true. The action files one issue per candidate
# in THIS repository and pushes a fuzzuer-evidence branch here for them to link into, and
# the job token grants neither by default. Without this the run fuzzes, reports, and then
# fails to file with a warning nobody reads.
permissions:
  contents: write
  issues: write

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
          fetch-depth: 0          # NOT 1: see below
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

**`fetch-depth: 0` on the FuzzUEr checkout, not 1.** `actions/checkout` fetches submodules
shallowly when the parent is shallow, and a shallow submodule fetch can leave a submodule on
its branch tip rather than on the commit FuzzUEr records -- so the job builds code nobody
asked for, and says nothing. Seen for real in FuzzUEr's own CI: a `--depth=1` clone put the
harness generator 40 commits off and the fix under test simply was not there. FuzzUEr checks
for this in `checks.yml`; your repository does not.

`uses: ./fuzzuer` runs the action out of the directory you just checked out. The referenced
form, `uses: <you>/FuzzUEr@<ref>`, also works, and the difference is worth understanding
rather than guessing at:

GitHub delivers a referenced action as an **archive**, which carries no git history and no
submodule contents -- and the harness generator, the sanitizer and the Simics backend are
three of its submodules. `action.yml` handles that itself: it notices the submodules are
empty, clones its own repository with submodules into `~/.cache/fuzzuer-action/<repo>@<ref>`,
pins that clone to the ref you named, asserts it landed there, and runs from it. So the
referenced form is correct; what it costs is that first clone, which is a ~24 GB fetch
cached per repository-and-ref rather than per job. Pin it to a **full 40-character SHA** if
you pin at all: git cannot fetch an abbreviated commit, and the action fails loudly rather
than falling back to the default branch.

Checking FuzzUEr out explicitly, as above, keeps that fetch where you can see it and pins
the version that ran, which a floating `@main` does not. That is the only reason to prefer
it.

An older version of this page, and of the example workflow, said the referenced form was
impossible because the runner downloads an action through an HTTP client with a hard 100
second timeout that FuzzUEr's archive could not meet. That was measured and is false -- the
archive is a few megabytes and arrives in about a second. The empty submodules were always
the real problem.

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
| `fail-on-degraded` | `false` | fail the step when a stage ran but not for every target |
| `boot-timeout` | scales with `jobs` | seconds a target may spend booting to the harness. Raise it before concluding a harness is broken |
| `out` | `$RUNNER_TEMP/fuzzuer-run/results/fuzz-<ref>` | where the artifacts go. The default is **outside the workspace on purpose** -- the pipeline writes a worktree and a docker build context, and putting those where `actions/checkout` owns files left the next job unable to check out at all. The runner wipes `$RUNNER_TEMP` when the job ends, so set this if you want a copy on the box as well as in the artifact |
| `token` | — | used to clone FuzzUEr's **own** repository when GitHub delivered it as an archive, i.e. for any `uses: owner/FuzzUEr@ref`. Only needed when FuzzUEr itself is private |
| `bootstrap` | `true` | build the images if the runner lacks them. Idempotent and seconds on a warm runner; **hours on a cold one**. Set `false` for a runner you prepared yourself with `scripts/bootstrap_runner.sh` |

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
| `bench` | `false` | build the SanBench drivers into the **campaign** firmware, so the benchmark's own protocols get fuzzed. These measure the fuzzer, not your firmware. The `detects` stage scores them on every run regardless of this input |

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

### Outputs

All eight, in the order `action.yml` declares them:

| output | |
|---|---|
| `bugs` | path to `bugs.md`, the triaged table. Empty when triage did not run |
| `reproducers` | directory of the inputs that triggered a finding, collected per protocol. Empty when there were none |
| `results` | the directory holding `run.json`, `bugs.md` and the per-campaign logs. This is what you point `upload-artifact` at |
| `issues` | space separated URLs of the issues this run filed |
| `issues-filed` | how many issues it filed, not counting ones already open |
| `issues-tracked` | how many of this run's candidates already had an issue |
| `candidates` | candidate bugs triage attributed to firmware code |
| `stages` | `passed/total`, counting only stages that ran |
| `degraded` | `true` when a stage ran but not for every target |

`candidates` is **empty**, not `0`, on a `qualify-only` run — triage did not run, and "0
candidates" would read as a clean sweep when nothing was fuzzed at all. The three `issues-*`
outputs come from the filing step, which runs only when `candidates` is neither empty nor
`0`, so on a clean run they are empty too.

`stages` reads `11/11` on a `qualify-only` run and `13/13` on a full one: the pipeline has
thirteen stages and qualify deliberately skips `fuzz` and `triage`, which are not counted
rather than counted as passes.

`fail-on-findings` is off by default on purpose. A candidate is something to read, not a
confirmed defect, and a sweep that goes red on the first one stops reporting the rest.

---

## Findings come back as issues, in your repository

When triage attributes candidates to firmware code, the action files **one issue per
candidate** in the repository whose tree was fuzzed -- the checkout `source` points at. Not
upstream edk2, and not FuzzUEr: the findings are about your firmware, and a candidate is not
a confirmed defect that upstream asked for. A `source` whose `origin` the **tianocore
organisation owns**, or which lives on a `tianocore.org` host, is refused outright, with the
findings left in the artifact -- the owner segment, not the repository name, so
`edk2-platforms` and `edk2-non-osi` are covered too and your own `acme/tianocore-edk2` fork
is not.

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

**A clean run files nothing.** That gate is deliberate: a sweep produces candidates, and most
are not defects. In the sweep triaged in `results/findings.md`, four reports were defects in
EDK2 and a class of 24 was not -- unrelated modules all reporting the same faulting address,
which turned out to be the harness's own argument buffer.

Three knobs:

| input | default | |
|---|---|---|
| `open-issues` | `true` | set `false` to leave findings in the artifact only |
| `max-issues` | `50` | stop after this many new issues, worst severity first; the rest are named in the job log and stay in the artifact. `0`: no limit |
| `findings-token` | the job token | needed when `source` is a *different* repository: `Issues: write` and `Contents: write` on that one |

With the job token, the workflow needs **both** grants, and neither is a default:

```yaml
permissions:
  issues: write      # to file
  contents: write    # to push the fuzzuer-evidence branch the issues link into
```

Shape A (dispatch from FuzzUEr) passes `secrets.EDK2_TOKEN` as `findings-token`, so the same
secret that reads a private tree also carries the findings back to it -- which is why that
PAT needs `Issues: write` and `Contents: write`, not the `Contents: read` this page used to
ask for. Shape B needs no secret, but it does need the `permissions:` block above: a
workflow that omits it runs with the repository's default grants, which do not include
issues.

**Issues also have to be enabled on the repository.** GitHub turns them off by default on a
fork, and a fork is exactly what this tool gets pointed at. The action checks before it
posts and says so, because without the check every `POST` comes back 410 while the issue
*listing* still answers 200 with an empty array -- so nothing earlier in the run gives it
away. Settings -> General -> Features -> Issues.

None of these failures turns the job red. Findings in the artifact beat a red job, so a
filing that goes nowhere is a warning in a step log; `issues-filed` reading `0` with a
non-zero `candidates` is the signal to look.

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

`results/findings.md` in FuzzUEr is a worked example of that triage: four defects in upstream
edk2 written up with mechanism and reachability, one class of 24 reports recorded as *not*
defects with the reasoning, and one entry retracted when a supposed upstream defect turned out
to be FuzzUEr's own carried patch. See also [SECURITY.md](../SECURITY.md) on what a candidate
is and is not.

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

Set `smm: true` to get an SMM core at all. `SMM_REQUIRE` defaults to FALSE in
`OvmfPkgX64.dsc`, so a default build contains no SMM core and no handlers -- even though the
guest is started with `q35,smm=on`, which means the machine has SMM and the firmware does
not use it. Verified on `edk2-stable202502`: 0 SMM modules by default, 45 with it.

The handler count FuzzUEr reports is a **lower bound** either way, and that is independent of
`smm`: discovery is static analysis of the source, and it matches registration call sites, so
a handler registered through a function pointer held in a structure is not found. A tree with
more handlers than this reports is expected, not a defect.

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
| `ready` | the runner has no campaign image or no `fwbuild-stack` container. Run `scripts/bootstrap_runner.sh`, or leave `bootstrap: true` |
| `fetch` | the ref is not in the checkout and could not be fetched. `fetch-depth: 0`? |
| `submodules` | edk2 vendors its dependencies and some are missing. The pipeline inits them itself; if this fails the tree has no git history to init from |
| `port` | the sanitizer integration did not apply to your tree. The detail counts what merged |
| `vendor` | your branch ships something that breaks `AutoGen` — an unresolvable library class |
| `sync` | the ported tree could not be copied into the builder container, or arrived without an `OvmfPkg/OvmfPkgX64.dsc`. A tree with no OVMF X64 platform has nothing for this action to build |
| `build` | ordinary edk2 build failure, in `build.log` |
| `instrumented` | it built but the modules carry no ASan checks, so a clean sweep would mean nothing |
| `discover` | no protocols found in your tree's headers |
| `image` | the campaign image did not build |
| `detects` | the sanitizer did **not** report a deliberately planted error in your firmware. Treat a clean sweep from a tree that fails this as meaningless |

`port` reporting some count as *resolved* rather than *clean* is normal and not a warning:
it means the integration needed adjusting to your tree, and it did.
