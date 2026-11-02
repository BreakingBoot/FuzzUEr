# Security

This repository is two different security questions wearing one name, and they want
different answers.

1. A vulnerability **in FuzzUEr itself** -- the action, the driver scripts, the harness
   generator, the sanitizer runtime.
2. A finding **produced by FuzzUEr** about somebody's firmware.

## Reporting a vulnerability in FuzzUEr

Use GitHub's private vulnerability reporting on this repository: **Security -> Report a
vulnerability**. That keeps the report out of the public issue tracker while it is being
looked at. If private reporting is not enabled on the fork you are looking at, open an issue
that says only that you have a report and asks for a private channel -- do not put the detail
in it.

Please include the commit or tag, what you ran, and what happened. A reproducer that fits in
a workflow file is worth more than a description.

There is no SLA here, and pretending otherwise would be worse than saying so. This is a
research tool maintained alongside other work.

What is in scope, and worth reporting:

- A path by which a **workflow input** reaches a shell or a build. The action deliberately
  passes every input through the environment rather than interpolating it into a script body,
  because an input is whatever the caller typed; a place where that discipline was missed is a
  real finding.
- A way the action **writes outside what it declares**: anything other than its results
  directory, its scratch directory under `$RUNNER_TEMP`, and -- when `open-issues` is on --
  issues and the `fuzzuer-evidence` branch in the repository whose tree was fuzzed.
- A way to make it **file issues or push a branch somewhere it refuses to**, in particular
  anything the tianocore organisation owns.
- **Token handling**: a token reaching a log, an artifact, a git remote URL that is kept, or
  a repository it was not given for.
- A way the fuzzed tree's **contents** can influence the runner, as against the guest. A
  firmware build is arbitrary code execution by design; a harness build should not be a way
  for the tree under test to reach the host.

What is not in scope:

- That a firmware build runs the tree's own build scripts. That is what a build is. Run this
  on trees you would already have built.
- That campaigns run with Docker access. The pipeline is containers; a runner that can run
  this can run containers.
- That the base image installs software non-interactively, including Intel Simics. That is a
  licensing matter and it is documented in [THIRD-PARTY.md](THIRD-PARTY.md).

## Findings this tool produces are candidates, not vulnerabilities

This is the part that matters most, because the tool is built to generate a lot of them.

**A row in `bugs.md`, and an issue the action files, is a candidate: a place where a
sanitizer reported, attributed to a module.** It is not a confirmed defect, it is not
triaged, and it is not reachable by assumption. `results/findings.md` is the triage of one
sweep: four reports were defects in EDK2, and a class of 24 `fwsan-double-fetch` reports
across 12 modules was not. The giveaway there was the address -- unrelated modules all
reporting the same faulting address, which turned out to be the harness's own argument
buffer. That ratio is normal, not a bad run.

Three things are worth checking before believing one, and
[docs/private-edk2.md](docs/private-edk2.md#reading-it-honestly) says more:

1. **The module column.** A report attributed to the harness is not a finding about your
   firmware, and `results/findings.md` puts it plainly: most sites are the harness rather
   than the firmware. `scripts/bug_report.py` separates them.
2. **Whether it is input driven.** Some sites fire on every boot regardless of the testcase.
   Both kinds can be real; they mean different things.
3. **One site, many hits.** A single location with thousands of hits is a loop or a scanner,
   not thousands of bugs. `results/bugs-qemu.md` is 730 report rows over 25 distinct sites,
   and one of those sites -- `EbcExecuteInstructions` -- accounts for 1629 hits on its own.

`fail-on-findings` is off by default for exactly this reason: a sweep that goes red on the
first candidate stops reporting the rest.

### If a candidate turns out to be real

The action files findings into **your** repository, never upstream, and refuses outright to
file anything at a repository the tianocore organisation owns. That is deliberate: a
candidate list is not a disclosure, and upstream did not ask for it.

If you read a candidate back to source and it holds up -- you can say what the mechanism is
and how an attacker reaches it -- that is the point at which to report it to whoever owns the
code, through their process. For tianocore that is their own security process, not a GitHub
issue. `results/findings.md` in this repository is a worked example of that triage: four
defects in upstream edk2 written up with mechanism and reachability, one class of 24 reports
recorded as *not* defects with the reasoning, and one entry that was written up as an
upstream defect and retracted when it turned out to be this project's own carried patch --
all three kinds kept, so none is triaged twice.

Do not forward a `bugs.md` to a vendor. It will be the last time they read one.

## Limits worth knowing before trusting a clean result

A clean sweep from a broken setup looks exactly like a clean sweep from clean firmware, and
most of the pipeline's stages exist to tell those apart. Even so:

- **Stack memory is not covered.** The build carries `-mllvm -asan-stack=0`, because enabling
  stack instrumentation faults the boot in CpuDxe. A stack overread of any shape is invisible.
- **SMM code is not instrumented.** The SMM and MM module types resolve `AsanLibNull`, so
  their instrumentation handlers are no-ops; SMM needs a shadow mapping reachable from SMRAM
  and that is not wired up. A memory error inside an SMI handler surfaces as an ASSERT, a
  crash or a timeout, not as a sanitizer report.
- **A protocol your build does not install is skipped, not fuzzed.** `presence.csv` is the
  record of that decision. A harness for an absent protocol still burns iterations and still
  grows coverage while calling nothing, so "executions but zero objectives" usually means
  absent rather than clean.
- **An objective count is not a bug count.** Most objectives in a typical campaign are
  crashes and timeouts rather than escalated sanitizer reports.

If the `detects` stage fails, treat every result from that run as meaningless: a sanitizer
that reports nothing is indistinguishable from firmware with no bugs in it, and that stage is
the only thing standing between those two readings.
