# Contributing

Patches are welcome. The main thing to know is what this project treats as evidence.

## Verify, do not assert

Most of what is hard here is telling a working pipeline from one that is quietly doing
nothing, and the repository's history is mostly the second kind. A sanitizer that reports
nothing looks exactly like firmware with no bugs in it; a harness that never reached its
target still burns iterations and still grows coverage; a build flag that moved the narration
to another stream made working firmware report as unbootable. So:

- **A change to the generator or the build needs a real build, not a syntax check.**
  `scripts/check_generation.py` only checks that generated code parses.
  `scripts/build_sweep.sh` links every harness with the real toolchain, and that is the proof.
- **A change to detection needs `scripts/detect_check.py` and `scripts/bench_cases.py`.** The
  first asserts a planted error is still reported *and* that the control case stays silent.
  The second scores all eleven benchmark classes, one boot each.
- **Quote the run.** When a number goes into a README or a doc, say which directory under
  `results/` it came from and what budget it was given. A rate quoted without its budget is
  not comparable to another one. A measurement that disagrees with a stored one is
  interesting; a measurement with no provenance is not usable.
- **Say what failed.** Several of the most useful comments in this tree exist because
  something plausible was tried and did not work. Deleting that history makes somebody redo
  it. If you remove a workaround, say what you checked to show it is no longer needed.

`scripts/verify_all.sh` runs the checks that do not need a fuzzing campaign. Run it before
opening a pull request.

## Running the checks at all

Everything needs the self-hosted runner setup described in
[Requirements](README.md#requirements): Docker, ~100 GB of disk, and a bootstrap that is
hours on a cold machine. There is no lighter path, and a change that cannot be exercised is
hard to review.

`.github/workflows/checks.yml` is the cheap gate: submodules at the commits this repo
records, the two copies of the sanitizer in agreement, every driver script parsing, and
`action.yml` well formed. It still wants a self-hosted runner, because it asks Docker
questions.

## Prose

The documentation is part of the tool and is reviewed the same way.

- Plain language. State the thing, then why it is that way. No marketing, no emoji.
- Record what failed, with enough detail that the next person does not repeat it. "Seen for
  real -- a `--depth=1` clone put the harness generator 40 commits off" is worth more than
  "use full depth".
- Numbers carry their source. Name the sweep, the budget and the runner.
- When you find a claim in the docs that the code contradicts, fix the claim and say in the
  commit message which one you trusted and why. Several numbers in this repository were
  wrong for months because they were copied forward rather than re-measured.

## Pull requests

- One subject per pull request. Several unrelated things behind one review get read, or
  ignored, together.
- The commit message should say what it changes and what it was checked against.
- Note which of the checks above you ran, and which you could not and why. "I could not run
  the benchmark" is a reasonable thing to say; silence about it is not.

## Scope

Three repositories do most of the work and they are submodules, not part of this one:

| | |
|---|---|
| [firness](https://github.com/BreakingBoot/firness) | the harness generator, including the Clang AST passes |
| [uefi_asan](https://github.com/BreakingBoot/uefi_asan) | the sanitizer: libraries, headers, the edk2 patch, and `apply_asan.py` |
| [tsffs](https://github.com/intel/tsffs) | the Simics backend |

A change to any of those belongs there. What belongs here is the pipeline, the action, the
scripts, the checks and the documentation. If you are not sure which, open an issue first and
say what you are trying to change.

## Licensing

Contributions are taken under [LICENSE](LICENSE), MIT. Note that the repository depends on
code with other terms, including GPL-2.0, and that its own copyright line names no legal
entity -- both are described in [THIRD-PARTY.md](THIRD-PARTY.md), and the second is an open
question rather than a settled one.
