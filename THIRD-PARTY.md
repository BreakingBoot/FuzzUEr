# Third-party code and licences

FuzzUEr's own code is MIT, in [LICENSE](LICENSE). On its own it does nothing: the
harness generator, the sanitizer, both fuzzing backends and the firmware under test are
other people's repositories, pulled in as eight submodules, and more is fetched during the
image build. Those carry licences that are not MIT, and one of them is GPL-2.0.

This file is a map of what arrives and under what terms. It is **not legal advice**, and it
is not a substitute for reading the licences it names. Where something could not be verified
from a checkout on disk, that is said rather than assumed.

## A note on FuzzUEr's own LICENSE

The MIT text reads `Copyright (c) 2024 FuzzUEr`. "FuzzUEr" is the name of this tool, not a
person or an organisation that can hold a copyright. A copyright line that names no legal
entity makes the grant harder to rely on, which matters more once other projects are being
invited to adopt this. **This needs a decision by the owner** -- the individual authors, an
institution, or whatever the paper's authorship implies -- and it is deliberately not
guessed at here.

## The submodules

All eight, as `.gitmodules` declares them.

| path | upstream | licence | notes |
|---|---|---|---|
| `qemu` | [AFLplusplus/qemu-libafl-bridge](https://github.com/AFLplusplus/qemu-libafl-bridge) | **GPL-2.0** | A patched QEMU. `LICENSE` and `COPYING` in the checkout are GPLv2; the bridge's own README states its additions are GPL-2.0-or-later. This is the strongest obligation in the tree and the one to think about first if you intend to redistribute a built image |
| `tsffs` | [intel/tsffs](https://github.com/intel/tsffs) | Apache-2.0 | `LICENSE` in the checkout. **The code is Apache-2.0; what it drives is not.** TSFFS is a fuzzer built on Intel Simics, and Simics is licensed separately by Intel -- see below |
| `firness` | [BreakingBoot/firness](https://github.com/BreakingBoot/firness) | Apache-2.0 per source headers, no `LICENSE` file | The harness generator: Clang AST passes plus a Python generator. Eight sources carry `SPDX-License-Identifier: Apache-2.0`; the repository has no top-level `LICENSE`. (A ninth hit, `GPL-2.0`, is a string inside `linux_harness/smi_driver_template.py` that stamps the *generated* Linux kernel module, as a kernel module must; it does not describe firness.) Adding the `LICENSE` file is the fix |
| `uefi_asan` | [BreakingBoot/uefi_asan](https://github.com/BreakingBoot/uefi_asan) | BSD-2-Clause-Patent per source headers, no `LICENSE` file | The sanitizer: five libraries, two headers and a patch applied into an edk2 tree. All 60 sources carry `SPDX-License-Identifier: BSD-2-Clause-Patent`, which is both consistent and the right answer -- it matches the edk2 tree this code is merged into. The repository simply has no top-level `LICENSE` file saying so |
| `eval_source/edk2` | [cglosner/edk2](https://github.com/cglosner/edk2), branch `simics-sanitizer` | BSD-2-Clause-Patent | A fork of [tianocore/edk2](https://github.com/tianocore/edk2) carrying the sanitizer port. `License.txt` is tianocore's, SPDX `BSD-2-Clause-Patent`. This is the tree `apply_asan.py` lifts the port *from*, so it is load-bearing even when the tree being fuzzed is somebody else's |
| `eval_source/edk2-platforms` | [cglosner/edk2-platforms](https://github.com/cglosner/edk2-platforms), branch `simics-sanitizer` | BSD-2-Clause-Patent | A fork of tianocore/edk2-platforms. Used by the Simics path, which builds an edk2-platforms platform for its compilation database |
| `eval_source/edk2-non-osi` | [cglosner/edk2-non-osi](https://github.com/cglosner/edk2-non-osi), branch `simics-sanitizer` | **per module; binary-only in places** | A fork of tianocore/edk2-non-osi, which exists precisely because its contents are not compatible with edk2's licensing. There is **no top-level licence**: each module carries its own `License.txt`, and the nearest one in the hierarchy governs. Most of the Intel silicon packages are BSD-style binary redistribution terms. Two directories go further and are governed by an `IntelProprietaryLicense.txt` permitting redistribution **in binary form only, without modification**: `Silicon/Intel/QuarkSocBinPkg/QuarkNorthCluster/Binary/QuarkMicrocode/` and `Silicon/Intel/SimicsIch10BinPkg/UndiBinary/`. One package, `Silicon/Intel/Vlv2SocBinPkg`, has no `License.txt` at all: in its place is `MinnowBoardMAXUEFIFirmware-LicenseAgreement-Final.txt`, a click-through "PRODUCTION LICENSE AGREEMENT" between the licensee and Intel Corporation that takes effect on first copy or use |
| `eval_source/FSP` | [cglosner/FSP](https://github.com/cglosner/FSP), branch `simics-sanitizer` | Intel FSP binary licence | A fork of Intel's FSP binary repository. The terms are in `FSP_License.pdf` at the root -- a PDF, so they are not greppable and have not been read into this table. Binary silicon initialisation blobs, no source |

Four of these -- `firness`, `uefi_asan`, `tsffs` and `eval_source/edk2` -- are what
`scripts/bootstrap_runner.sh` and `action.yml` require to be non-empty. The other four are
needed by the Simics path and by `scripts/firness.py`'s full pipeline.

## Fetched during the image build, not vendored

`docker build` on `Dockerfile` reaches the network. These are not in the repository and will
not show up in a licence scan of it.

| what | where from | licence |
|---|---|---|
| LLVM / Clang 15.0.7 | `llvm-project` source tarball, built from source in the image | Apache-2.0 WITH LLVM-exception |
| Intel Simics public packages, and ISPM | Intel's download centre, via the two `PUBLIC_SIMICS_*_URL` values at the top of `Dockerfile` | Intel's own terms; see below |
| LibAFL 0.16.1 (`libafl`, `libafl_bolts`, `libafl_targets`, `libafl_qemu`, `libafl_qemu_build`) | crates.io, pinned in `Harness/qemu_fuzzer/Cargo.toml` | LibAFL publishes these as MIT OR Apache-2.0. **Not verified from a checkout here** -- the crates are fetched inside the image -- so confirm it from the crate metadata before relying on it |
| a second `qemu-libafl-bridge` | cloned by `libafl_qemu_build` at a revision written into the crate | GPL-2.0, as above. Note that this happens whether or not the `qemu` submodule is populated |
| Ubuntu 22.04 | the base image | the usual Ubuntu mix of licences |
| `actions/checkout`, `actions/upload-artifact` | GitHub, at workflow run time | MIT |
| the GitHub Actions runner | `actions/runner` releases, downloaded by `scripts/setup_gh_runner.sh` | MIT |

## Intel Simics, specifically

Read this before building the base image.

`Dockerfile` downloads the Intel Simics public release and installs it with
`ispm packages --install-bundle ... --non-interactive --trust-insecure-packages`.
`--non-interactive` is what makes the image build unattended, and it also means **nobody is
shown a licence prompt**. Whoever builds the image is accepting Intel's terms for those
packages; this repository does not reproduce them, and they are not quoted here, because
they are Intel's to state. Read them at the download page linked in the `Dockerfile`
comment before building on a machine where that matters.

Two further points, both verified against the code:

- **The GitHub Action never starts Simics.** `scripts/fuzz_edk2.py` passes
  `--backend qemu` unconditionally. Simics and TSFFS are only reached through
  `scripts/firness.py --backend tsffs`.
- **There is no way to skip installing it.** The only build arguments `Dockerfile` accepts
  are `NJOBS` and `WITH_QEMU`; neither gates the Simics install. So an action-only user pays
  for Simics in build time and in roughly half the base image's 26.5 GB, and gets nothing
  from it.

Using the Simics backend in earnest is a separate matter again: it needs a Simics
installation and the licence that goes with it, and the paper's results were produced that
way. The public packages the image installs are what make the backend buildable, not a
licence to use Simics for whatever you like.

## What this means if you redistribute

Nothing here is advice, but two things are worth being explicit about, because they are
easy to get wrong by accident:

- **A built image is not MIT.** It contains GPL-2.0 QEMU, Apache-2.0 LLVM, Intel Simics
  under Intel's terms, and -- if you built the Simics path -- Intel binary firmware
  components. Pushing such an image to a public registry is a distribution.
- **Fuzzing output is derived from the tree you fuzzed.** The issues the action files quote
  source lines out of your edk2, and the `fuzzuer-evidence` branch holds a generated harness
  and the inputs. They land in your own repository, under your own tree's licence, which is
  the reason filing anywhere else is refused.
