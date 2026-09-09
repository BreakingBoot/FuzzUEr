# FuzzUEr

This is the tool is designed for setting up and Fuzzing the EDK2 firmware. The tool is designed to work with [TSFFS](https://github.com/intel/tsffs).

## Research Paper

This tool was developed as part of a research project and the paper called `FuzzUEr: Enabling Fuzzing of UEFI Interfaces` that is NDSS 25 and can be found [here](https://dx.doi.org/10.14722/ndss.2025.240400).


## Overview

This repo is responsible for fuzzing the EDK2 UEFI through the use of a harness UEFI application that is reposible for creating well formed inputs to pass to other drivers. The tool generates the harness for TSFFS automatically. Everything has been configured to run within Docker containers to make it easier to use and more portable. FuzzUEr has 3 main components:

1. [Firness](https://github.com/BreakingBoot/firness)
2. [Sanitizer](https://github.com/BreakingBoot/uefi_asan)
3. Testing Platform: [TSFFS](https://github.com/intel/tsffs)

![FuzzUEr Overview](./FuzzUEr_Overview.png)

Firness and the sanitizer instrumentation both take the original firmware image as input and output the generated harness and instrumented firmware image with ASan, respectively. 

## Running FuzzUEr

There are are only two things that you will need to do in order to run the system: create a shared folder for the input firmware and the input file descibing the protocols to harness. For our experiments we have all of the source code already added as submodules within the `eval_source` directory.

And then you can add the input file containing the target functions, for example:

```
[Protocols]
  // EFI_IP4_PROTOCOL
  gEfiIp4ProtocolGuid:GetModeData
  gEfiIp4ProtocolGuid:Configure
  gEfiIp4ProtocolGuid:Groups
  gEfiIp4ProtocolGuid:Routes
  gEfiIp4ProtocolGuid:Transmit
  gEfiIp4ProtocolGuid:Receive
  gEfiIp4ProtocolGuid:Cancel
  gEfiIp4ProtocolGuid:Poll
```
This file is already included in the `eval_source` directory.

A new docker container can be created by running the following commands:
```
docker build -t fuzzuer-image .
docker run -it -v ./eval_source/:/input fuzzuer-image
```

And then you can run everything with the helper script `firness.py`:

```
python firness.py -h

  -i, --input INPUT     Input directory with the source files, or the input file
                        for a single run
  -s, --src SRC         Path to the source directory with edk2 and input.txt
  -a, --analyze         Run the static analysis tool
  -g, --generate        Generate the harness
  -f, --fuzz            Run the fuzzer
  -e, --eval            Evaluate the results of the static analysis tool
  -t, --timeout N       Fuzzing budget in seconds, counted from the moment the
                        harness is reached, not from simics startup
  --backend BACKEND     Fuzzer the generated harness targets:
                        tsffs (default) | qemu | nyx | none
  --smi                 Fuzz SMI handlers instead of protocols
  --max-steps N         Calls chained per fuzzing iteration
  --seed-corpus DIR     Start the corpus from a previous campaign's
  --snapshot            Restore projects/example/booted.ckpt instead of booting
  --make-snapshot       Boot once, write booted.ckpt, then stop
  --reproduce           Replay a saved test case instead of fuzzing
  --testcase FILE       Test case to replay with --reproduce
```

`-g` matters more than it looks: `-f` on its own fuzzes whatever harness is already
built into the image, not the one just generated for the protocol you asked for.

## Example

This is an example of running the system with the `eval_source` directory:

```
# build the docker image
docker build -t fuzzuer-image .

# run the docker image
docker run -it -v ./eval_source/:/input fuzzuer-image

# run the firness.py script
python firness.py -i /input/input.txt -s /input
```

This will automatically generate the compilation database, analyze the source code, generate the harness, compile the firmware and harness, and then run the fuzzer. Note: it will run the fuzzer indefinitely, so make sure to CTRL+C to stop it. The results will be in the `/workspace/firness_output` directory, where the most recent harness is in a folder called `Firness` but all generated harness are stored based on time they are generated.

## Backends

The harness targets one of two machines. They answer different questions, so the
choice is not just taste.

| | Simics / TSFFS | QEMU |
|---|---|---|
| speed | ~0.17 exec/s | ~7.4 exec/s |
| ASan instrumentation | yes | yes |
| how a finding surfaces | an ASan report becomes a solution | a crash or a timeout |

With `ASAN_FUZZER=qemu`, AsanLib emits the LibAFL crash handshake when it reports.
That the handshake is emitted has been checked -- stock QEMU raises `#UD` on those four
bytes, which is what `qemu_smoke.sh` keys on -- but it has not yet been confirmed
captured end to end by the LibAFL fuzzer, so treat QEMU ASan findings as crashes to
triage rather than as counted solutions.

Pick with `--backend`. The backend is compiled into the harness, so it has to be set
at generation time (`-g --backend qemu`), not just at fuzzing time.

```
# generate and fuzz under QEMU
python firness.py -i /input/input.txt -s /input -a -g -f --backend qemu
```

Two QEMU helpers stand on their own:

```
# does the harness load and reach HARNESS_START at all?  (stock QEMU, no fuzzer)
./scripts/qemu_smoke.sh path/to/Firness.efi

# fuzz it under LibAFL-QEMU, for 600 seconds by default
./scripts/qemu_fuzz.sh path/to/Firness.efi [seconds]
```

`qemu_smoke.sh` is a real test rather than a demo because the two backends give
opposite, unambiguous answers: a `--backend none` build runs to completion, while a
`--backend qemu` build raises `#UD` on the four magic bytes that stock QEMU cannot
decode. Either answer appearing for the wrong build means the backend never reached
the compiler.

## Running it under QEMU, end to end

Simics is what the paper used; QEMU is roughly forty times faster per execution and needs
no licence. The whole path, from nothing to a campaign:

**1. Build the firmware with ASan and the QEMU backend.** `ASAN_FUZZER=qemu` is what makes
a finding reach the fuzzer rather than only the log.

```
export WORKSPACE=$PWD/eval_source/edk2 EDK_TOOLS_PATH=$WORKSPACE/BaseTools
export CONF_PATH=$WORKSPACE/Conf CLANGSAN_BIN=/path/to/llvm/bin/
cd $WORKSPACE && make -C BaseTools && source edksetup.sh
build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc \
      -D ASAN_SCOPE=per-module -D ASAN_FUZZER=qemu
```

**2. Build the fuzzer.** It compiles its own QEMU, so the first build is long.

```
cd Harness/qemu_fuzzer && cargo build --release
```

**3. Generate a harness for the QEMU backend.** The backend is compiled in, so it has to
be chosen at generation time.

```
python scripts/firness.py -i /input/input.txt -s /input -a -g --backend qemu
```

**4. Check it loads before spending a campaign on it.**

```
OVMF_CODE=.../OVMF_CODE.fd ./scripts/qemu_smoke.sh .../Firness.efi
```

**5. Fuzz it.**

```
export FIRNESS_OVMF_CODE=$WORKSPACE/Build/OvmfX64/DEBUG_CLANGSAN/FV/OVMF_CODE.fd
export FIRNESS_OVMF_VARS=$WORKSPACE/Build/OvmfX64/DEBUG_CLANGSAN/FV/OVMF_VARS.fd
export FIRNESS_TIMEOUT=60
./scripts/qemu_fuzz.sh .../Firness.efi 600
```

Three of these are easy to get wrong, and each fails quietly:

- **`FIRNESS_OVMF_CODE` is not optional.** Left unset the fuzzer runs the distribution
  OVMF, which has no ASan in it at all. The campaign then reports crashes and timeouts
  only and looks like a clean target; that is what "objectives: 0" meant here for a whole
  afternoon. The script warns about it now.
- **`FIRNESS_TIMEOUT` defaults to 10 seconds**, which an instrumented boot can exceed. Every
  iteration then ends as a timeout, and a real crash is indistinguishable from one. If
  every input is an objective and the corpus stays empty, raise it before believing
  anything.
- **The emulator is linked into the fuzzer**, so it has no data directory and looks for its
  roms relative to the working directory. `qemu_fuzz.sh` now finds the bridge checkout's
  `pc-bios` itself; if it cannot, set `FIRNESS_QEMU_BIOS_DIR`.

To confirm the reporting path end to end rather than trusting it, fuzz `AsanSelfTest.efi`
instead of a harness. Seeded with a first byte of 0 it commits a heap overflow and the
fuzzer records an objective about a second after the boot; seeded with 4 it does the same
allocation correctly and produces nothing but a timeout.

## AddressSanitizer

### Adding it to a platform

Everything is in one include. Set two defines above `[LibraryClasses]` in the
platform DSC and pull it in:

```
[Defines]
  DEFINE ASAN_SCOPE  = per-module     # off | per-module | full
  DEFINE ASAN_FUZZER = tsffs          # tsffs | qemu | none

!include MdeModulePkg/Include/Dsc/Asan.dsc.inc
```

Both are overridable from the build command line, so one tree builds every variant:

```
build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc \
      -D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FD_SIZE_IN_KB=8192
```

The platform still has to reserve the shadow region and publish `gAsanInfoGuid` from
PEI. Without that HOB AsanLib deactivates itself, and every instrumented access
becomes a no-op that looks exactly like a clean run. `OvmfPkg/PlatformPei/MemDetect.c`
is the worked example.

### Porting to a fresh EDK2 tree

The sanitizer is five libraries, two headers and a patch. Against a clean upstream
checkout:

```
# 1. the libraries and headers, copied in
cp -r uefi_asan/AsanLib          <edk2>/MdeModulePkg/Library/
cp -r uefi_asan/AsanLibNull      <edk2>/MdeModulePkg/Library/
cp -r uefi_asan/AsanRuntimeLib   <edk2>/MdeModulePkg/Library/
cp -r uefi_asan/AsanMemoryLib        <edk2>/MdePkg/Library/
cp -r uefi_asan/AsanMemoryLibRepStr  <edk2>/MdePkg/Library/
cp uefi_asan/Asan.h     <edk2>/MdeModulePkg/Include/Library/
cp uefi_asan/AsanInfo.h <edk2>/MdeModulePkg/Include/Guid/

# 2. the patch, which is the part that touches upstream files
patch -p1 --forward --batch --binary -d <edk2> < uefi_asan/asan.patch
```

`scripts/firness.py` does both of these itself; the manual form is for a tree it does not
manage. The patch touches the toolchain definition (`BaseTools/Conf/tools_def.template`
adds the `CLANGSAN` toolchain, `build_rule.template` adds the `SANITIZER` build rule and
its nasm command), the DXE and SMM cores so the allocator can poison and quarantine
(`Core/Dxe/Mem/Page.c`, `Mem/Pool.c`, `Core/PiSmmCore`), and a few call sites.

Then, per platform:

- **Declare the HOB guid.** `gAsanInfoGuid` has to be in `MdeModulePkg.dec` under
  `[Guids]`. The patch adds it; check it survived a merge.
- **Include the DSC fragment** and set the two defines, as above.
- **Reserve the shadow and publish the HOB from PEI.** This is the one part that is
  genuinely platform specific, and the one whose absence is silent: without the HOB
  AsanLib deactivates itself and every instrumented access becomes a no-op.
  `OvmfPkg/PlatformPei/MemDetect.c` (`AsanInitializeShadowMemory`) is 20 lines and is the
  model -- reserve `LowMemory >> 3` bytes at `0x5000000`, zero it, and
  `BuildGuidDataHob (&gAsanInfoGuid, ...)`.
- **Resolve `AsanLib` for every module type the platform builds.** A core INF that calls
  into the runtime -- `DxeMain`, `PiSmmCore`, `BootScriptExecutorDxe` -- consumes the class
  by name, so a platform that resolves it for only some phases stops with "Instance of
  library class [AsanLib] is not found".
- **Build with `-t CLANGSAN`**, and point `CLANGSAN_BIN` at a clang whose ASan pass matches
  the runtime's expectations. Clang 15 is what this tree is built and tested with.

Then run `AsanSelfTest` before trusting a single result.

### Scope

`per-module` instruments nothing until a module opts in, which keeps the image inside
a 4MB flash. Give the module's entry in `[Components]`:

```
MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf {
  <BuildOptions>
    *_CLANGSAN_X64_SAN_FLAGS == $(ASAN_SAN_FLAGS)
  <LibraryClasses>
    AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
    NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
    BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf
}
```

`full` instruments every DXE phase module -- 265 of 277 on OVMF against 3 at
per-module -- which is what finds an error whose allocation and access are in
different drivers. It roughly triples the image, so it needs `-D FD_SIZE_IN_KB=8192`.

Three rules that are easy to get wrong, each of which cost a debugging cycle:

- **The runtime is pinned uninstrumented in its sources, not in the build files.** A
  DSC global `SAN_FLAGS ==` overrides an INF `[BuildOptions]` outright, and edk2 builds
  a library instance once, so `[Components]` cannot reach it either. The AsanLib and
  AsanMemoryLib sources carry `no_sanitize` pragmas instead, which also means they hold
  under whatever flags a platform sets.
- **Stack instrumentation is per-module on purpose.** The compiler writes frame
  redzones inline and unconditionally, past AsanLib's range guard, so a module whose
  stack falls outside the mapped shadow corrupts memory. `full` therefore adds
  `-mllvm -asan-stack=0` globally. Nothing is lost for cross-module work: a stack frame
  never outlives the function that owns it.
- **`SAN_FLAGS` is replaced with `==`, never appended with `=`.** `build_rule` puts it
  after `CC_FLAGS`, so a `-fno-sanitize` in `CC_FLAGS` has no effect.

### Checking that it actually reports

`AsanSelfTest` commits deliberate errors and says what it expects, so a silent ASan is
distinguishable from a clean run. Put it on an ESP and boot it:

```
./scripts/make_esp.sh Build/OvmfX64/DEBUG_CLANGSAN/X64/AsanSelfTest.efi esp.img
```

A working image reports the overflow, the underflow and the use-after-free with shadow
`FA`/`FD`, reports the double free, and stays silent on the control case.

## SMI fuzzing

`--smi` targets SMI handlers instead of protocols. The harness writes the buffer into
the SMM Core private data and raises the SMI, which is what `SmmCommunicationCommunicate`
does; a plain write to the command port dispatches on whatever the last DXE caller left
behind.

### From a Linux kernel module

`--host linux` emits the same harness as a kernel module, so handlers can be driven from
a running OS rather than from DXE. It reads the firmware's `FirnessSmmInfo` variable out
of `/sys/firmware/efi/efivars` for the addresses it needs.

```
python firness/harness_generator/main.py --smi --host linux --backend none \
    --edk2 eval_source/edk2 -i eval_source/evalset/SmiTest.txt \
    -sm <cache>/smi-function-guid-map.json ... -o out/
```

Build the module against the guest's kernel, then load it:

```
insmod firness_smi.ko comm_phys=$COMM comm_size=$COMMSZ \
       bufptr_phys=$BUFPTR bufsize_phys=$BUFSZ smi_port=$PORT target=2
```

`insmod` answering `-ENODEV` is the designed path: the work happens in module init and
the module unloads itself. `target=<n>` picks one handler; without a fuzzer attached the
input is all zeroes, so the choice byte is always 0 and only the first handler is ever
reached.

**Cross handler state.** `chain=<n>` calls n handlers before the iteration ends, so one
runs against whatever the previous one left behind. That is the only way to reach a bug
where a handler stores something -- a length, an NVRAM variable -- that a different handler
later trusts; with one call per iteration the second handler never sees the first one's
state. `target` then steps rather than pins, so `chain=4 target=0` dispatches handlers
0, 1, 2, 3 in order, which is deterministic without a fuzzer attached.

Two limits worth knowing before reading anything into a chained run:

- With `--backend none` every generated length field reads zero, so the handlers reject
  the buffer and no state actually crosses. A chain only carries data with a fuzzer
  supplying non-empty messages.
- **SMM code is not instrumented.** `Asan.dsc.inc` excludes `SMM_CORE` and
  `DXE_SMM_DRIVER`, because SMM needs its own shadow and its own runtime and that is not
  wired up. A memory error inside a handler is therefore not an ASan finding here; what
  surfaces is an ASSERT, a crash or a timeout, which is how the VarCheckPolicy defect was
  found.

Three things that are not obvious:

- **The guest usually has no toolchain and no kernel headers.** Cross-build the `.ko`
  against matching headers (the vermagic has to match exactly), strip it, and hand it to
  the guest as a raw disk rather than installing a compiler in the target.
- **X64 plus SMM needs `-global ICH9-LPC.disable_s3=1`**, or OVMF asserts in
  `Platform.c` before any driver runs.
- **Start from a fresh `OVMF_VARS` copy each run.** Reusing a written one lands the
  guest in the UEFI Shell, because the earlier boot rewrote the boot order.

`scripts/guest_run.py` drives the whole thing over the guest's serial console and can
capture the firmware debug port with `--fw-log`, which is the only place OVMF's DEBUG
output goes:

```
python scripts/guest_run.py --code OVMF_CODE.fd --vars VARS.fd --disk guest.qcow2 \
    --extra-disk ko.img --script run.sh --fw-log fw.log
```

To confirm a handler really ran rather than just an SMI being raised, look for the SMM
core's dispatch line in `--fw-log`. `Success` means a handler registered for that GUID
executed; `Not Found` means none was:

```
SmmCore: dispatch 2A3CFEBD-27E8-4D0A-8B79-D688C2A3E1C0 len 0 -> Success
```

## Network and network boot fuzzing

A protocol harness calls a protocol member with fuzzed arguments. That reaches the API
surface of the network stack and almost none of its parsing: what `Dhcp4Dxe`, `Mtftp4Dxe`
and `UefiPxeBcDxe` spend their code on is bytes that arrived from somewhere else, and
nothing was ever on the other end of the wire.

`scripts/net_peer.py` is that other end -- a server whose every reply is built from an
input file. QEMU's socket netdev hands the guest's NIC straight to a process, so this
needs no tap device, no root and no host networking:

```
-netdev socket,id=n0,connect=127.0.0.1:5555 -device virtio-net-pci,netdev=n0
```

It speaks ARP, ICMP, DHCP and TFTP -- enough to PXE boot a UEFI guest. Run it by hand to
watch an exchange:

```
python3 scripts/net_peer.py --port 5555 --serve-file some.efi
```

A healthy run prints the whole boot: `DHCP DISCOVER -> OFFER`, `DHCP REQUEST -> ACK`,
`ARP who-has`, `TFTP RRQ`, then `TFTP transfer complete, 29 block(s)`. The guest then
executes what it was handed, so a real application in `--serve-file` puts the PE loader
and everything that application touches in range as well.

`scripts/net_fuzz.py` is the loop around it:

```
python3 scripts/net_fuzz.py --code OVMF_CODE.fd --vars OVMF_VARS.fd \
    --serve-file some.efi --iterations 20 --mutate 8 --mutate-labels DATA
```

`--mutate-labels` picks which replies to corrupt -- `OFFER`, `ACK`, `OACK`, `DATA` -- and
choosing it is most of the skill:

| target | reaches | what a run looks like |
|---|---|---|
| `DATA` | TFTP block handling, then the PE loader | 232 mutations into a 40KB image, `start failed: Unsupported` |
| `OFFER,ACK` | the DHCP option parser | exchange completes, PXE gives up expanding the boot path |
| `OACK` | option negotiation | the transfer aborts before a block is sent |

Three things that took a measurement each to get right:

- **The BOOTP header is 236 bytes, not 240.** Four bytes of padding in front of the magic
  cookie is enough for the client to reject the offer and go back to DISCOVER, which looks
  exactly like a guest that cannot see the server.
- **TFTP needs a fresh server port per transfer.** RFC 1350 gives each transfer its own
  TID and the client sends its ACKs there; answering from port 69 got one DATA out and
  never an ACK back. PXE also asks for `blksize`/`tsize`, which want an OACK first.
- **Corrupt the payload, not the framing.** Mutations in the BOOTP header or in an OACK
  end the exchange before the parser under test runs, so the DHCP replies protect their
  first 236 bytes and `--mutate-labels DATA` is the default.

`net_fuzz.py` takes a baseline with no mutations before it starts and counts only
reporting sites beyond it. An instrumented boot raises the same 23 every time, so a run
that counted reports would call every iteration a finding -- the same trap as
[Triage](#triage) below.

## Triage

A campaign's solution count is not a bug count. Most reports are the harness, not the
firmware, so check the module a report is attributed to before chasing it:

```
python scripts/triage_crashes.py
python scripts/symbolize.py       # raw addresses -> module names
```

Group reports by return IP first. A single site dominating the count is a scanner or a
loop rather than N bugs.
