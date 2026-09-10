//! LibAFL-QEMU host for a generated Firness UEFI harness.
//!
//! The guest is OVMF plus one UEFI application, Firness.efi, built with
//! FIRNESS_BACKEND=2. That build emits the four bytes 0f 3a f2 66 at HARNESS_START and
//! again at HARNESS_STOP; qemu-libafl-bridge decodes them at TCG translation time, which
//! is why this has to be a TCG run and can never be a KVM one.
//!
//! Everything after the QEMU arguments is the upstream qemu_baremetal custom_insn
//! fuzzer. What is specific to a UEFI target is the argument list itself, so it is
//! assembled here rather than left to the caller: the harness is reached over the
//! removable media path with no shell and no startup.nsh, and the snapshot the emulator
//! takes at the first HARNESS_START is what every later iteration is restored to.
use core::time::Duration;
use std::{env, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    emu::Emulator, executor::QemuExecutor, modules::edges::StdEdgeCoverageModule,
    QemuSnapshotManager,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

fn env_or(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.to_string())
}

/// Where QEMU looks for option roms.
///
/// The emulator is linked into this binary rather than installed under a prefix, so it
/// has no data directory of its own and every rom load fails with "failed to find
/// romfile" -- for kvmvapic.bin, for the vga bios, and for whichever NIC the machine
/// has. The build tree copies only a handful of roms next to the binary; the full set is
/// in the qemu-libafl-bridge checkout that libafl_qemu_build cloned. Prefer whichever
/// actually holds them, and say so plainly rather than letting QEMU fail one rom at a
/// time.
fn qemu_bios_dir() -> String {
    const PROBE: &str = "kvmvapic.bin";
    if let Ok(dir) = env::var("FIRNESS_QEMU_BIOS_DIR") {
        return dir;
    }
    let candidates = [
        "./target/release/qemu-libafl-bridge/pc-bios",
        "./target/release/pc-bios",
    ];
    for dir in candidates {
        if PathBuf::from(dir).join(PROBE).is_file() {
            return dir.to_string();
        }
    }
    panic!(
        "no QEMU rom directory holds {PROBE} (looked in {candidates:?}). Point \
         FIRNESS_QEMU_BIOS_DIR at the pc-bios directory of the qemu-libafl-bridge \
         checkout that the build cloned."
    );
}

/// QEMU's own argv. argv[0] is required and ignored.
///
/// FIRNESS_ESP is a qcow2 FAT image, not a directory: the QEMU that libafl_qemu builds is
/// configured without the vvfat block driver, so "-drive file=fat:rw:<dir>" -- which is
/// what scripts/qemu_smoke.sh uses against a distribution QEMU -- fails here with
/// "Unknown protocol 'fat'". qcow2 rather than raw because a writable raw disk cannot be
/// snapshotted, and the snapshot is what every iteration after the first restores from.
/// scripts/make_esp.sh builds the image.
///
/// Both OVMF pflash images are opened read-only. That is not a detail: QEMU refuses to
/// snapshot a writable pflash ("Device 'pflash1' is writable but does not support
/// snapshots"), and without a snapshot the emulator cannot restore between iterations,
/// so every run ends after one testcase. The harness is reached over the removable media
/// path, which needs no boot option in the variable store, so nothing here depends on
/// the variables surviving.
fn qemu_args() -> Vec<String> {
    let ovmf_code = env_or("FIRNESS_OVMF_CODE", "/usr/share/OVMF/OVMF_CODE.fd");
    let ovmf_vars = env_or("FIRNESS_OVMF_VARS", "/tmp/firness_vars.fd");
    let esp = env_or("FIRNESS_ESP", "/tmp/firness_esp.qcow2");
    let memory = env_or("FIRNESS_MEMORY", "2048");
    let bios_dir = qemu_bios_dir();

    // q35 by default; "q35,smm=on" for an SMI harness, which needs SMRAM to exist before
    // PiSmmIpl will publish anything. The extra globals an SMM build needs come with it,
    // because X64 plus SMM asserts in Platform.c without S3 disabled.
    let machine = env_or("FIRNESS_QEMU_MACHINE", "q35");
    let mut argv: Vec<String> = [
        "qemu-system-x86_64",
        "-machine",
        &machine,
        "-m",
        &memory,
        // One CPU, and the override OVMF asks for by name. Against QEMU 6.2 OVMF's
        // PlatformCpuCountBugCheck decides the CPU hotplug register block is buggy and
        // stops with "ASSERT Platform.c(520)" before any driver runs -- the firmware
        // never reaches the harness and the run looks like a target that does not boot.
        "-smp",
        "1",
        "-fw_cfg",
        "name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes",
        "-drive",
        &format!("if=pflash,format=raw,unit=0,readonly=on,file={ovmf_code}"),
        "-drive",
        &format!("if=pflash,format=raw,unit=1,readonly=on,file={ovmf_vars}"),
        "-drive",
        &format!("file={esp},format=qcow2,if=ide"),
        "-L",
        &bios_dir,
        "-debugcon",
        &format!("file:{}", env_or("FIRNESS_DEBUGCON", "/tmp/firness_debugcon.log")),
        "-global",
        "isa-debugcon.iobase=0x402",
        "-serial",
        &format!("file:{}", env_or("FIRNESS_SERIAL", "/tmp/firness_serial.log")),
        // no display and no display adapter: the harness reports over serial, and the
        // vga bios is one more rom to find and one more device in every snapshot
        "-display",
        "none",
        "-vga",
        "none",
        "-no-reboot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if machine.contains("smm=on") {
        for extra in ["-global", "ICH9-LPC.disable_s3=1",
                      "-global", "driver=cfi.pflash01,property=secure,value=on"] {
            argv.push(extra.to_string());
        }
    }
    argv
}

pub fn main() {
    env_logger::init();

    let timeout = Duration::from_secs(
        env_or("FIRNESS_TIMEOUT", "10").parse().expect("FIRNESS_TIMEOUT was not a number"),
    );
    let broker_port = env_or("FIRNESS_BROKER_PORT", "1340")
        .parse()
        .expect("FIRNESS_BROKER_PORT was not a number");
    let cores = Cores::from_cmdline(&env_or("FIRNESS_CORES", "0")).unwrap();
    let corpus_dirs = [PathBuf::from(env_or("FIRNESS_CORPUS", "./corpus"))];
    let objective_dir = PathBuf::from(env_or("FIRNESS_CRASHES", "./crashes"));

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        let modules = tuple_list!(StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?);

        let mut emu = Emulator::builder()
            .qemu_parameters(qemu_args())
            .modules(modules)
            .snapshot_manager(QemuSnapshotManager::default())
            .build()?;

        // Runs the guest until the first HARNESS_START. Under a harness that never
        // reaches it -- the protocol is not installed, the boot option was not taken --
        // this is where the run stops, so say so rather than reporting zero coverage.
        unsafe {
            emu.start().unwrap();
        }

        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           _state: &mut _,
                           input: &BytesInput| unsafe {
            emulator.run(input).unwrap().try_into().unwrap()
        };

        let time_observer = TimeObserver::new("time");

        let mut feedback = feedback_or!(
            MaxMapFeedback::new(&edges_observer),
            TimeFeedback::new(&time_observer)
        );

        // A UEFI harness that faults is a crash; one that wanders off is a timeout. Both
        // are objectives, and the serial log is what says which driver it was in.
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryCorpus::new(),
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        // CalibrationStage wants the map feedback, not the observer, and the one above
        // was moved into the fuzzer; a second one over the same observer is what upstream
        // does here too
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator),
            CalibrationStage::new(&calibration_feedback)
        );

        let mut executor = QemuExecutor::new(
            emu,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|err| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}: {err:?}");
                    process::exit(0);
                });
            println!("Imported {} input(s) from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
