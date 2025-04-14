use std::path::Path;
use anyhow::Context;
use ceno_emul::{IterAddresses, Program, WORD_SIZE};
use ceno_zkvm::e2e::*;
use ceno_zkvm::scheme::ZKVMProof;
use ceno_zkvm::structs::ZKVMVerifyingKey;
use crate::{commands::common_args::*, utils::*};

/// Run the ceno elf file.
pub fn run_elf<P: AsRef<Path>>(
    options: &CenoOptions,
    elf_path: P
) -> anyhow::Result<(ZKVMProof<E, Pcs>, ZKVMVerifyingKey<E, Pcs>)> {
    options.try_setup_logger();

    let elf_path = elf_path.as_ref();
    let elf_bytes = std::fs::read(elf_path)
        .context(format!("failed to read {}", elf_path.display()))?;
    let program = Program::load_elf(&elf_bytes, u32::MAX)
        .context("failed to load elf")?;
    print_cargo_message("Loaded", format_args!("{}", elf_path.display()));

    let public_io = options.read_public_io()
        .context("failed to read public io")?;
    // estimate required pub io size, which is required in platform/key setup phase
    let pub_io_size: u32 = ((public_io.len() * WORD_SIZE) as u32)
        .next_power_of_two()
        .max(16);

    let platform = setup_platform(
        options.platform,
        &program,
        options.stack_size(),
        options.heap_size(),
        pub_io_size,
    );
    tracing::info!("Running on platform {:?} {}", options.platform, platform);
    tracing::info!(
        "Stack: {} bytes. Heap: {} bytes.",
        options.stack_size(),
        options.heap_size()
    );

    let hints = options.read_hints()
        .context("failed to read hints")?;
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );

    let (state, _) = run_e2e_with_checkpoint::<E, Pcs>(
        program,
        platform,
        hints,
        public_io,
        options.max_steps,
        Checkpoint::PrepSanityCheck,
    );

    Ok(state.expect("PrepSanityCheck should yield state."))
}
