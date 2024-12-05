use anyhow::Result;
use ceno_emul::{StepRecord, VMState, CENO_PLATFORM};

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    let steps = state.iter_until_halt().collect::<Result<Vec<_>>>()?;
    eprintln!("Emulator ran for {} steps.", steps.len());
    Ok(steps)
}

fn main() {
    let program_elf = elf::elf;
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf).expect("Failed to load ELF");
    let steps = run(&mut state).expect("Failed to run the program");
    println!("Ran for {} steps.", steps.len());
}
