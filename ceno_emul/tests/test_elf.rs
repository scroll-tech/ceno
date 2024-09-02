use anyhow::Result;
use ceno_emul::{ByteAddr, Program, StepRecord, VMState, CENO_PLATFORM};

#[test]
fn test_ceno_rt_mini() -> Result<()> {
    let mut state = VMState::new(CENO_PLATFORM);

    // Load an ELF program in memory.
    let program_elf = include_bytes!("./data/ceno_rt_mini");
    let program = Program::load_elf(program_elf, u32::MAX)?;
    for (addr, word) in program.image.iter() {
        let addr = ByteAddr(*addr).waddr();
        state.init_memory(addr, *word);
    }
    assert_eq!(program.entry, CENO_PLATFORM.pc_start());

    let _steps = run(&mut state)?;

    Ok(())
}

#[test]
fn test_ceno_rt_mem() -> Result<()> {
    let mut state = VMState::new(CENO_PLATFORM);

    // Load an ELF program in memory.
    let program_elf = include_bytes!("./data/ceno_rt_mem");
    let program = Program::load_elf(program_elf, u32::MAX)?;
    for (addr, word) in program.image.iter() {
        let addr = ByteAddr(*addr).waddr();
        state.init_memory(addr, *word);
    }
    assert_eq!(program.entry, CENO_PLATFORM.pc_start());

    let mut prev_step = StepRecord::default();
    for step in state.iter_until_success() {
        match step {
            Ok(step) => {
                // println!("{:?}", step);
                prev_step = step;
            }
            Err(e) => {
                println!("pc = {:?}", prev_step.pc().after);
                return Err(e);
            }
        }
    }

    for i in 0..4 {
        let addr = ByteAddr(CENO_PLATFORM.ram_start()).waddr() + i as u32;
        let value = state.peek_memory(addr);
        println!("{:?} = 0x{:08x}", addr, value);
    }

    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_success().collect()
}
