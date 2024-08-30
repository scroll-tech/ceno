use anyhow::Result;
use ceno_emul::{ByteAddr, Program, StepRecord, VMState, CENO_PLATFORM};

#[test]
fn test_ceno_rt_mini() -> Result<()> {
    let mut ctx = VMState::new(CENO_PLATFORM);

    // Load an ELF program in memory.
    let program_elf = include_bytes!("./data/ceno_rt_mini");
    let program = Program::load_elf(program_elf, u32::MAX)?;
    for (addr, word) in program.image.iter() {
        let addr = ByteAddr(*addr).waddr();
        ctx.init_memory(addr, *word);
    }
    assert_eq!(program.entry, CENO_PLATFORM.pc_start());

    let _steps = run(&mut ctx)?;
    let ctx = ctx;

    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_success().collect()
}
