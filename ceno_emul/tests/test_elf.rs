use anyhow::Result;
use ceno_emul::{ByteAddr, EmuContext, StepRecord, VMState, CENO_PLATFORM};

#[test]
fn test_ceno_rt_mini() -> Result<()> {
    let program_elf = include_bytes!("./data/ceno_rt_mini");
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;
    Ok(())
}

#[test]
fn test_ceno_rt_panic() -> Result<()> {
    let program_elf = include_bytes!("./data/ceno_rt_panic");
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let res = run(&mut state);

    assert!(matches!(res, Err(e) if e.to_string().contains("EcallError")));
    Ok(())
}

#[test]
fn test_ceno_rt_mem() -> Result<()> {
    let program_elf = include_bytes!("./data/ceno_rt_mem");
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;

    let value = state.peek_memory(ByteAddr(CENO_PLATFORM.ram_start()).waddr());
    assert_eq!(value, 6765, "Expected Fibonacci 20, got {}", value);
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_success().collect()
}
