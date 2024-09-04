use anyhow::Result;
use ceno_emul::{EmuContext, StepRecord, VMState, CENO_PLATFORM};

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

    let value = state.peek_memory(CENO_PLATFORM.ram_start().into());
    assert_eq!(value, 6765, "Expected Fibonacci 20, got {}", value);
    Ok(())
}

#[test]
fn test_ceno_rt_alloc() -> Result<()> {
    let program_elf = include_bytes!("./data/ceno_rt_alloc");
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;

    // Search for the RAM action of the test program.
    let mut found = (false, false);
    for &addr in state.tracer().final_accesses().keys() {
        if !CENO_PLATFORM.is_ram(addr.into()) {
            continue;
        }
        let value = state.peek_memory(addr);
        if value == 0xf00d {
            found.0 = true;
        }
        if value == 0xbeef {
            found.1 = true;
        }
    }
    assert!(found.0);
    assert!(found.1);
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_success().collect()
}
