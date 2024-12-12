use anyhow::Result;
use ceno_emul::{
    CENO_PLATFORM, EmuContext, InsnKind, Platform, StepRecord, VMState,
    host_utils::read_all_messages,
};

#[test]
fn test_ceno_rt_mini() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_mini;
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;
    Ok(())
}

#[test]
fn test_ceno_rt_panic() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_panic;
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let steps = run(&mut state)?;
    let last = steps.last().unwrap();
    assert_eq!(last.insn().kind, InsnKind::ECALL);
    assert_eq!(last.rs1().unwrap().value, Platform::ecall_halt());
    assert_eq!(last.rs2().unwrap().value, 1); // panic / halt(1)
    Ok(())
}

#[test]
fn test_ceno_rt_mem() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_mem;
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;

    let value = state.peek_memory(CENO_PLATFORM.ram.start.into());
    assert_eq!(value, 6765, "Expected Fibonacci 20, got {}", value);
    Ok(())
}

#[test]
fn test_ceno_rt_alloc() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_alloc;
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

#[test]
fn test_ceno_rt_io() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_io;
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;

    let all_messages = read_all_messages(&state);
    for msg in &all_messages {
        print!("{msg}");
    }
    assert_eq!(&all_messages[0], "📜📜📜 Hello, World!\n");
    assert_eq!(&all_messages[1], "🌏🌍🌎\n");
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    let steps = state.iter_until_halt().collect::<Result<Vec<_>>>()?;
    eprintln!("Emulator ran for {} steps.", steps.len());
    Ok(steps)
}
