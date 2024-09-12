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

#[test]
fn test_ceno_rt_io() -> Result<()> {
    let program_elf = include_bytes!("./data/ceno_rt_io");
    let mut state = VMState::new_from_elf(CENO_PLATFORM, program_elf)?;
    let _steps = run(&mut state)?;

    let all_messages = read_all_messages(&state);
    for msg in &all_messages {
        print!("{}", String::from_utf8_lossy(msg));
    }
    assert_eq!(&all_messages[0], "📜📜📜 Hello, World!\n".as_bytes());
    assert_eq!(&all_messages[1], "🌏🌍🌎\n".as_bytes());
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_success().collect()
}

const WORD_SIZE: usize = 4;
const INFO_OUT_ADDR: u32 = 0xC000_0000;

fn read_all_messages(state: &VMState) -> Vec<Vec<u8>> {
    let mut all_messages = Vec::new();
    let mut word_offset = 0;
    loop {
        let out = read_message(state, word_offset);
        if out.is_empty() {
            break;
        }
        word_offset += out.len().div_ceil(WORD_SIZE) as u32 + 1;
        all_messages.push(out);
    }
    all_messages
}

fn read_message(state: &VMState, word_offset: u32) -> Vec<u8> {
    let out_addr = ByteAddr(INFO_OUT_ADDR).waddr() + word_offset;
    let byte_len = state.peek_memory(out_addr);
    let word_len_up = byte_len.div_ceil(4);

    let mut info_out = Vec::with_capacity(WORD_SIZE * word_len_up as usize);
    for i in 1..1 + word_len_up {
        let value = state.peek_memory(out_addr + i);
        info_out.extend_from_slice(&value.to_le_bytes());
    }
    info_out.truncate(byte_len as usize);
    info_out
}
