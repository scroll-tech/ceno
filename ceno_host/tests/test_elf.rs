use anyhow::Result;
use ceno_emul::{ByteAddr, CENO_PLATFORM, EmuContext, InsnKind, Platform, StepRecord, VMState};
use itertools::{Itertools, izip};
use tiny_keccak::keccakf;

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

    let value = state.peek_memory(CENO_PLATFORM.heap.start.into());
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
        print!("{}", String::from_utf8_lossy(msg));
    }
    assert_eq!(&all_messages[0], "📜📜📜 Hello, World!\n".as_bytes());
    assert_eq!(&all_messages[1], "🌏🌍🌎\n".as_bytes());
    Ok(())
}

#[test]
fn test_ceno_rt_keccak() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_keccak;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;
    let steps = run(&mut state)?;

    // Expect the program to have written successive states between Keccak permutations.
    const ITERATIONS: usize = 3;
    let keccak_outs = sample_keccak_f(ITERATIONS);

    let all_messages = read_all_messages(&state);
    assert_eq!(all_messages.len(), ITERATIONS);
    for (got, expect) in izip!(&all_messages, &keccak_outs) {
        let got = got
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec();
        assert_eq!(&got, expect);
    }

    // Find the syscall records.
    let syscalls = steps.iter().filter_map(|step| step.syscall()).collect_vec();
    assert_eq!(syscalls.len(), ITERATIONS);

    // Check the syscall effects.
    for (witness, expect) in izip!(syscalls, keccak_outs) {
        assert_eq!(witness.reg_accesses.len(), 1);
        assert_eq!(
            witness.reg_accesses[0].register_index(),
            Platform::reg_arg0()
        );

        assert_eq!(witness.mem_writes.len(), expect.len() * 2);
        let got = witness
            .mem_writes
            .chunks_exact(2)
            .map(|write_ops| {
                assert_eq!(
                    write_ops[1].addr.baddr(),
                    write_ops[0].addr.baddr() + WORD_SIZE as u32
                );
                let lo = write_ops[0].value.after as u64;
                let hi = write_ops[1].value.after as u64;
                lo | (hi << 32)
            })
            .collect_vec();
        assert_eq!(got, expect);
    }

    Ok(())
}

fn unsafe_platform() -> Platform {
    let mut platform = CENO_PLATFORM;
    platform.unsafe_ecall_nop = true;
    platform
}

fn sample_keccak_f(count: usize) -> Vec<Vec<u64>> {
    let mut state = [0_u64; 25];

    (0..count)
        .map(|_| {
            keccakf(&mut state);
            state.into()
        })
        .collect_vec()
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    let steps = state.iter_until_halt().collect::<Result<Vec<_>>>()?;
    eprintln!("Emulator ran for {} steps.", steps.len());
    Ok(steps)
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
