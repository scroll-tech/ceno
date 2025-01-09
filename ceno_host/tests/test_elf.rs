use std::{collections::BTreeSet, iter::from_fn, sync::Arc};

use anyhow::Result;
use ceno_emul::{
    CENO_PLATFORM, EmuContext, InsnKind, Platform, Program, StepRecord, VMState, WORD_SIZE,
    host_utils::read_all_messages,
};
use ceno_host::CenoStdin;
use itertools::{Itertools, enumerate, izip};
use rand::{Rng, thread_rng};
use tiny_keccak::keccakf;

#[test]
fn test_ceno_rt_mini() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_mini;
    let program = Program::load_elf(program_elf, u32::MAX)?;
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..CENO_PLATFORM
    };
    let mut state = VMState::new(platform, Arc::new(program));
    let _steps = run(&mut state)?;
    Ok(())
}

// TODO(Matthias): We are using Rust's standard library's default panic handler now,
// and they are indicated with a different instruction than our ecall.  (But still work,
// as you can tell, because this tests panics.)  However, we should adapt this test
// to properly check for the conventional Rust panic.
#[test]
#[should_panic(expected = "Trap IllegalInstruction")]
fn test_ceno_rt_panic() {
    let program_elf = ceno_examples::ceno_rt_panic;
    let program = Program::load_elf(program_elf, u32::MAX).unwrap();
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..CENO_PLATFORM
    };
    let mut state = VMState::new(platform, Arc::new(program));
    let steps = run(&mut state).unwrap();
    let last = steps.last().unwrap();
    assert_eq!(last.insn().kind, InsnKind::ECALL);
    assert_eq!(last.rs1().unwrap().value, Platform::ecall_halt());
    assert_eq!(last.rs2().unwrap().value, 1); // panic / halt(1)
}

#[test]
fn test_ceno_rt_mem() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_mem;
    let program = Program::load_elf(program_elf, u32::MAX)?;
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..CENO_PLATFORM
    };
    let mut state = VMState::new(platform.clone(), Arc::new(program));
    let _steps = run(&mut state)?;

    let value = state.peek_memory(platform.heap.start.into());
    assert_eq!(value, 6765, "Expected Fibonacci 20, got {}", value);
    Ok(())
}

#[test]
fn test_ceno_rt_alloc() -> Result<()> {
    let program_elf = ceno_examples::ceno_rt_alloc;
    let program = Program::load_elf(program_elf, u32::MAX)?;
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..CENO_PLATFORM
    };
    let mut state = VMState::new(platform, Arc::new(program));
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
    let program = Program::load_elf(program_elf, u32::MAX)?;
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..CENO_PLATFORM
    };
    let mut state = VMState::new(platform, Arc::new(program));
    let _steps = run(&mut state)?;

    let all_messages = messages_to_strings(&read_all_messages(&state));
    for msg in &all_messages {
        print!("{msg}");
    }
    assert_eq!(&all_messages[0], "📜📜📜 Hello, World!\n");
    assert_eq!(&all_messages[1], "🌏🌍🌎\n");
    Ok(())
}

#[test]
fn test_hints() -> Result<()> {
    let all_messages = messages_to_strings(&ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::hints,
        CenoStdin::default()
            .write(&true)?
            .write(&"This is my hint string.".to_string())?
            .write(&1997_u32)?
            .write(&1999_u32)?,
    ));
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    assert_eq!(all_messages[0], "3992003");
    Ok(())
}

#[test]
fn test_bubble_sorting() -> Result<()> {
    let mut rng = thread_rng();
    let all_messages = messages_to_strings(&ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::quadratic_sorting,
        // Provide some random numbers to sort.
        CenoStdin::default().write(&(0..1_000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>())?,
    ));
    for msg in &all_messages {
        print!("{msg}");
    }
    Ok(())
}
#[test]
fn test_sorting() -> Result<()> {
    let mut rng = thread_rng();
    let all_messages = messages_to_strings(&ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::sorting,
        // Provide some random numbers to sort.
        CenoStdin::default().write(&(0..1000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>())?,
    ));
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    Ok(())
}

#[test]
fn test_median() -> Result<()> {
    let mut hints = CenoStdin::default();
    let mut rng = thread_rng();

    // Provide some random numbers to find the median of.
    let mut nums = (0..1000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    hints.write(&nums)?;
    nums.sort();
    hints.write(&nums[nums.len() / 2])?;

    let all_messages = messages_to_strings(&ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::median,
        &hints,
    ));
    assert!(!all_messages.is_empty());
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    Ok(())
}

#[test]
#[should_panic(expected = "Trap IllegalInstruction")]
fn test_hashing_fail() {
    let mut rng = thread_rng();

    let mut nums = (0..1_000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    // Add a duplicate number to make uniqueness check fail:
    nums[211] = nums[907];

    let _ = ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::hashing,
        CenoStdin::default().write(&nums).unwrap(),
    );
}

#[test]
fn test_hashing() -> Result<()> {
    let mut rng = thread_rng();

    // Provide some unique random numbers to verify:
    let uniques: Vec<u32> = {
        let mut seen_so_far = BTreeSet::default();
        from_fn(move || Some(rng.gen::<u32>()))
            .filter(|&item| seen_so_far.insert(item))
            .take(1_000)
            .collect::<Vec<_>>()
    };

    let all_messages = messages_to_strings(&ceno_host::run(
        CENO_PLATFORM,
        ceno_examples::hashing,
        CenoStdin::default().write(&uniques)?,
    ));
    assert!(!all_messages.is_empty());
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    assert_eq!(all_messages[0], "The input is a set of unique numbers.\n");
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
        assert_eq!(witness.reg_ops.len(), 1);
        assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());

        assert_eq!(witness.mem_ops.len(), expect.len() * 2);
        let got = witness
            .mem_ops
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

fn messages_to_strings(messages: &[Vec<u8>]) -> Vec<String> {
    messages
        .iter()
        .map(|msg| String::from_utf8_lossy(msg).to_string())
        .collect()
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    let steps = state.iter_until_halt().collect::<Result<Vec<_>>>()?;
    eprintln!("Emulator ran for {} steps.", steps.len());
    Ok(steps)
}
