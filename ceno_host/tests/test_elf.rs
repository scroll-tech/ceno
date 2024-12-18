use std::{collections::BTreeSet, iter::from_fn, sync::Arc};

use anyhow::Result;
use ceno_emul::{
    CENO_PLATFORM, EmuContext, InsnKind, Platform, Program, StepRecord, VMState,
    host_utils::read_all_messages,
};
use ceno_host::CenoStdin;
use itertools::enumerate;

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

    let all_messages = read_all_messages(&state);
    for msg in &all_messages {
        print!("{msg}");
    }
    assert_eq!(&all_messages[0], "📜📜📜 Hello, World!\n");
    assert_eq!(&all_messages[1], "🌏🌍🌎\n");
    Ok(())
}

#[test]
fn test_hints() -> Result<()> {
    let mut hints = CenoStdin::default();
    hints.write(&true)?;
    hints.write(&"This is my hint string.".to_string())?;
    hints.write(&1997_u32)?;
    hints.write(&1999_u32)?;

    let all_messages = ceno_host::run(CENO_PLATFORM, ceno_examples::hints, &hints);
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    assert_eq!(all_messages[0], "3992003");
    Ok(())
}

#[test]
fn test_sorting() -> Result<()> {
    use rand::Rng;
    let mut hints = CenoStdin::default();
    let mut rng = rand::thread_rng();

    // Provide some random numbers to sort.
    hints.write(&(0..1000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>())?;

    let all_messages = ceno_host::run(CENO_PLATFORM, ceno_examples::sorting, &hints);
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    Ok(())
}

#[test]
fn test_median() -> Result<()> {
    use rand::Rng;
    let mut hints = CenoStdin::default();
    let mut rng = rand::thread_rng();

    // Provide some random numbers to find the median of.
    let mut nums = (0..1000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    hints.write(&nums)?;
    nums.sort();
    hints.write(&nums[nums.len() / 2])?;

    let all_messages = ceno_host::run(CENO_PLATFORM, ceno_examples::median, &hints);
    assert!(!all_messages.is_empty());
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    Ok(())
}

#[test]
#[should_panic(expected = "Trap IllegalInstruction")]
fn test_hashing_fail() {
    use rand::Rng;
    let mut hints = CenoStdin::default();
    let mut rng = rand::thread_rng();

    let mut nums = (0..1_000).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    // Add a duplicate number to make uniqueness check fail:
    nums[211] = nums[907];
    hints.write(&nums).unwrap();

    let _ = ceno_host::run(CENO_PLATFORM, ceno_examples::hashing, &hints);
}

#[test]
fn test_hashing() -> Result<()> {
    use rand::Rng;
    let mut hints = CenoStdin::default();
    let mut rng = rand::thread_rng();

    // Provide some unique random numbers to verify:
    let uniques: Vec<u32> = {
        let mut seen_so_far = BTreeSet::default();
        from_fn(move || Some(rng.gen::<u32>()))
            .filter(|&item| seen_so_far.insert(item))
            .take(1_000)
            .collect::<Vec<_>>()
    };

    hints.write(&uniques)?;
    let all_messages = ceno_host::run(CENO_PLATFORM, ceno_examples::hashing, &hints);
    assert!(!all_messages.is_empty());
    for (i, msg) in enumerate(&all_messages) {
        println!("{i}: {msg}");
    }
    assert_eq!(all_messages[0], "The input is a set of unique numbers.\n");
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    let steps = state.iter_until_halt().collect::<Result<Vec<_>>>()?;
    eprintln!("Emulator ran for {} steps.", steps.len());
    Ok(steps)
}
