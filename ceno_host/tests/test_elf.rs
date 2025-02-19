use std::{collections::BTreeSet, iter::from_fn, sync::Arc};

use anyhow::Result;
use ceno_emul::{
    CENO_PLATFORM, COORDINATE_WORDS, EmuContext, InsnKind, Platform, Program, SECP256K1_ARG_WORDS,
    SHA_EXTEND_WORDS, StepRecord, VMState, WORD_SIZE, WordAddr, host_utils::read_all_messages,
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
        assert_eq!(witness.reg_ops.len(), 2);
        assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());
        assert_eq!(witness.reg_ops[1].register_index(), Platform::reg_arg1());

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

fn bytes_to_words(bytes: [u8; 65]) -> [u32; 16] {
    // ignore the tag byte (specific to the secp repr.)
    let mut bytes: [u8; 64] = bytes[1..].try_into().unwrap();

    // Reverse the order of bytes for each coordinate
    bytes[0..32].reverse();
    bytes[32..].reverse();
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
}

#[test]
fn test_secp256k1_add() -> Result<()> {
    let program_elf = ceno_examples::secp256k1_add_syscall;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;
    let steps = run(&mut state)?;

    let syscalls = steps.iter().filter_map(|step| step.syscall()).collect_vec();
    assert_eq!(syscalls.len(), 1);

    let witness = syscalls[0];
    assert_eq!(witness.reg_ops.len(), 2);
    assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());
    assert_eq!(witness.reg_ops[1].register_index(), Platform::reg_arg1());

    let p_address = witness.reg_ops[0].value.after;
    assert_eq!(p_address, witness.reg_ops[0].value.before);
    let p_address: WordAddr = p_address.into();

    let q_address = witness.reg_ops[1].value.after;
    assert_eq!(q_address, witness.reg_ops[1].value.before);
    let q_address: WordAddr = q_address.into();

    const P_PLUS_Q: [u8; 65] = [
        4, 188, 11, 115, 232, 35, 63, 79, 186, 163, 11, 207, 165, 64, 247, 109, 81, 125, 56, 83,
        131, 221, 140, 154, 19, 186, 109, 173, 9, 127, 142, 169, 219, 108, 17, 216, 218, 125, 37,
        30, 87, 86, 194, 151, 20, 122, 64, 118, 123, 210, 29, 60, 209, 138, 131, 11, 247, 157, 212,
        209, 123, 162, 111, 197, 70,
    ];
    let expect = bytes_to_words(P_PLUS_Q);

    assert_eq!(witness.mem_ops.len(), 2 * SECP256K1_ARG_WORDS);
    // Expect first half to consist of read/writes on P
    for (i, write_op) in witness.mem_ops.iter().take(SECP256K1_ARG_WORDS).enumerate() {
        assert_eq!(write_op.addr, p_address + i);
        assert_eq!(write_op.value.after, expect[i]);
    }

    // Expect second half to consist of reads on Q
    for (i, write_op) in witness
        .mem_ops
        .iter()
        .skip(SECP256K1_ARG_WORDS)
        .take(SECP256K1_ARG_WORDS)
        .enumerate()
    {
        assert_eq!(write_op.addr, q_address + i);
        assert_eq!(write_op.value.after, write_op.value.before);
    }

    Ok(())
}

#[test]
fn test_secp256k1_double() -> Result<()> {
    let program_elf = ceno_examples::secp256k1_double_syscall;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;

    let steps = run(&mut state)?;

    let syscalls = steps.iter().filter_map(|step| step.syscall()).collect_vec();
    assert_eq!(syscalls.len(), 1);

    let witness = syscalls[0];
    assert_eq!(witness.reg_ops.len(), 2);
    assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());

    let p_address = witness.reg_ops[0].value.after;
    assert_eq!(p_address, witness.reg_ops[0].value.before);
    let p_address: WordAddr = p_address.into();

    const DOUBLE_P: [u8; 65] = [
        4, 111, 137, 182, 244, 228, 50, 13, 91, 93, 34, 231, 93, 191, 248, 105, 28, 226, 251, 23,
        66, 192, 188, 66, 140, 44, 218, 130, 239, 101, 255, 164, 76, 202, 170, 134, 48, 127, 46,
        14, 9, 192, 64, 102, 67, 163, 33, 48, 157, 140, 217, 10, 97, 231, 183, 28, 129, 177, 185,
        253, 179, 135, 182, 253, 203,
    ];
    let expect = bytes_to_words(DOUBLE_P);

    assert_eq!(witness.mem_ops.len(), SECP256K1_ARG_WORDS);
    for (i, write_op) in witness.mem_ops.iter().enumerate() {
        assert_eq!(write_op.addr, p_address + i);
        assert_eq!(write_op.value.after, expect[i]);
    }

    Ok(())
}

#[test]
fn test_secp256k1_decompress() -> Result<()> {
    let program_elf = ceno_examples::secp256k1_decompress_syscall;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;

    let steps = run(&mut state)?;

    let syscalls = steps.iter().filter_map(|step| step.syscall()).collect_vec();
    assert_eq!(syscalls.len(), 1);

    let witness = syscalls[0];
    assert_eq!(witness.reg_ops.len(), 2);
    assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());
    assert_eq!(witness.reg_ops[1].register_index(), Platform::reg_arg1());

    let x_address = witness.reg_ops[0].value.after;
    assert_eq!(x_address, witness.reg_ops[0].value.before);
    let x_address: WordAddr = x_address.into();
    // Y coordinate  should be written immediately after X coordinate
    // X coordinate takes "half an argument" of words
    let y_address = x_address + SECP256K1_ARG_WORDS / 2;

    // Complete decompressed point (X and Y)
    let mut decompressed: [u8; 65] = [
        4, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64,
        50, 63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166, 242,
        145, 107, 249, 24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67, 37, 222,
        234, 108, 57, 84, 148,
    ];

    decompressed[33..].reverse();

    // Writes should cover the Y coordinate, i.e latter half of the repr
    let expect = bytes_to_words(decompressed)[8..].to_vec();

    assert_eq!(witness.mem_ops.len(), 2 * COORDINATE_WORDS);
    // Reads on X
    for (i, write_op) in witness.mem_ops.iter().take(COORDINATE_WORDS).enumerate() {
        assert_eq!(write_op.addr, x_address + i);
        assert_eq!(write_op.value.after, write_op.value.before);
    }

    // Reads/writes on Y
    for (i, write_op) in witness
        .mem_ops
        .iter()
        .skip(COORDINATE_WORDS)
        .take(COORDINATE_WORDS)
        .enumerate()
    {
        assert_eq!(write_op.addr, y_address + i);
        assert_eq!(write_op.value.after, expect[i]);
    }

    Ok(())
}

#[test]
fn test_sha256_extend() -> Result<()> {
    let program_elf = ceno_examples::sha_extend_syscall;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;

    let steps = run(&mut state)?;
    let syscalls = steps.iter().filter_map(|step| step.syscall()).collect_vec();
    assert_eq!(syscalls.len(), 1);

    let witness = syscalls[0];
    assert_eq!(witness.reg_ops.len(), 2);
    assert_eq!(witness.reg_ops[0].register_index(), Platform::reg_arg0());
    assert_eq!(witness.reg_ops[1].register_index(), Platform::reg_arg1());

    let state_ptr = witness.reg_ops[0].value.after;
    assert_eq!(state_ptr, witness.reg_ops[0].value.before);
    let state_ptr: WordAddr = state_ptr.into();

    let expected = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 34013193, 67559435, 1711661200,
        3020350282, 1447362251, 3118632270, 4004188394, 690615167, 6070360, 1105370215, 2385558114,
        2348232513, 507799627, 2098764358, 5845374, 823657968, 2969863067, 3903496557, 4274682881,
        2059629362, 1849247231, 2656047431, 835162919, 2096647516, 2259195856, 1779072524,
        3152121987, 4210324067, 1557957044, 376930560, 982142628, 3926566666, 4164334963,
        789545383, 1028256580, 2867933222, 3843938318, 1135234440, 390334875, 2025924737,
        3318322046, 3436065867, 652746999, 4261492214, 2543173532, 3334668051, 3166416553,
        634956631,
    ];

    assert_eq!(witness.mem_ops.len(), SHA_EXTEND_WORDS);

    for (i, write_op) in witness.mem_ops.iter().enumerate() {
        assert_eq!(write_op.addr, state_ptr + i);
        assert_eq!(write_op.value.after, expected[i]);
        if i < 16 {
            // sanity check: first 16 entries remain unchanged
            assert_eq!(write_op.value.before, write_op.value.after);
        }
    }

    Ok(())
}

#[test]
fn test_syscalls_compatibility() -> Result<()> {
    let program_elf = ceno_examples::syscalls;
    let mut state = VMState::new_from_elf(unsafe_platform(), program_elf)?;

    let _ = run(&mut state)?;
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
