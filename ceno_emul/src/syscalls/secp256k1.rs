use crate::{Change, EmuContext, Platform, VMState, WORD_SIZE, WordAddr, WriteOp};
use itertools::{Itertools, izip};
use secp::Point;

use super::{SyscallEffects, SyscallWitness};

pub const SECP256K1_WORDS: usize = 16;

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
///
/// TODO: test compatibility.
pub fn secp256k1_add(vm: &VMState) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());
    let q_ptr = vm.peek_register(Platform::reg_arg1());

    // Read the argument pointers
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(p_ptr, p_ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(q_ptr, q_ptr),
            0, // Cycle set later in finalize().
        ),
    ];

    let [p_addrs, q_addrs] = [p_ptr, q_ptr].map(|ptr| {
        (ptr..)
            .step_by(WORD_SIZE)
            .take(SECP256K1_WORDS)
            .map(WordAddr::from)
            .collect_vec()
    });

    // Read Keccak state.
    let [p_bytes, q_bytes] = [p_addrs.clone(), q_addrs].map(|addrs| {
        addrs
            .iter()
            // TODO: double check endianess etc
            .map(|&addr| vm.peek_memory(addr).to_le_bytes().to_vec())
            .flatten()
            .collect::<Vec<_>>()
    });

    let [p, q] = [p_bytes, q_bytes].map(|bytes| {
        Point::from_slice(&bytes).expect(&format!(
            "failed to parse affine point from byte array {:?}",
            bytes
        ))
    });

    let output_bytes = (p + q).serialize_uncompressed();

    let output_words: Vec<u32> = output_bytes
        .chunks_exact(4)
        .map(|chunk| {
            let arr: [u8; 4] = chunk.try_into().unwrap();
            u32::from_le_bytes(arr)
        })
        .collect();

    let p_words = p_addrs
        .clone()
        .iter()
        .map(|addr| vm.peek_memory(*addr))
        .collect_vec();

    // write over p memory
    let mem_ops = izip!(p_addrs, p_words, output_words)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Cycle set later in finalize().
        })
        .collect_vec();

    assert_eq!(mem_ops.len(), SECP256K1_WORDS);
    SyscallEffects {
        witness: SyscallWitness { mem_ops, reg_ops },
        next_pc: None,
    }
}
