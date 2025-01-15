use std::{iter, rc::Rc};

use crate::{
    Change, EmuContext, Platform, VMState, WORD_SIZE, Word, WordAddr, WriteOp,
    utils::{HasByteRepr, MemoryView},
};
use itertools::{Itertools, izip};
use secp;

use super::{SyscallEffects, SyscallWitness};
// A secp256k1 point in uncompressed form takes 64 bytes
pub const SECP256K1_ARG_WORDS: usize = 16;

/// Trace the execution of a secp256k1_add call
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/weierstrass/add.rs
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

    // Create byte-views of point P and Q
    let [p_view, q_view] = [p_ptr, q_ptr].map(|start| MemoryView::<u8>::new(vm, start, 64, true));

    let [p, q] = [&p_view, &q_view].map(|view| {
        // prepend the "0x04" tag byte for secp compatibility
        let bytes = iter::once(4u8).chain(view.iter_bytes()).collect_vec();
        secp::Point::from_slice(&bytes).expect(&format!(
            "failed to parse affine point from byte array {:?}",
            bytes
        ))
    });

    // Perform the sum and serialize; ignore the "tag byte"
    let output_bytes: [u8; 64] = (p + q).serialize_uncompressed()[1..].try_into().unwrap();
    // Convert into words
    let output_words: Vec<Word> = Word::vec_from_bytes(&output_bytes);

    // overwrite result at point P
    let mem_ops = izip!(p_view.addrs(), p_view.words(), output_words)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Cycle set later in finalize().
        })
        .collect_vec();

    assert_eq!(mem_ops.len(), SECP256K1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness { mem_ops, reg_ops },
        next_pc: None,
    }
}
