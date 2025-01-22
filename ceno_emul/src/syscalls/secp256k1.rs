use crate::{Change, EmuContext, Platform, VMState, WORD_SIZE, Word, WriteOp, utils::MemoryView};
use itertools::{Itertools, izip};
use secp::{self};
use std::iter;

use super::{SyscallEffects, SyscallWitness};
// A secp256k1 point in uncompressed form takes 64 bytes
pub const SECP256K1_ARG_WORDS: usize = 16;

/// Wrapper type for a point on the secp256k1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpPoint(pub secp::Point);

impl From<[Word; SECP256K1_ARG_WORDS]> for SecpPoint {
    fn from(words: [Word; SECP256K1_ARG_WORDS]) -> Self {
        // Prepend the "tag" byte as expected by secp
        let mut bytes = iter::once(4u8)
            .chain(words.iter().map(|word| word.to_le_bytes()).flatten())
            .collect_vec();

        // The call-site uses "little endian", while secp uses "big endian"
        // We need to reverse the coordinate representations

        // Reverse X coordinate
        bytes[1..33].reverse();
        // Reverse Y coordinate
        bytes[33..].reverse();
        SecpPoint(secp::Point::from_slice(&bytes).expect(&format!(
            "failed to parse affine point from byte array {:?}",
            bytes
        )))
    }
}

impl Into<[Word; SECP256K1_ARG_WORDS]> for SecpPoint {
    fn into(self) -> [Word; SECP256K1_ARG_WORDS] {
        // reuse MaybePoint implementation
        SecpMaybePoint(self.0.into()).into()
    }
}

/// Wrapper type for a maybe-point on the secp256k1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpMaybePoint(pub secp::MaybePoint);

impl Into<[Word; SECP256K1_ARG_WORDS]> for SecpMaybePoint {
    fn into(self) -> [Word; SECP256K1_ARG_WORDS] {
        let mut bytes: [u8; 64] = self.0.serialize_uncompressed()[1..].try_into().unwrap();
        // The call-site expects "little endian", while secp uses "big endian"
        // We need to reverse the coordinate representations

        // Reverse X coordinate
        bytes[..32].reverse();
        // Reverse Y coordinate
        bytes[32..].reverse();
        bytes
            .chunks_exact(4)
            .map(|chunk| Word::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

/// Trace the execution of a secp256k1_add call
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

    // Memory segments of P and Q
    let [p_view, q_view] =
        [p_ptr, q_ptr].map(|start| MemoryView::<SECP256K1_ARG_WORDS>::new(vm, start));

    // Read P and Q from words via wrapper type
    let [p, q] = [&p_view, &q_view].map(|view| SecpPoint::from(view.words()));

    // Compute the sum and convert back to words
    let sum = SecpMaybePoint(p.0 + q.0);
    let output_words: [Word; SECP256K1_ARG_WORDS] = sum.into();

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

/// Trace the execution of a secp256k1_double call
pub fn secp256k1_double(vm: &VMState) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument pointers
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(p_ptr, p_ptr),
        0, // Cycle set later in finalize().
    )];

    // P's memory segment
    let p_view = MemoryView::<SECP256K1_ARG_WORDS>::new(vm, p_ptr);
    // Create point from words via wrapper type
    let p = SecpPoint::from(p_view.words());

    // Compute result and convert back into words
    let result = SecpPoint(secp::Scalar::two() * p.0);
    let output_words: [Word; SECP256K1_ARG_WORDS] = result.into();

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

pub const COORDINATE_WORDS: usize = SECP256K1_ARG_WORDS / 2;

/// Wrapper type for a single coordinate of a point on the secp256k1 curve.
/// It implements conversions from and to VM word-representations according
/// to the spec of syscall
pub struct SecpCoordinate(pub [u8; COORDINATE_WORDS * WORD_SIZE]);

impl From<[Word; COORDINATE_WORDS]> for SecpCoordinate {
    fn from(words: [Word; COORDINATE_WORDS]) -> Self {
        let bytes = (words.iter().map(|word| word.to_le_bytes()).flatten())
            .collect_vec()
            .try_into()
            .unwrap();
        SecpCoordinate(bytes)
    }
}

impl Into<[Word; COORDINATE_WORDS]> for SecpCoordinate {
    fn into(self) -> [Word; COORDINATE_WORDS] {
        self.0
            .chunks_exact(4)
            .map(|chunk| Word::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

/// Trace the execution of a secp256k1_decompress call
pub fn secp256k1_decompress(vm: &VMState) -> SyscallEffects {
    let ptr = vm.peek_register(Platform::reg_arg0());
    let y_is_odd = vm.peek_register(Platform::reg_arg1());

    // Read the argument pointers
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(ptr, ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(y_is_odd, y_is_odd),
            0, // Cycle set later in finalize().
        ),
    ];

    // Memory segment of X coordinate
    let input_view = MemoryView::<COORDINATE_WORDS>::new(vm, ptr);
    // Memory segment where Y coordinate will be written
    let output_view =
        MemoryView::<COORDINATE_WORDS>::new(vm, ptr + (COORDINATE_WORDS * WORD_SIZE) as u32);

    let point = {
        // Encode parity byte according to secp spec
        let parity_byte = match y_is_odd {
            0 => 2,
            1 => 3,
            _ => panic!("y_is_odd should be 0/1"),
        };
        // Read bytes of the X coordinate
        let coordinate_bytes = SecpCoordinate::from(input_view.words()).0;
        // Prepend parity byte to complete compressed repr.
        let bytes = iter::once(parity_byte)
            .chain(coordinate_bytes.iter().cloned())
            .collect::<Vec<u8>>();

        secp::Point::from_slice(&bytes).expect(&format!(
            "failed to parse affine point from byte array {:?}",
            bytes
        ))
    };

    // Get uncompressed repr. of the point and extract the Y-coordinate bytes
    // Y-coordinate is the second half after eliminating the "tag" byte
    let y_bytes: [u8; 32] = point.serialize_uncompressed()[1..][32..]
        .try_into()
        .unwrap();

    // Convert into words via the internal wrapper type
    let output_words: [Word; COORDINATE_WORDS] = SecpCoordinate(y_bytes).into();

    let mem_ops = izip!(output_view.addrs(), output_view.words(), output_words)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Cycle set later in finalize().
        })
        .collect_vec();

    assert_eq!(mem_ops.len(), COORDINATE_WORDS);
    SyscallEffects {
        witness: SyscallWitness { mem_ops, reg_ops },
        next_pc: None,
    }
}
