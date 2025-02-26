use crate::{Change, EmuContext, Platform, VMState, WORD_SIZE, Word, WriteOp, utils::MemoryView};
use itertools::Itertools;
use secp::{self};
use std::iter;

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

pub struct Secp256k1AddSpec;
pub struct Secp256k1DoubleSpec;
pub struct Secp256k1DecompressSpec;

impl SyscallSpec for Secp256k1AddSpec {
    const NAME: &'static str = "SECP256K1_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * SECP256K1_ARG_WORDS;
    const CODE: u32 = ceno_rt::syscalls::SECP256K1_ADD;
}

impl SyscallSpec for Secp256k1DoubleSpec {
    const NAME: &'static str = "SECP256K1_DOUBLE";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = SECP256K1_ARG_WORDS;
    const CODE: u32 = ceno_rt::syscalls::SECP256K1_DOUBLE;
}

impl SyscallSpec for Secp256k1DecompressSpec {
    const NAME: &'static str = "SECP256K1_DECOMPRESS";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * COORDINATE_WORDS;
    const CODE: u32 = ceno_rt::syscalls::SECP256K1_DECOMPRESS;
}

// A secp256k1 point in uncompressed form takes 64 bytes
pub const SECP256K1_ARG_WORDS: usize = 16;

/// Wrapper type for a point on the secp256k1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpPoint(pub secp::Point);

impl From<[Word; SECP256K1_ARG_WORDS]> for SecpPoint {
    fn from(words: [Word; SECP256K1_ARG_WORDS]) -> Self {
        // Prepend the "tag" byte as expected by secp
        let mut bytes = iter::once(4u8)
            .chain(words.iter().flat_map(|word| word.to_le_bytes()))
            .collect_vec();

        // The call-site uses "little endian", while secp uses "big endian"
        // We need to reverse the coordinate representations

        // Reverse X coordinate
        bytes[1..33].reverse();
        // Reverse Y coordinate
        bytes[33..].reverse();
        SecpPoint(secp::Point::from_slice(&bytes).unwrap())
    }
}

impl From<SecpPoint> for [Word; SECP256K1_ARG_WORDS] {
    fn from(point: SecpPoint) -> [Word; SECP256K1_ARG_WORDS] {
        // reuse MaybePoint implementation
        SecpMaybePoint(point.0.into()).into()
    }
}

/// Wrapper type for a maybe-point on the secp256k1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpMaybePoint(pub secp::MaybePoint);

impl From<SecpMaybePoint> for [Word; SECP256K1_ARG_WORDS] {
    fn from(maybe_point: SecpMaybePoint) -> [Word; SECP256K1_ARG_WORDS] {
        let mut bytes: [u8; 64] = maybe_point.0.serialize_uncompressed()[1..]
            .try_into()
            .unwrap();
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
    let [mut p_view, q_view] =
        [p_ptr, q_ptr].map(|start| MemoryView::<SECP256K1_ARG_WORDS>::new(vm, start));

    // Read P and Q from words via wrapper type
    let [p, q] = [&p_view, &q_view].map(|view| SecpPoint::from(view.words()));

    // Compute the sum and convert back to words
    let sum = SecpMaybePoint(p.0 + q.0);
    let output_words: [Word; SECP256K1_ARG_WORDS] = sum.into();

    p_view.write(output_words);

    let mem_ops = p_view
        .mem_ops()
        .into_iter()
        .chain(q_view.mem_ops())
        .collect_vec();

    assert_eq!(mem_ops.len(), 2 * SECP256K1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

/// Trace the execution of a secp256k1_double call
pub fn secp256k1_double(vm: &VMState) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // for compatibility with sp1 spec
    assert_eq!(vm.peek_register(Platform::reg_arg1()), 0);

    // Read the argument pointers
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(p_ptr, p_ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(0, 0),
            0, // Cycle set later in finalize().
        ),
    ];

    // P's memory segment
    let mut p_view = MemoryView::<SECP256K1_ARG_WORDS>::new(vm, p_ptr);
    // Create point from words via wrapper type
    let p = SecpPoint::from(p_view.words());

    // Compute result and convert back into words
    let result = SecpPoint(secp::Scalar::two() * p.0);
    let output_words: [Word; SECP256K1_ARG_WORDS] = result.into();

    p_view.write(output_words);

    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), SECP256K1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
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
        let bytes = (words.iter().flat_map(|word| word.to_le_bytes()))
            .collect_vec()
            .try_into()
            .unwrap();
        SecpCoordinate(bytes)
    }
}

impl From<SecpCoordinate> for [Word; COORDINATE_WORDS] {
    fn from(coord: SecpCoordinate) -> [Word; COORDINATE_WORDS] {
        coord
            .0
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
    let mut output_view =
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

        secp::Point::from_slice(&bytes).unwrap()
    };

    // Get uncompressed repr. of the point and extract the Y-coordinate bytes
    // Y-coordinate is the second half after eliminating the "tag" byte
    let y_bytes: [u8; 32] = point.serialize_uncompressed()[1..][32..]
        .try_into()
        .unwrap();

    // Convert into words via the internal wrapper type
    let output_words: [Word; COORDINATE_WORDS] = SecpCoordinate(y_bytes).into();

    output_view.write(output_words);

    let y_mem_ops = output_view.mem_ops();
    let x_mem_ops = input_view.mem_ops();

    let mem_ops = x_mem_ops.into_iter().chain(y_mem_ops).collect_vec();

    assert_eq!(mem_ops.len(), 2 * COORDINATE_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
