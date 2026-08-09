use super::{SyscallEffects, SyscallSpec, SyscallWitness};
use crate::{
    Change, EmuContext, Platform, Tracer, VMState, WORD_SIZE, Word, WriteOp, utils::MemoryView,
};
use itertools::Itertools;
use k256::elliptic_curve::PrimeField;

pub struct Secp256k1AddSpec;

pub struct Secp256k1DoubleSpec;

pub struct Secp256k1ScalarInvertSpec;

pub struct Secp256k1DecompressSpec;

impl SyscallSpec for Secp256k1AddSpec {
    const NAME: &'static str = "SECP256K1_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * SECP256K1_ARG_WORDS;
    const CODE: u32 = ceno_syscall::SECP256K1_ADD;
}

impl SyscallSpec for Secp256k1DoubleSpec {
    const NAME: &'static str = "SECP256K1_DOUBLE";

    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = SECP256K1_ARG_WORDS;
    const CODE: u32 = ceno_syscall::SECP256K1_DOUBLE;
}

impl SyscallSpec for Secp256k1ScalarInvertSpec {
    const NAME: &'static str = "SECP256K1_SCALAR_INVERT";

    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = COORDINATE_WORDS;
    const CODE: u32 = ceno_syscall::SECP256K1_SCALAR_INVERT;
}

impl SyscallSpec for Secp256k1DecompressSpec {
    const NAME: &'static str = "SECP256K1_DECOMPRESS";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * COORDINATE_WORDS;
    const CODE: u32 = ceno_syscall::SECP256K1_DECOMPRESS;
}

// A secp256k1 point in uncompressed form takes 64 bytes
pub const SECP256K1_ARG_WORDS: usize = 16;

/// Wrapper type for a point on the secp256k1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpPoint(pub secp::Point);

impl From<[Word; SECP256K1_ARG_WORDS]> for SecpPoint {
    fn from(words: [Word; SECP256K1_ARG_WORDS]) -> Self {
        // Prepend the "tag" byte as expected by secp
        let mut bytes = [0u8; 65];
        bytes[0] = 4;
        for (chunk, word) in bytes[1..].chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }

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
        std::array::from_fn(|index| {
            Word::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
        })
    }
}

#[inline(never)]
pub(crate) fn add_words(
    p: [Word; SECP256K1_ARG_WORDS],
    q: [Word; SECP256K1_ARG_WORDS],
) -> [Word; SECP256K1_ARG_WORDS] {
    SecpMaybePoint(SecpPoint::from(p).0 + SecpPoint::from(q).0).into()
}

#[inline(never)]
pub(crate) fn double_words(words: [Word; SECP256K1_ARG_WORDS]) -> [Word; SECP256K1_ARG_WORDS] {
    let point = SecpPoint::from(words).0;
    SecpMaybePoint(point + point).into()
}

/// Trace the execution of a secp256k1_add call
pub fn secp256k1_add<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
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
        [p_ptr, q_ptr].map(|start| MemoryView::<_, SECP256K1_ARG_WORDS>::new(vm, start));

    // Read P and Q from words via wrapper type
    let output_words = add_words(p_view.words(), q_view.words());

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
pub fn secp256k1_double<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument pointers
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(p_ptr, p_ptr),
        0, // Cycle set later in finalize().
    )];

    // P's memory segment
    let mut p_view = MemoryView::<_, SECP256K1_ARG_WORDS>::new(vm, p_ptr);
    let output_words = double_words(p_view.words());

    p_view.write(output_words);

    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), SECP256K1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub fn secp256k1_invert<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument pointers
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(p_ptr, p_ptr),
        0, // Cycle set later in finalize().
    )];

    // P's memory segment
    let mut p_view = MemoryView::<_, COORDINATE_WORDS>::new(vm, p_ptr);
    let output_words = invert_words(p_view.words());

    p_view.write(output_words);
    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), COORDINATE_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

#[inline(never)]
pub(crate) fn invert_words(words: [Word; COORDINATE_WORDS]) -> [Word; COORDINATE_WORDS] {
    let bytes: [u8; 32] = unsafe { std::mem::transmute(words) };
    let scalar = k256::Scalar::from_repr(bytes.into()).expect("illegal p");
    let inverted: [u8; 32] = scalar.invert().unwrap().to_bytes().into();
    unsafe { std::mem::transmute(inverted) }
}

pub const COORDINATE_WORDS: usize = SECP256K1_ARG_WORDS / 2;

/// Wrapper type for a single coordinate of a point on the secp256k1 curve.
/// It implements conversions from and to VM word-representations according
/// to the spec of syscall
pub struct SecpCoordinate(pub [u8; COORDINATE_WORDS * WORD_SIZE]);

impl From<[Word; COORDINATE_WORDS]> for SecpCoordinate {
    fn from(words: [Word; COORDINATE_WORDS]) -> Self {
        SecpCoordinate(unsafe { std::mem::transmute(words) })
    }
}

impl From<SecpCoordinate> for [Word; COORDINATE_WORDS] {
    fn from(coord: SecpCoordinate) -> [Word; COORDINATE_WORDS] {
        unsafe { std::mem::transmute(coord.0) }
    }
}

#[inline(never)]
pub(crate) fn decompress_words(
    x_words: [Word; COORDINATE_WORDS],
    y_is_odd: Word,
) -> [Word; COORDINATE_WORDS] {
    let parity_byte = match y_is_odd {
        0 => 2,
        1 => 3,
        _ => panic!("y_is_odd should be 0/1"),
    };
    let mut bytes = [0u8; 33];
    bytes[0] = parity_byte;
    bytes[1..].copy_from_slice(&SecpCoordinate::from(x_words).0);
    let point = secp::Point::from_slice(&bytes).unwrap();
    let serialized = point.serialize_uncompressed();
    SecpCoordinate(serialized[33..65].try_into().unwrap()).into()
}

/// Trace the execution of a secp256k1_decompress call
pub fn secp256k1_decompress<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
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
    let input_view = MemoryView::<_, COORDINATE_WORDS>::new(vm, ptr);
    // Memory segment where Y coordinate will be written
    let mut output_view =
        MemoryView::<_, COORDINATE_WORDS>::new(vm, ptr + (COORDINATE_WORDS * WORD_SIZE) as u32);

    let output_words = decompress_words(input_view.words(), y_is_odd);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_point_double_matches_scalar_multiplication() {
        let mut point = secp::Point::generator();
        for _ in 0..16 {
            let direct = SecpMaybePoint(point + point);
            let scalar = SecpPoint(secp::Scalar::two() * point);
            assert_eq!(
                <[Word; SECP256K1_ARG_WORDS]>::from(direct),
                <[Word; SECP256K1_ARG_WORDS]>::from(scalar),
            );
            point = (point + secp::Point::generator()).into_option().unwrap();
        }
    }
}
