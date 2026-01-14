use super::{SyscallEffects, SyscallSpec, SyscallWitness};
use crate::{
    Change, EmuContext, Platform, Tracer, VMState, WORD_SIZE, Word, WriteOp, utils::MemoryView,
};
use itertools::Itertools;
use p256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{
        PrimeField,
        group::Group,
        sec1::{Coordinates, FromEncodedPoint, ToEncodedPoint},
    },
};

pub struct Secp256r1AddSpec;

pub struct Secp256r1DoubleSpec;

pub struct Secp256r1ScalarInvertSpec;

impl SyscallSpec for Secp256r1AddSpec {
    const NAME: &'static str = "SECP256R1_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * SECP256R1_ARG_WORDS;
    const CODE: u32 = ceno_syscall::SECP256R1_ADD;
}

impl SyscallSpec for Secp256r1DoubleSpec {
    const NAME: &'static str = "SECP256R1_DOUBLE";

    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = SECP256R1_ARG_WORDS;
    const CODE: u32 = ceno_syscall::SECP256R1_DOUBLE;
}

impl SyscallSpec for Secp256r1ScalarInvertSpec {
    const NAME: &'static str = "SECP256R1_SCALAR_INVERT";

    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = COORDINATE_WORDS;
    const CODE: u32 = ceno_syscall::SECP256R1_SCALAR_INVERT;
}

// A secp256r1 point in uncompressed form takes 64 bytes
pub const SECP256R1_ARG_WORDS: usize = 16;

/// Wrapper type for a point on the secp256r1 curve that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct SecpPoint(pub AffinePoint);

impl From<[Word; SECP256R1_ARG_WORDS]> for SecpPoint {
    fn from(words: [Word; SECP256R1_ARG_WORDS]) -> Self {
        if words.iter().all(|&word| word == 0) {
            return SecpPoint(AffinePoint::IDENTITY);
        }

        let x_words: [Word; COORDINATE_WORDS] = words[..COORDINATE_WORDS]
            .try_into()
            .expect("invalid point words");
        let y_words: [Word; COORDINATE_WORDS] = words[COORDINATE_WORDS..]
            .try_into()
            .expect("invalid point words");

        let mut x_bytes = SecpCoordinate::from(x_words).0;
        let mut y_bytes = SecpCoordinate::from(y_words).0;
        x_bytes.reverse();
        y_bytes.reverse();

        let encoded = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&x_bytes),
            FieldBytes::from_slice(&y_bytes),
            false,
        );

        let point = Option::from(AffinePoint::from_encoded_point(&encoded))
            .expect("illegal secp256r1 point");
        SecpPoint(point)
    }
}

impl From<SecpPoint> for [Word; SECP256R1_ARG_WORDS] {
    fn from(point: SecpPoint) -> [Word; SECP256R1_ARG_WORDS] {
        if bool::from(point.0.is_identity()) {
            return [0; SECP256R1_ARG_WORDS];
        }

        let encoded = point.0.to_encoded_point(false);
        let (x, y) = match encoded.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            _ => panic!("unexpected coordinate encoding"),
        };

        let mut x_bytes = [0u8; COORDINATE_WORDS * WORD_SIZE];
        x_bytes.copy_from_slice(x.as_slice());
        x_bytes.reverse();

        let mut y_bytes = [0u8; COORDINATE_WORDS * WORD_SIZE];
        y_bytes.copy_from_slice(y.as_slice());
        y_bytes.reverse();

        let x_words: [Word; COORDINATE_WORDS] = SecpCoordinate(x_bytes).into();
        let y_words: [Word; COORDINATE_WORDS] = SecpCoordinate(y_bytes).into();

        let mut words = [0u32; SECP256R1_ARG_WORDS];
        words[..COORDINATE_WORDS].copy_from_slice(&x_words);
        words[COORDINATE_WORDS..].copy_from_slice(&y_words);
        words
    }
}

/// Trace the execution of a secp256r1_add call
pub fn secp256r1_add<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
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
        [p_ptr, q_ptr].map(|start| MemoryView::<_, SECP256R1_ARG_WORDS>::new(vm, start));

    // Read P and Q from words via wrapper type
    let [p, q] = [&p_view, &q_view].map(|view| SecpPoint::from(view.words()));

    // Compute the sum and convert back to words
    let sum = ProjectivePoint::from(p.0) + ProjectivePoint::from(q.0);
    let output_words: [Word; SECP256R1_ARG_WORDS] = SecpPoint(AffinePoint::from(sum)).into();

    p_view.write(output_words);

    let mem_ops = p_view
        .mem_ops()
        .into_iter()
        .chain(q_view.mem_ops())
        .collect_vec();

    assert_eq!(mem_ops.len(), 2 * SECP256R1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

/// Trace the execution of a secp256r1_double call
pub fn secp256r1_double<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument pointers
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(p_ptr, p_ptr),
        0, // Cycle set later in finalize().
    )];

    // P's memory segment
    let mut p_view = MemoryView::<_, SECP256R1_ARG_WORDS>::new(vm, p_ptr);
    // Create point from words via wrapper type
    let p = SecpPoint::from(p_view.words());

    // Compute result and convert back into words
    let doubled = ProjectivePoint::from(p.0).double();
    let output_words: [Word; SECP256R1_ARG_WORDS] = SecpPoint(AffinePoint::from(doubled)).into();

    p_view.write(output_words);

    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), SECP256R1_ARG_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub fn secp256r1_invert<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let p_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument pointers
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(p_ptr, p_ptr),
        0, // Cycle set later in finalize().
    )];

    // P's memory segment
    let mut p_view = MemoryView::<_, COORDINATE_WORDS>::new(vm, p_ptr);
    let p = Scalar::from_repr(*FieldBytes::from_slice(&p_view.bytes())).expect("illegal p");
    let p_inv = p.invert().unwrap();
    let bytes: [u8; 32] = p_inv.to_bytes().into();
    let output_words: [Word; COORDINATE_WORDS] = unsafe { std::mem::transmute(bytes) };

    p_view.write(output_words);
    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), COORDINATE_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub const COORDINATE_WORDS: usize = SECP256R1_ARG_WORDS / 2;

/// Wrapper type for a single coordinate of a point on the secp256r1 curve.
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
