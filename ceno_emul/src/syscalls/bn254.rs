use super::{SyscallEffects, SyscallSpec};
use crate::{
    Change, EmuContext, Platform, VMState, Word, WriteOp, syscalls::SyscallWitness,
    utils::MemoryView,
};

use itertools::Itertools;
use substrate_bn::{AffineG1, Fq, Fq2, Fr, G1, Group};

pub const BN254_POINT_WORDS: usize = BN254_FP_WORDS * 2;

pub struct Bn254AddSpec;
impl SyscallSpec for Bn254AddSpec {
    const NAME: &'static str = "BN254_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * BN254_POINT_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_ADD;
}

pub struct Bn254DoubleSpec;
impl SyscallSpec for Bn254DoubleSpec {
    const NAME: &'static str = "BN254_DOUBLE";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = BN254_POINT_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_DOUBLE;
}

pub struct Bn254FpAddSpec;
impl SyscallSpec for Bn254FpAddSpec {
    const NAME: &'static str = "BN254_FP_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * BN254_FP_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_FP_ADD;
}

pub struct Bn254Fp2AddSpec;
impl SyscallSpec for Bn254Fp2AddSpec {
    const NAME: &'static str = "BN254_FP2_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * BN254_FP2_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_FP2_ADD;
}

pub struct Bn254FpMulSpec;
impl SyscallSpec for Bn254FpMulSpec {
    const NAME: &'static str = "BN254_FP_MUL";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * BN254_FP_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_FP_MUL;
}

pub struct Bn254Fp2MulSpec;
impl SyscallSpec for Bn254Fp2MulSpec {
    const NAME: &'static str = "BN254_FP2_MUL";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * BN254_FP2_WORDS;
    const CODE: u32 = ceno_rt::syscalls::BN254_FP2_MUL;
}

#[derive(Debug)]
struct Bn254Point(substrate_bn::G1);

impl From<[Word; BN254_POINT_WORDS]> for Bn254Point {
    fn from(value: [Word; BN254_POINT_WORDS]) -> Self {
        let first_half: [Word; BN254_FP_WORDS] = value[..BN254_FP_WORDS].try_into().unwrap();
        let second_half: [Word; BN254_FP_WORDS] = value[BN254_FP_WORDS..].try_into().unwrap();
        let a = Bn254Fp::from(first_half).0;
        let b = Bn254Fp::from(second_half).0;
        Bn254Point(G1::new(a, b, Fq::one()))
    }
}

impl From<Bn254Point> for [Word; BN254_POINT_WORDS] {
    fn from(value: Bn254Point) -> Self {
        let affine = AffineG1::from_jacobian(value.0).expect("cannot unpack affine");
        let first_half: [Word; BN254_FP_WORDS] = Bn254Fp(affine.x()).into();
        let second_half: [Word; BN254_FP_WORDS] = Bn254Fp(affine.y()).into();

        [first_half, second_half].concat().try_into().unwrap()
    }
}

pub fn bn254_add(vm: &VMState) -> SyscallEffects {
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
        [p_ptr, q_ptr].map(|start| MemoryView::<BN254_POINT_WORDS>::new(vm, start));

    // Read P and Q from words via wrapper type
    let [p, q] = [&p_view, &q_view].map(|view| Bn254Point::from(view.words()));

    // TODO: what does sp1 do with invalid points? equal points?
    // Compute the sum and convert back to words
    let sum = Bn254Point(p.0 + q.0);
    let output_words: [Word; BN254_POINT_WORDS] = sum.into();

    println!("{:?}", output_words);

    p_view.write(output_words);

    let mem_ops = p_view
        .mem_ops()
        .into_iter()
        .chain(q_view.mem_ops())
        .collect_vec();

    assert_eq!(mem_ops.len(), 2 * BN254_POINT_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub fn bn254_double(vm: &VMState) -> SyscallEffects {
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
    let mut p_view = MemoryView::<BN254_POINT_WORDS>::new(vm, p_ptr);
    // Create point from words via wrapper type
    let p = Bn254Point::from(p_view.words());

    // Compute result and convert back into words
    let two = Fr::from_str("2").unwrap();

    let result = Bn254Point(p.0 * two);
    let output_words: [Word; BN254_POINT_WORDS] = result.into();

    p_view.write(output_words);

    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), BN254_POINT_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub const BN254_FP_WORDS: usize = 8;

pub struct Bn254Fp(substrate_bn::Fq);

impl From<[Word; BN254_FP_WORDS]> for Bn254Fp {
    fn from(value: [Word; BN254_FP_WORDS]) -> Self {
        let bytes_be = value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .rev()
            .collect_vec();
        Bn254Fp(Fq::from_slice(&bytes_be).expect("cannot parse Fq"))
    }
}

impl From<Bn254Fp> for [Word; BN254_FP_WORDS] {
    fn from(value: Bn254Fp) -> Self {
        let mut bytes_be = [0u8; 32];
        value
            .0
            .to_big_endian(&mut bytes_be)
            .expect("cannot serialize Fq");
        bytes_be.reverse();

        bytes_be
            .chunks_exact(4)
            .map(|chunk| Word::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

pub fn bn254_fp_binary_op(vm: &VMState, is_add: bool) -> SyscallEffects {
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
        [p_ptr, q_ptr].map(|start| MemoryView::<BN254_FP_WORDS>::new(vm, start));

    let p = Bn254Fp::from(p_view.words());
    let q = Bn254Fp::from(q_view.words());
    let result = match is_add {
        true => Bn254Fp(p.0 + q.0),
        false => Bn254Fp(p.0 * q.0),
    };
    p_view.write(result.into());

    let p_mem_ops = p_view.mem_ops();
    let q_mem_ops = q_view.mem_ops();

    let mem_ops = p_mem_ops.into_iter().chain(q_mem_ops).collect_vec();

    assert_eq!(mem_ops.len(), 2 * BN254_FP_WORDS);

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub const BN254_FP2_WORDS: usize = 2 * BN254_FP_WORDS;

pub struct Bn254Fp2(substrate_bn::Fq2);

impl From<[Word; BN254_FP2_WORDS]> for Bn254Fp2 {
    fn from(value: [Word; BN254_FP2_WORDS]) -> Self {
        let first_half: [Word; BN254_FP_WORDS] = value[..BN254_FP_WORDS].try_into().unwrap();
        let second_half: [Word; BN254_FP_WORDS] = value[BN254_FP_WORDS..].try_into().unwrap();
        // notation: Fq2 is a + bi (a real and b imaginary)
        let a = Bn254Fp::from(first_half).0;
        let b = Bn254Fp::from(second_half).0;
        Bn254Fp2(Fq2::new(a, b))
    }
}

impl From<Bn254Fp2> for [Word; BN254_FP2_WORDS] {
    fn from(value: Bn254Fp2) -> Self {
        // notation: Fq2 is a + bi (a real and b imaginary)
        let first_half: [Word; BN254_FP_WORDS] = Bn254Fp(value.0.real()).into();
        let second_half: [Word; BN254_FP_WORDS] = Bn254Fp(value.0.imaginary()).into();

        [first_half, second_half].concat().try_into().unwrap()
    }
}

pub fn bn254_fp2_binary_op(vm: &VMState, is_add: bool) -> SyscallEffects {
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
        [p_ptr, q_ptr].map(|start| MemoryView::<BN254_FP2_WORDS>::new(vm, start));

    let p = Bn254Fp2::from(p_view.words());
    let q = Bn254Fp2::from(q_view.words());
    let result = match is_add {
        true => Bn254Fp2(p.0 + q.0),
        false => Bn254Fp2(p.0 * q.0),
    };
    p_view.write(result.into());

    let p_mem_ops = p_view.mem_ops();
    let q_mem_ops = q_view.mem_ops();

    let mem_ops = p_mem_ops.into_iter().chain(q_mem_ops).collect_vec();

    assert_eq!(mem_ops.len(), 2 * BN254_FP2_WORDS);

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub fn bn254_fp_add(vm: &VMState) -> SyscallEffects {
    bn254_fp_binary_op(vm, true)
}

pub fn bn254_fp_mul(vm: &VMState) -> SyscallEffects {
    bn254_fp_binary_op(vm, false)
}

pub fn bn254_fp2_add(vm: &VMState) -> SyscallEffects {
    bn254_fp2_binary_op(vm, true)
}

pub fn bn254_fp2_mul(vm: &VMState) -> SyscallEffects {
    bn254_fp2_binary_op(vm, false)
}
