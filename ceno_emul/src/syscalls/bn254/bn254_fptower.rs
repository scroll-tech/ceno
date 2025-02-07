use itertools::Itertools;

use crate::{
    Change, EmuContext, Platform, SyscallSpec, VMState, WriteOp,
    syscalls::{
        SyscallEffects, SyscallWitness,
        bn254::types::{Bn254Fp, Bn254Fp2},
    },
    utils::MemoryView,
};

use super::types::{BN254_FP_WORDS, BN254_FP2_WORDS};

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

fn bn254_fp_binary_op(vm: &VMState, is_add: bool) -> SyscallEffects {
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
        true => p + q,
        false => p * q,
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

fn bn254_fp2_binary_op(vm: &VMState, is_add: bool) -> SyscallEffects {
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
        true => p + q,
        false => p * q,
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
