use itertools::Itertools;

use crate::{
    Change, EmuContext, Platform, SyscallSpec, VMState, Word, WriteOp,
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

fn bn254_fptower_binary_op<
    const WORDS: usize,
    const IS_ADD: bool,
    F: From<[Word; WORDS]>
        + Into<[Word; WORDS]>
        + std::ops::Add<Output = F>
        + std::ops::Mul<Output = F>,
>(
    vm: &VMState,
) -> SyscallEffects {
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
    let [mut p_view, q_view] = [p_ptr, q_ptr].map(|start| MemoryView::<WORDS>::new(vm, start));

    let p = F::from(p_view.words());
    let q = F::from(q_view.words());
    let result = match IS_ADD {
        true => p + q,
        false => p * q,
    };
    p_view.write(result.into());

    let mem_ops = p_view
        .mem_ops()
        .into_iter()
        .chain(q_view.mem_ops())
        .collect_vec();

    assert_eq!(mem_ops.len(), 2 * WORDS);

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}

pub fn bn254_fp_add(vm: &VMState) -> SyscallEffects {
    bn254_fptower_binary_op::<BN254_FP_WORDS, true, Bn254Fp>(vm)
}

pub fn bn254_fp_mul(vm: &VMState) -> SyscallEffects {
    bn254_fptower_binary_op::<BN254_FP_WORDS, false, Bn254Fp>(vm)
}

pub fn bn254_fp2_add(vm: &VMState) -> SyscallEffects {
    bn254_fptower_binary_op::<BN254_FP2_WORDS, true, Bn254Fp2>(vm)
}

pub fn bn254_fp2_mul(vm: &VMState) -> SyscallEffects {
    bn254_fptower_binary_op::<BN254_FP2_WORDS, false, Bn254Fp2>(vm)
}
