use crate::{
    Change, EmuContext, Platform, SyscallSpec, VMState, Word, WriteOp,
    syscalls::{SyscallEffects, SyscallWitness, bn254::types::Bn254Point},
    utils::MemoryView,
};

use super::types::BN254_POINT_WORDS;
use itertools::Itertools;

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
    let output_words: [Word; BN254_POINT_WORDS] = (p + q).into();

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

    let result = p.double();
    let output_words: [Word; BN254_POINT_WORDS] = result.into();

    p_view.write(output_words);

    let mem_ops = p_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), BN254_POINT_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
