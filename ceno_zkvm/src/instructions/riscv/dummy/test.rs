use ceno_emul::KeccakSpec;
use ff_ext::GoldilocksExt2;

use super::LargeEcallDummy;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::ShardContext,
    instructions::Instruction,
    scheme::mock_prover::MockProver,
    structs::ProgramParams,
};

#[test]
fn test_large_ecall_dummy_keccak() {
    type KeccakDummy = LargeEcallDummy<GoldilocksExt2, KeccakSpec>;

    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = KeccakDummy::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

    let (step, program) = ceno_emul::test_utils::keccak_step();
    let (raw_witin, lkm) = KeccakDummy::assign_instances(
        &config,
        &mut ShardContext::default(),
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
        &[step],
    )
    .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &program, 1, None, Some(lkm));
}
