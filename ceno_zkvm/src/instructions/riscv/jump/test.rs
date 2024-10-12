use ceno_emul::{ByteAddr, Change, StepRecord, PC_STEP_SIZE};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MockProver, MOCK_PC_JAL, MOCK_PROGRAM},
};

use super::JalInstruction;

#[test]
fn test_opcode_jal() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "jal",
            |cb| {
                let config = JalInstruction::<GoldilocksExt2>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let pc_offset: i32 = -4i32;
    let new_pc: ByteAddr = ByteAddr(MOCK_PC_JAL.0.wrapping_add_signed(pc_offset));
    let (raw_witin, _lkm) = JalInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_j_instruction(
            4,
            Change::new(MOCK_PC_JAL, new_pc),
            MOCK_PROGRAM[21],
            Change::new(0, (MOCK_PC_JAL + PC_STEP_SIZE).into()),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied(
        &mut cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
    );
}
