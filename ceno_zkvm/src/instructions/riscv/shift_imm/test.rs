use ceno_emul::{Change, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{riscv::constants::UInt, Instruction},
    scheme::mock_prover::{MockProver, MOCK_PC_SRLI, MOCK_PC_SRLI_31, MOCK_PROGRAM},
    Value,
};

use super::{shift_imm_circuit::ShiftImmInstruction, SrliOp};

#[test]
fn test_opcode_srli_1() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "srli",
            |cb| {
                let config = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (raw_witin, _) = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_i_instruction(
            3,
            MOCK_PC_SRLI,
            MOCK_PROGRAM[10],
            32,
            Change::new(0, 32 >> 3),
            0,
        )],
    )
    .unwrap();

    let expected_rd_written =
        UInt::from_const_unchecked(Value::new_unchecked(32u32 >> 3).as_u16_limbs().to_vec());

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
        .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
    );
}

#[test]
fn test_opcode_srli_2() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "srli",
            |cb| {
                let config = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (raw_witin, _) = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_i_instruction(
            3,
            MOCK_PC_SRLI_31,
            MOCK_PROGRAM[11],
            32,
            Change::new(0, 32 >> 31),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
    );
}
