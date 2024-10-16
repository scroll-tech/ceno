use ceno_emul::{ByteAddr, Change, PC_STEP_SIZE, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MOCK_PC_AUIPC, MOCK_PC_JAL, MOCK_PC_LUI, MOCK_PROGRAM, MockProver},
};

use super::{AuipcInstruction, JalInstruction, LuiInstruction};

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
    let (raw_witin, lkm) = JalInstruction::<GoldilocksExt2>::assign_instances(
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
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
}

#[test]
fn test_opcode_lui() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "lui",
            |cb| {
                let config = LuiInstruction::<GoldilocksExt2>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let lui_insn = MOCK_PROGRAM[22];
    let imm = lui_insn & 0xfffff000;
    let (raw_witin, lkm) = LuiInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_u_instruction(
            4,
            MOCK_PC_LUI,
            lui_insn,
            Change::new(0, imm),
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
        Some(lkm),
    );
}

#[test]
fn test_opcode_auipc() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "auipc",
            |cb| {
                let config = AuipcInstruction::<GoldilocksExt2>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let auipc_insn = MOCK_PROGRAM[23];
    let imm = auipc_insn & 0xfffff000;
    let (raw_witin, lkm) = AuipcInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_u_instruction(
            4,
            MOCK_PC_AUIPC,
            auipc_insn,
            Change::new(0, MOCK_PC_AUIPC.0.wrapping_add(imm)),
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
        Some(lkm),
    );
}
