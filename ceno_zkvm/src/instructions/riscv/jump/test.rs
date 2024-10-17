use ceno_emul::{ByteAddr, Change, EncodedInstruction, InsnKind, PC_STEP_SIZE, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MOCK_PC_JAL, MOCK_PC_START, MOCK_PROGRAM, MockProver},
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

fn imm(imm: u32) -> u32 {
    // valid imm is imm[12:31] in U-type
    imm << 12
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

    let imm_value = imm(0x90005);
    let insn_code = EncodedInstruction::encode(InsnKind::LUI, 0, 0, 4, imm_value);
    let (raw_witin, lkm) = LuiInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_u_instruction(
            4,
            MOCK_PC_START,
            insn_code,
            Change::new(0, imm_value),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied_with_program(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        &[insn_code],
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

    let imm_value = imm(0x90005);
    let insn_code = EncodedInstruction::encode(InsnKind::AUIPC, 0, 0, 4, imm_value);
    let (raw_witin, lkm) = AuipcInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_u_instruction(
            4,
            MOCK_PC_START,
            insn_code,
            Change::new(0, MOCK_PC_START.0.wrapping_add(imm_value)),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied_with_program(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        &[insn_code],
        None,
        Some(lkm),
    );
}
