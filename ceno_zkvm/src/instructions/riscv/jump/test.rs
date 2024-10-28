use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, Word, encode_rv32};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::test_utils::{imm_j, imm_u},
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
};

use super::{AuipcInstruction, JalInstruction, JalrInstruction, LuiInstruction};

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

    let pc_offset: i32 = -8i32;
    let new_pc: ByteAddr = ByteAddr(MOCK_PC_START.0.wrapping_add_signed(pc_offset));
    let insn_code = encode_rv32(InsnKind::JAL, 0, 0, 4, imm_j(pc_offset));
    let (raw_witin, lkm) = JalInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_j_instruction(
            4,
            Change::new(MOCK_PC_START, new_pc),
            insn_code,
            Change::new(0, (MOCK_PC_START + PC_STEP_SIZE).into()),
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
        &[insn_code],
        None,
        Some(lkm),
    );
}

#[test]
fn test_opcode_jalr() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "jalr",
            |cb| {
                let config = JalrInstruction::<GoldilocksExt2>::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let imm = -15i32;
    let rs1_read: Word = 10u32;
    let new_pc: ByteAddr = ByteAddr(rs1_read.wrapping_add_signed(imm) & (!1));
    let insn_code = encode_rv32(InsnKind::JALR, 2, 0, 4, imm as u32);

    let (raw_witin, lkm) = JalrInstruction::<GoldilocksExt2>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_i_instruction(
            4,
            Change::new(MOCK_PC_START, new_pc),
            insn_code,
            rs1_read,
            Change::new(0, (MOCK_PC_START + PC_STEP_SIZE).into()),
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
        &[insn_code],
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

    let imm_value = imm_u(0x90005);
    let insn_code = encode_rv32(InsnKind::LUI, 0, 0, 4, imm_value);
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

    MockProver::assert_satisfied(
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

    let imm_value = imm_u(0x90005);
    let insn_code = encode_rv32(InsnKind::AUIPC, 0, 0, 4, imm_value);
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

    MockProver::assert_satisfied(
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
