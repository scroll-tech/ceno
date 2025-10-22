use super::{JalInstruction, JalrInstruction};
use crate::{
    Value,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{Instruction, riscv::constants::UInt},
    scheme::mock_prover::{MOCK_PC_START, MockProver},
    structs::ProgramParams,
};
use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, Word, encode_rv32};
#[cfg(feature = "u16limb_circuit")]
use ff_ext::BabyBearExt4;
use ff_ext::{ExtensionField, GoldilocksExt2};
use gkr_iop::circuit_builder::DebugIndex;

#[test]
fn test_opcode_jal() {
    verify_test_opcode_jal::<GoldilocksExt2>(-8);
    verify_test_opcode_jal::<GoldilocksExt2>(8);

    #[cfg(feature = "u16limb_circuit")]
    {
        verify_test_opcode_jal::<BabyBearExt4>(-8);
        verify_test_opcode_jal::<BabyBearExt4>(8);
    }
}

fn verify_test_opcode_jal<E: ExtensionField>(pc_offset: i32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let inst = JalInstruction::default();
    let config = cb
        .namespace(
            || "jal",
            |cb| {
                let config = inst.construct_circuit(cb, &ProgramParams::default());
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let new_pc: ByteAddr = ByteAddr(MOCK_PC_START.0.wrapping_add_signed(pc_offset));
    let insn_code = encode_rv32(InsnKind::JAL, 0, 0, 4, pc_offset);
    let (raw_witin, lkm) = JalInstruction::<E>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
        vec![StepRecord::new_j_instruction(
            4,
            Change::new(MOCK_PC_START, new_pc),
            insn_code,
            Change::new(0, (MOCK_PC_START + PC_STEP_SIZE).into()),
            0,
        )],
    )
    .unwrap();

    // verify rd_written
    let expected_rd_written = UInt::from_const_unchecked(
        Value::new_unchecked(MOCK_PC_START.0 + PC_STEP_SIZE as u32)
            .as_u16_limbs()
            .to_vec(),
    );
    let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
    cb.require_equal(
        || "assert_rd_written",
        rd_written_expr,
        expected_rd_written.value(),
    )
    .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

#[test]
fn test_opcode_jalr() {
    verify_test_opcode_jalr::<GoldilocksExt2>(100, 3);
    verify_test_opcode_jalr::<GoldilocksExt2>(100, -3);

    #[cfg(feature = "u16limb_circuit")]
    {
        verify_test_opcode_jalr::<BabyBearExt4>(100, 3);
        verify_test_opcode_jalr::<BabyBearExt4>(100, -3);
    }
}

fn verify_test_opcode_jalr<E: ExtensionField>(rs1_read: Word, imm: i32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let inst = JalrInstruction::default();
    let config = cb
        .namespace(
            || "jalr",
            |cb| {
                let config = inst.construct_circuit(cb, &ProgramParams::default());
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    // trim lower bit to 0
    let new_pc: ByteAddr = ByteAddr(rs1_read.wrapping_add_signed(imm) & (!1));
    let insn_code = encode_rv32(InsnKind::JALR, 2, 0, 4, imm);

    // verify rd_written
    let expected_rd_written = UInt::from_const_unchecked(
        Value::new_unchecked(MOCK_PC_START.0 + PC_STEP_SIZE as u32)
            .as_u16_limbs()
            .to_vec(),
    );
    let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
    cb.require_equal(
        || "assert_rd_written",
        rd_written_expr,
        expected_rd_written.value(),
    )
    .unwrap();

    let (raw_witin, lkm) = JalrInstruction::<E>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
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
    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}
