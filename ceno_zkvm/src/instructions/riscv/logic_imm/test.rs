use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32u};
use ff_ext::GoldilocksExt2;
use gkr_iop::circuit_builder::DebugIndex;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::{
            constants::UInt8,
            logic_imm::{AndiOp, LogicInstruction, LogicOp, OriOp, XoriOp},
        },
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
    structs::ProgramParams,
    utils::split_to_u8,
};

/// An arbitrary test value.
const TEST: u32 = 0xabed_5eff;
/// An example of a sign-extended negative immediate value.
const NEG: u32 = 0xffff_ff55;

#[test]
fn test_opcode_andi() {
    verify::<AndiOp>("basic", 0x0000_0011, 3, 0x0000_0011 & 3);
    verify::<AndiOp>("zero result", 0x0000_0100, 3, 0x0000_0100 & 3);
    verify::<AndiOp>("negative imm", TEST, NEG, TEST & NEG);
}

#[test]
fn test_opcode_ori() {
    verify::<OriOp>("basic", 0x0000_0011, 3, 0x0000_0011 | 3);
    verify::<OriOp>("basic2", 0x0000_0100, 3, 0x0000_0100 | 3);
    verify::<OriOp>("negative imm", TEST, NEG, TEST | NEG);
}

#[test]
fn test_opcode_xori() {
    verify::<XoriOp>("basic", 0x0000_0011, 3, 0x0000_0011 ^ 3);
    verify::<XoriOp>("non-overlap", 0x0000_0100, 3, 0x0000_0100 ^ 3);
    verify::<XoriOp>("negative imm", TEST, NEG, TEST ^ NEG);
}

fn verify<I: LogicOp>(name: &'static str, rs1_read: u32, imm: u32, expected_rd_written: u32) {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);

    let (prefix, rd_written) = match I::INST_KIND {
        InsnKind::ANDI => ("ANDI", rs1_read & imm),
        InsnKind::ORI => ("ORI", rs1_read | imm),
        InsnKind::XORI => ("XORI", rs1_read ^ imm),
        _ => unreachable!(),
    };

    let config = cb
        .namespace(
            || format!("{prefix}_({name})"),
            |cb| {
                let config = LogicInstruction::<GoldilocksExt2, I>::construct_circuit(
                    cb,
                    &ProgramParams::default(),
                );
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32u(I::INST_KIND, 2, 0, 4, imm);
    let (raw_witin, lkm) = LogicInstruction::<GoldilocksExt2, I>::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
        vec![StepRecord::new_i_instruction(
            3,
            Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
            insn_code,
            rs1_read,
            Change::new(0, rd_written),
            0,
        )],
    )
    .unwrap();

    let expected = UInt8::from_const_unchecked(split_to_u8::<u64>(expected_rd_written));
    let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
    cb.require_equal(|| "assert_rd_written", rd_written_expr, expected.value())
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}
