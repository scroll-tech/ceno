use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::Instruction,
    structs::{PCUInt, TSUInt, UInt64},
};

use super::{
    constants::{OPType, OpcodeType, RISCV64_PC_STEP_SIZE},
    RIVInstruction,
};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: PCUInt,
    pub ts: TSUInt,
    pub operand_0: UInt64,
    pub operand_1: UInt64,
    pub imm: WitIn,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub prev_rs1_ts: TSUInt,
    pub prev_rs2_ts: TSUInt,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for BltInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::BType(OPType::Branch, 0x004);
}

/// if (rs1 < rs2) PC += sext(imm)
/// imm is a 12 bit integer
fn blt_gadget<E: ExtensionField, const IS_ADD: bool>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = PCUInt::new(circuit_builder);
    let mut ts = TSUInt::new(circuit_builder);

    // state in
    circuit_builder.state_in(&pc, &ts)?;

    let operand_0 = UInt64::new(circuit_builder);
    let operand_1 = UInt64::new(circuit_builder);
    let borrow = operand_0.sub_with_borrow(circuit_builder, &operand_1)?;

    let rs1_id = circuit_builder.create_witin();
    let rs2_id = circuit_builder.create_witin();
    circuit_builder.assert_u5(rs1_id.expr())?;
    circuit_builder.assert_u5(rs2_id.expr())?;

    // TODO: can we assume imm is already sext(imm)?
    // replaced imm by sext(imm): UInt64 for next_pc_1
    let imm = circuit_builder.create_witin();
    circuit_builder.assert_u12(imm.expr())?;
    let next_pc_1 = pc.add_const(circuit_builder, imm.expr())?;
    let next_pc_2 = pc.add_const(circuit_builder, RISCV64_PC_STEP_SIZE.into())?;
    let next_pc = PCUInt::new(circuit_builder);
    circuit_builder.require_zero(
        borrow.expr() * next_pc_1.value_expr()
            + (Expression::from(1) - borrow.expr()) * next_pc_2.value_expr()
            - next_pc.value_expr(),
    )?;

    let mut prev_rs1_ts = TSUInt::new(circuit_builder);
    let mut prev_rs2_ts = TSUInt::new(circuit_builder);
    let mut ts = circuit_builder.register_read(&rs1_id, &mut prev_rs1_ts, &mut ts, &operand_0)?;
    let _ = circuit_builder.register_read(&rs2_id, &mut prev_rs2_ts, &mut ts, &operand_1)?;

    let next_ts = ts.add_const(circuit_builder, 1.into())?;
    circuit_builder.state_out(&next_pc, &next_ts)?;

    Ok(InstructionConfig {
        pc,
        ts,
        operand_0,
        operand_1,
        imm,
        rs1_id,
        rs2_id,
        prev_rs1_ts,
        prev_rs2_ts,
        phantom: PhantomData,
    })
}

impl<E: ExtensionField> Instruction<E> for BltInstruction {
    // const NAME: &'static str = "BLT";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        blt_gadget::<E, true>(circuit_builder)
    }
}
