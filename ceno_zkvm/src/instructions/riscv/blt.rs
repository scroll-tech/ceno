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
    constants::{OPType, OpcodeType, PC_STEP_SIZE},
    RIVInstruction,
};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: PCUInt,
    pub ts: TSUInt,
    pub lhs: UInt64,
    pub rhs: UInt64,
    pub imm: UInt64,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub prev_rs1_ts: TSUInt,
    pub prev_rs2_ts: TSUInt,
    pub lt: WitIn,
    pub ltu: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for BltInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::BType(OPType::Branch, 0x004);
}

/// if (rs1 < rs2) PC += sext(imm)
fn blt_gadget<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = PCUInt::new(circuit_builder);
    let mut ts = TSUInt::new(circuit_builder);
    circuit_builder.state_in(&pc, &ts)?;

    let rs1_id = circuit_builder.create_witin();
    let rs2_id = circuit_builder.create_witin();
    circuit_builder.assert_u5(rs1_id.expr())?;
    circuit_builder.assert_u5(rs2_id.expr())?;

    let lhs = UInt64::new(circuit_builder);
    let rhs = UInt64::new(circuit_builder);
    // imm is already sext(imm) from instruction
    let imm = UInt64::new(circuit_builder);

    // is true when lhs < rhs as sign
    let ltu = circuit_builder.create_witin();
    // is true when lhs < rhs as usign
    let lt = circuit_builder.create_witin();
    circuit_builder.assert_bit(ltu.expr())?;
    circuit_builder.assert_bit(lt.expr())?;

    let (lhs_msb, _) = lhs.msb_decompose(circuit_builder)?;
    let (rhs_msb, _) = rhs.msb_decompose(circuit_builder)?;

    // (1) compute ltu(a_{<s},b_{<s})

    // (2) compute $lt(a,b)=a_s\cdot (1-b_s)+eq(a_s,b_s)\cdot ltu(a_{<s},b_{<s})$
    // Source: Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)

    // update pc
    let next_pc_1 = pc.add(circuit_builder, &imm)?;
    let next_pc_2 = pc.add_const(circuit_builder, PC_STEP_SIZE.into())?;
    let next_pc = PCUInt::select_if(circuit_builder, lt.expr(), next_pc_1, next_pc_2)?;

    // update ts
    let mut prev_rs1_ts = TSUInt::new(circuit_builder);
    let mut prev_rs2_ts = TSUInt::new(circuit_builder);
    let mut ts = circuit_builder.register_read(&rs1_id, &mut prev_rs1_ts, &mut ts, &lhs)?;
    let _ = circuit_builder.register_read(&rs2_id, &mut prev_rs2_ts, &mut ts, &rhs)?;

    let next_ts = ts.add_const(circuit_builder, 1.into())?;
    circuit_builder.state_out(&next_pc, &next_ts)?;

    Ok(InstructionConfig {
        pc,
        ts,
        lhs,
        rhs,
        imm,
        rs1_id,
        rs2_id,
        prev_rs1_ts,
        prev_rs2_ts,
        ltu,
        lt,
        phantom: PhantomData,
    })
}

impl<E: ExtensionField> Instruction<E> for BltInstruction {
    // const NAME: &'static str = "BLT";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        blt_gadget::<E>(circuit_builder)
    }
}
