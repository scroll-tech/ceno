use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
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
    pub addend_0: UInt64,
    pub addend_1: UInt64,
    pub imm: UInt64, // which type?
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub prev_rs1_ts: TSUInt,
    pub prev_rs2_ts: TSUInt,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for BltInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::BType(OPType::BRANCH, 0x004);
}

fn blt_gadget<E: ExtensionField, const IS_ADD: bool>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    todo!()
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
