use crate::{
    error::ZKVMError,
    instructions::riscv::{constants::UInt, i_insn::IInstructionConfig},
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use goldilocks::ExtensionField;
use std::mem::MaybeUninit;
use crate::chip_handler::MemoryExpr;
use crate::circuit_builder::CircuitBuilder;

pub struct IMInstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: UInt<E>,
    rs1_read: UInt<E>,
}

impl<E: ExtensionField> IMInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        memory_read: MemoryExpr<E>
    ) -> Result<Self, ZKVMError> {
        // configure i_insn
        // compute mem_addr
        // read memory at addr location

        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;

        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;

        // Memory read
        // what ts to use here
        // let ()

        todo!()
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
