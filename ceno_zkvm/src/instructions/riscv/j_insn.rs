use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::riscv::insn_base::{StateInOut, WriteRD},
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

// Opcode: 1101111

/// This config handles the common part of the J-type instruction (JAL):
/// - PC, cycle, fetch
/// - Register access
///
/// It does not witness the output rd value produced by the JAL opcode, but
/// does constrain next_pc = pc + imm using the instruction table lookup
#[derive(Debug)]
pub struct JInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rd: WriteRD<E>,
}

impl<E: ExtensionField> JInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        rd_written: RegisterExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, true)?;

        // Registers
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts)?;

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.into(),
            Some(rd.id.expr()),
            0.into(),
            0.into(),
            vm_state.next_pc.unwrap().expr() - vm_state.pc.expr(),
        ))?;

        Ok(JInstructionConfig { vm_state, rd })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.vm_state.assign_instance(instance, step)?;
        self.rd.assign_instance(instance, lk_multiplicity, step)?;

        // Fetch the instruction.
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
