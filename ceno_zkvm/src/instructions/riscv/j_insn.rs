use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
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
/// It does not witness the output rd value or next_pc produced by the JAL opcode
#[derive(Debug)]
pub struct JInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rd: WriteRD<E>,
}

impl<E: ExtensionField> JInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rd_written: RegisterExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, true)?;

        // Registers
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts)?;

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            rd.id.expr(),
            0.into(),
            0.into(),
            0.into(),
            imm.clone(),
        ))?;

        Ok(JInstructionConfig { vm_state, rd })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
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