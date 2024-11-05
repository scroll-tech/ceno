use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    instructions::riscv::insn_base::{ReadRS1, StateInOut, WriteRD},
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles the common part of I-type instructions:
/// - PC, cycle, fetch.
/// - Registers read and write.
///
/// It does not witness of the register values, nor the actual function (e.g. srli, addi, etc).
#[derive(Debug)]
pub struct IInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rs1: ReadRS1<E>,
    pub rd: WriteRD<E>,
}

impl<E: ExtensionField> IInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        rd_written: RegisterExpr<E>,
        branching: bool,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, branching)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts)?;

        // TODO make imm representation consistent between instruction types

        // Fetch the instruction.
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.into(),
            Some(rd.id.expr()),
            rs1.id.expr(),
            0.into(),
            imm.clone(),
        ))?;

        Ok(IInstructionConfig { vm_state, rs1, rd })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.vm_state.assign_instance(instance, step)?;
        self.rs1.assign_instance(instance, lk_multiplicity, step)?;
        self.rd.assign_instance(instance, lk_multiplicity, step)?;

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
