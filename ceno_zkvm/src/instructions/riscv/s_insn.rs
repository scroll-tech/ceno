use crate::{
    chip_handler::{AddressExpr, MemoryExpr, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    instructions::riscv::insn_base::{ReadRS1, ReadRS2, StateInOut, WriteMEM},
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

/// This config handles the common part of S-type instructions:
/// - PC, cycle, fetch.
/// - Registers reads.
/// - Memory write
pub struct SInstructionConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    rs1: ReadRS1<E>,
    rs2: ReadRS2<E>,
    mem_write: WriteMEM<E>,
}

impl<E: ExtensionField> SInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        memory_addr: AddressExpr<E>,
        memory_value: MemoryExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, false)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rs2 = ReadRS2::construct_circuit(circuit_builder, rs2_read, vm_state.ts)?;

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            0.into(),
            (insn_kind.codes().func3 as usize).into(),
            rs1.id.expr(),
            rs2.id.expr(),
            imm.clone(),
        ))?;

        // Memory
        let mem_write =
            WriteMEM::construct_circuit(circuit_builder, memory_addr, memory_value, vm_state.ts)?;

        Ok(SInstructionConfig {
            vm_state,
            rs1,
            rs2,
            mem_write,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.vm_state.assign_instance(instance, step)?;
        self.rs1.assign_instance(instance, lk_multiplicity, step)?;
        self.rs2.assign_instance(instance, lk_multiplicity, step)?;
        self.mem_write
            .assign_instance(instance, lk_multiplicity, step)?;

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
