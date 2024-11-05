use crate::{
    chip_handler::{AddressExpr, MemoryExpr, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    instructions::riscv::insn_base::{ReadMEM, ReadRS1, StateInOut, WriteRD},
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

/// This config handle the common part of I-type Instruction (memory variant)
/// - PC, cycle, fetch
/// - Register reads and writes
/// - Memory reads
pub struct IMInstructionConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    rs1: ReadRS1<E>,
    rd: WriteRD<E>,
    mem_read: ReadMEM<E>,
}

impl<E: ExtensionField> IMInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        memory_read: MemoryExpr<E>,
        memory_addr: AddressExpr<E>,
        rd_written: RegisterExpr<E>,
    ) -> Result<Self, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(circuit_builder, false)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts)?;

        // Memory
        let mem_read =
            ReadMEM::construct_circuit(circuit_builder, memory_addr, memory_read, vm_state.ts)?;

        // Fetch the instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.into(),
            Some(rd.id.expr()),
            rs1.id.expr(),
            0.into(),
            imm.clone(),
        ))?;

        Ok(IMInstructionConfig {
            vm_state,
            rs1,
            rd,
            mem_read,
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
        self.rd.assign_instance(instance, lk_multiplicity, step)?;
        self.mem_read
            .assign_instance(instance, lk_multiplicity, step)?;

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
