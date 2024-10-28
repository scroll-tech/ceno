use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    expression::ToExpr,
    instructions::riscv::insn_base::{ReadRS1, ReadRS2, StateInOut, WriteRD},
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles the common part of R-type instructions:
/// - PC, cycle, fetch.
/// - Registers read and write.
///
/// It does not witness of the register values, nor the actual function (e.g. add, sub, etc).
#[derive(Debug)]
pub struct RInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rs1: ReadRS1<E>,
    pub rs2: ReadRS2<E>,
    pub rd: WriteRD<E>,
}

impl<E: ExtensionField> RInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        rd_written: RegisterExpr<E>,
    ) -> Self {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, false);

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts);
        let rs2 = ReadRS2::construct_circuit(circuit_builder, rs2_read, vm_state.ts);
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts);

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.codes().opcode.into(),
            rd.id.expr(),
            insn_kind.codes().func3.into(),
            rs1.id.expr(),
            rs2.id.expr(),
            insn_kind.codes().func7.into(),
        ));

        RInstructionConfig {
            vm_state,
            rs1,
            rs2,
            rd,
        }
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) {
        self.vm_state.assign_instance(instance, step);
        self.rs1.assign_instance(instance, lk_multiplicity, step);
        self.rs2.assign_instance(instance, lk_multiplicity, step);
        self.rd.assign_instance(instance, lk_multiplicity, step);

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);
    }
}
