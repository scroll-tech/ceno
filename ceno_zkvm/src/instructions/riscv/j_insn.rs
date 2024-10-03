#![allow(dead_code)] // TODO: remove after BLT, BEQ, …

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::riscv::insn_base::{StateInOut, WriteRD},
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

// Opcode: 1100011
// Funct3:
//   000  BEQ
//   001  BNE
//   100  BLT
//   101  BGE
//   110  BLTU
//   111  BGEU
//

/// This config handles the common part of the J-type instruction (JAL):
/// - PC, cycle, fetch
/// - Register access
///
/// It does not witness the output rd value or next_pc produced by the JAL opcode
#[derive(Debug)]
pub struct JInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rd: WriteRD<E>,
    pub imm: WitIn,
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

        // Immediate
        let imm = circuit_builder.create_witin(|| "imm")?;

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            rd.id.expr(),
            (insn_kind.codes().func3 as usize).into(),
            0.into(),
            0.into(),
            imm.expr(),
        ))?;

        Ok(JInstructionConfig { vm_state, rd, imm })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.vm_state.assign_instance(instance, step)?;
        self.rd.assign_instance(instance, lk_multiplicity, step)?;

        // Immediate
        set_val!(
            instance,
            self.imm,
            InsnRecord::imm_or_funct7_field::<E::BaseField>(&step.insn())
        );

        // Fetch the instruction.
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
