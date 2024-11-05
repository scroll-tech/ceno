use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::constants::PC_STEP_SIZE;
use crate::{
    chip_handler::RegisterExpr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::insn_base::{ReadRS1, ReadRS2, StateInOut},
    set_val,
    tables::InsnRecord,
    utils::i64_to_base,
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

/// This config handles the common part of B-type instructions (branches):
/// - PC, cycle, fetch.
/// - Registers read.
/// - Jump based on the immediate and the given `branch_taken_bit`.
///
/// It does _not_ range-check the `branch_taken_bit`.
/// It does not witness of the register values, nor the actual function (e.g. BNE).
#[derive(Debug)]
pub struct BInstructionConfig<E: ExtensionField> {
    pub vm_state: StateInOut<E>,
    pub rs1: ReadRS1<E>,
    pub rs2: ReadRS2<E>,
    pub imm: WitIn,
}

impl<E: ExtensionField> BInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        branch_taken_bit: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, true)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rs2 = ReadRS2::construct_circuit(circuit_builder, rs2_read, vm_state.ts)?;

        // Immediate
        let imm = circuit_builder.create_witin(|| "imm");

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.into(),
            None,
            rs1.id.expr(),
            rs2.id.expr(),
            imm.expr(),
        ))?;

        // Branch program counter
        let pc_offset =
            branch_taken_bit.clone() * imm.expr() - branch_taken_bit * PC_STEP_SIZE + PC_STEP_SIZE;
        let next_pc = vm_state.next_pc.unwrap();
        circuit_builder.require_equal(
            || "pc_branch",
            next_pc.expr(),
            vm_state.pc.expr() + pc_offset,
        )?;

        Ok(BInstructionConfig {
            vm_state,
            rs1,
            rs2,
            imm,
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

        // Immediate
        set_val!(
            instance,
            self.imm,
            i64_to_base::<E::BaseField>(InsnRecord::imm_internal(&step.insn()))
        );

        // Fetch the instruction.
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }
}
