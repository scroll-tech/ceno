use crate::{
    chip_handler::{register_expr_to_memory_expr, MemoryChipOperations, MemoryExpr, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::{
        constants::UInt,
        insn_base::{ReadRS1, ReadRS2, StateInOut},
    },
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{InsnKind, StepRecord, Tracer};
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

    prev_memory_ts: WitIn,
    prev_memory_value: UInt<E>,
}

impl<E: ExtensionField> SInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        memory_addr: MemoryExpr<E>,
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
            (insn_kind.codes().func7 as usize).into(),
        ))?;

        // Memory state
        let prev_memory_ts = circuit_builder.create_witin(|| "prev_memory_ts")?;
        let prev_memory_value = UInt::new_unchecked(|| "prev_memory_value", circuit_builder)?;

        // TODO: refactor into something similar to ReadRS1
        // Memory state
        circuit_builder.memory_write(
            || "write_mem",
            &memory_addr,
            prev_memory_ts.expr(),
            vm_state.ts.expr() + (Tracer::SUBCYCLE_MEM as usize).into(),
            prev_memory_value.memory_expr(),
            memory_value,
        )?;

        Ok(SInstructionConfig {
            vm_state,
            rs1,
            rs2,
            prev_memory_ts,
            prev_memory_value,
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

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        // Memory state
        set_val!(
            instance,
            self.prev_memory_ts,
            step.memory_op().unwrap().previous_cycle
        );
        self.prev_memory_value.assign_limbs(
            instance,
            Value::new_unchecked(step.memory_op().unwrap().value.before).as_u16_limbs(),
        );

        Ok(())
    }
}
