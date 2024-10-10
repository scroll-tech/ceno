use crate::{
    chip_handler::{MemoryChipOperations, MemoryExpr, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::insn_base::{ReadRS1, StateInOut, WriteRD},
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord, Tracer};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

/// This config handle the common part of I-type Instruction (memory variant)
/// - PC, cycle, fetch
/// - Register reads and writes
/// - Memory writes
pub struct IMInstructionConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    rs1: ReadRS1<E>,
    rd: WriteRD<E>,

    prev_memory_ts: WitIn,
}

impl<E: ExtensionField> IMInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        memory_read: MemoryExpr<E>,
        memory_addr: MemoryExpr<E>,
        rd_written: RegisterExpr<E>,
    ) -> Result<Self, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(circuit_builder, false)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rd = WriteRD::construct_circuit(circuit_builder, rd_written, vm_state.ts)?;

        // Fetch the instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            rd.id.expr(),
            (insn_kind.codes().func3 as usize).into(),
            rs1.id.expr(),
            0.into(),
            imm.clone(),
        ))?;

        // Memory State
        let prev_memory_ts = circuit_builder.create_witin(|| "prev_memory_ts")?;

        // TODO: handle the ltsconfig
        // TODO: refactor into RS1Read type structure
        circuit_builder.memory_read(
            || "read_mem",
            &memory_addr,
            prev_memory_ts.expr(),
            vm_state.ts.expr() + (Tracer::SUBCYCLE_MEM as usize).into(),
            memory_read,
        )?;

        Ok(IMInstructionConfig {
            vm_state,
            rs1,
            rd,
            prev_memory_ts,
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

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        // Memory state
        set_val!(
            instance,
            self.prev_memory_ts,
            step.memory_op().unwrap().previous_cycle
        );

        Ok(())
    }
}
