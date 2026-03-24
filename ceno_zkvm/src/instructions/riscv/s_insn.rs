use crate::{
    chip_handler::{AddressExpr, MemoryExpr, RegisterExpr, general::InstFetch},
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        riscv::insn_base::{ReadRS1, ReadRS2, StateInOut, WriteMEM},
        gpu::host_ops::{LkOp, LkShardramSink},
    },
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use multilinear_extensions::{Expression, ToExpr};

/// This config handles the common part of S-type instructions:
/// - PC, cycle, fetch.
/// - Registers reads.
/// - Memory write
pub struct SInstructionConfig<E: ExtensionField> {
    pub(crate) vm_state: StateInOut<E>,
    pub(crate) rs1: ReadRS1<E>,
    pub(crate) rs2: ReadRS2<E>,
    pub(crate) mem_write: WriteMEM,
}

impl<E: ExtensionField> SInstructionConfig<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        #[cfg(feature = "u16limb_circuit")] imm_sign: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        memory_addr: AddressExpr<E>,
        prev_memory_value: MemoryExpr<E>,
        new_memory_value: MemoryExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, false)?;

        // Registers
        let rs1 = ReadRS1::construct_circuit(circuit_builder, rs1_read, vm_state.ts)?;
        let rs2 = ReadRS2::construct_circuit(circuit_builder, rs2_read, vm_state.ts)?;

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind.into(),
            None,
            rs1.id.expr(),
            rs2.id.expr(),
            imm.clone(),
            #[cfg(feature = "u16limb_circuit")]
            imm_sign.expr(),
        ))?;

        // Memory
        let mem_write = WriteMEM::construct_circuit(
            circuit_builder,
            memory_addr,
            prev_memory_value,
            new_memory_value,
            vm_state.ts,
        )?;

        Ok(SInstructionConfig {
            vm_state,
            rs1,
            rs2,
            mem_write,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.vm_state.assign_instance(instance, shard_ctx, step)?;
        self.rs1
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
        self.rs2
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
        self.mem_write
            .assign_instance::<E>(instance, shard_ctx, lk_multiplicity, step)?;

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        Ok(())
    }

    pub fn emit_shardram(
        &self,
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) {
        lk_multiplicity.fetch(step.pc().before.0);
        self.rs1.emit_shardram(shard_ctx, step);
        self.rs2.emit_shardram(shard_ctx, step);
        self.mem_write.emit_shardram(shard_ctx, step);
    }

    #[allow(dead_code)]
    pub fn emit_lk_and_shardram(
        &self,
        sink: &mut impl LkShardramSink,
        shard_ctx: &ShardContext,
        step: &StepRecord,
    ) {
        sink.emit_lk(LkOp::Fetch {
            pc: step.pc().before.0,
        });
        self.rs1.emit_lk_and_shardram(sink, shard_ctx, step);
        self.rs2.emit_lk_and_shardram(sink, shard_ctx, step);
        self.mem_write.emit_lk_and_shardram(sink, shard_ctx, step);
    }
}
