//! The circuit implementation of logic instructions.

use ff_ext::ExtensionField;
use gkr_iop::tables::OpsTable;
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{constants::UInt8, r_insn::RInstructionConfig},
        side_effects::{CpuSideEffectSink, emit_logic_u8_ops},
    },
    structs::ProgramParams,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};

#[cfg(feature = "gpu")]
use crate::tables::RMMCollections;
#[cfg(feature = "gpu")]
use ceno_emul::StepIndex;
#[cfg(feature = "gpu")]
use gkr_iop::utils::lk_multiplicity::Multiplicity;

/// This trait defines a logic instruction, connecting an instruction type to a lookup table.
pub trait LogicOp {
    const INST_KIND: InsnKind;
    type OpsTable: OpsTable;
}

/// The Instruction circuit for a given LogicOp.
pub struct LogicInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: LogicOp> Instruction<E> for LogicInstruction<E, I> {
    type InstructionConfig = LogicConfig<E>;
    type InsnType = InsnKind;

    const GPU_SIDE_EFFECTS: bool = true;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[I::INST_KIND]
    }

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let config = LogicConfig::construct_circuit(cb, I::INST_KIND)?;

        // Constrain the registers based on the given lookup table.
        UInt8::logic(
            cb,
            I::OpsTable::ROM_TYPE,
            &config.rs1_read,
            &config.rs2_read,
            &config.rd_written,
        )?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        UInt8::<E>::logic_assign::<I::OpsTable>(
            lk_multiplicity,
            step.rs1().unwrap().value as u64,
            step.rs2().unwrap().value as u64,
        );

        config.assign_instance(instance, shard_ctx, lk_multiplicity, step)
    }

    fn collect_side_effects_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let shard_ctx_ptr = shard_ctx as *mut ShardContext;
        let shard_ctx_view = unsafe { &*shard_ctx_ptr };
        let mut sink = unsafe { CpuSideEffectSink::from_raw(shard_ctx_ptr, lk_multiplicity) };
        config.collect_side_effects(&mut sink, shard_ctx_view, step);
        emit_logic_u8_ops::<I::OpsTable>(
            &mut sink,
            step.rs1().unwrap().value as u64,
            step.rs2().unwrap().value as u64,
            4,
        );
        Ok(())
    }

    fn collect_shard_side_effects_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .collect_shard_effects(shard_ctx, lk_multiplicity, step);
        Ok(())
    }

    #[cfg(feature = "gpu")]
    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        shard_steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        use crate::instructions::riscv::gpu::witgen_gpu;
        if let Some(result) = witgen_gpu::try_gpu_assign_instances::<E, Self>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            witgen_gpu::GpuWitgenKind::LogicR(match I::INST_KIND {
                InsnKind::AND => 0,
                InsnKind::OR => 1,
                InsnKind::XOR => 2,
                kind => unreachable!("unsupported logic GPU kind: {kind:?}"),
            }),
        )? {
            return Ok(result);
        }
        crate::instructions::cpu_assign_instances::<E, Self>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
        )
    }
}

/// This config implements R-Instructions that represent registers values as 4 * u8.
/// Non-generic code shared by several circuits.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    pub(crate) r_insn: RInstructionConfig<E>,

    pub(crate) rs1_read: UInt8<E>,
    pub(crate) rs2_read: UInt8<E>,
    pub(crate) rd_written: UInt8<E>,
}

impl<E: ExtensionField> LogicConfig<E> {
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
    ) -> Result<Self, ZKVMError> {
        let rs1_read = UInt8::new_unchecked(|| "rs1_read", cb)?;
        let rs2_read = UInt8::new_unchecked(|| "rs2_read", cb)?;
        let rd_written = UInt8::new_unchecked(|| "rd_written", cb)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            insn_kind,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(Self {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.r_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        let rs1_read = split_to_u8(step.rs1().unwrap().value);
        self.rs1_read.assign_limbs(instance, &rs1_read);

        let rs2_read = split_to_u8(step.rs2().unwrap().value);
        self.rs2_read.assign_limbs(instance, &rs2_read);

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        self.rd_written.assign_limbs(instance, &rd_written);

        Ok(())
    }

    fn collect_side_effects(
        &self,
        sink: &mut impl crate::instructions::side_effects::SideEffectSink,
        shard_ctx: &ShardContext,
        step: &StepRecord,
    ) {
        self.r_insn.collect_side_effects(sink, shard_ctx, step);
    }
}
