use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::{UIntLimbsLT, UIntLimbsLTConfig},
    impl_collect_shardram, impl_collect_lk_and_shardram, impl_gpu_assign,
    instructions::{
        Instruction,
        riscv::{RIVInstruction, constants::UInt, r_insn::RInstructionConfig},
        side_effects::emit_uint_limbs_lt_ops,
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::marker::PhantomData;

pub struct SetLessThanInstruction<E, I>(PhantomData<(E, I)>);

/// This config handles R-Instructions that represent registers values as 2 * u16.
pub struct SetLessThanConfig<E: ExtensionField> {
    pub(crate) r_insn: RInstructionConfig<E>,

    pub(crate) rs1_read: UInt<E>,
    pub(crate) rs2_read: UInt<E>,
    #[allow(dead_code)]
    pub(crate) rd_written: UInt<E>,

    pub(crate) uint_lt_config: UIntLimbsLTConfig<E>,
}
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanInstruction<E, I> {
    type InstructionConfig = SetLessThanConfig<E>;
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
        // If rs1_read < rs2_read, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", cb)?;

        let (rd_written, uint_lt_config) = match I::INST_KIND {
            InsnKind::SLT => {
                let config = UIntLimbsLT::construct_circuit(cb, &rs1_read, &rs2_read, true)?;
                let rd_written = UInt::from_exprs_unchecked(vec![config.is_lt()]);
                (rd_written, config)
            }
            InsnKind::SLTU => {
                let config = UIntLimbsLT::construct_circuit(cb, &rs1_read, &rs2_read, false)?;
                let rd_written = UInt::from_exprs_unchecked(vec![config.is_lt()]);
                (rd_written, config)
            }
            _ => unreachable!(),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(SetLessThanConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            uint_lt_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [<E as ExtensionField>::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .assign_instance(instance, shard_ctx, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;

        let rs1_read = Value::new_unchecked(rs1);
        let rs2_read = Value::new_unchecked(rs2);
        config
            .rs1_read
            .assign_limbs(instance, rs1_read.as_u16_limbs());
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());

        let is_signed = matches!(step.insn().kind, InsnKind::SLT);
        UIntLimbsLT::<E>::assign(
            &config.uint_lt_config,
            instance,
            lkm,
            rs1_read.as_u16_limbs(),
            rs2_read.as_u16_limbs(),
            is_signed,
        )?;
        Ok(())
    }

    impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
        let rs1_value = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2_value = Value::new_unchecked(step.rs2().unwrap().value);
        let rs1_limbs = rs1_value.as_u16_limbs();
        let rs2_limbs = rs2_value.as_u16_limbs();
        emit_uint_limbs_lt_ops(
            sink,
            matches!(I::INST_KIND, InsnKind::SLT),
            &rs1_limbs,
            &rs2_limbs,
        );
    });

    impl_collect_shardram!(r_insn);

    impl_gpu_assign!(witgen_gpu::GpuWitgenKind::Slt(match I::INST_KIND {
        InsnKind::SLT => 1u32,
        InsnKind::SLTU => 0u32,
        _ => unreachable!(),
    }));
}
