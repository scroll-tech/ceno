use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::{UIntLimbsLT, UIntLimbsLTConfig},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{UINT_LIMBS, UInt},
            i_insn::IInstructionConfig,
        },
        side_effects::{CpuSideEffectSink, emit_uint_limbs_lt_ops},
    },
    structs::ProgramParams,
    utils::{imm_sign_extend, imm_sign_extend_circuit},
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord, Word};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::marker::PhantomData;
use witness::set_val;

#[cfg(feature = "gpu")]
use crate::tables::RMMCollections;
#[cfg(feature = "gpu")]
use ceno_emul::StepIndex;
#[cfg(feature = "gpu")]
use gkr_iop::utils::lk_multiplicity::Multiplicity;

#[derive(Debug)]
pub struct SetLessThanImmConfig<E: ExtensionField> {
    pub(crate) i_insn: IInstructionConfig<E>,

    pub(crate) rs1_read: UInt<E>,
    pub(crate) imm: WitIn,
    // 0 positive, 1 negative
    pub(crate) imm_sign: WitIn,
    #[allow(dead_code)]
    pub(crate) rd_written: UInt<E>,

    pub(crate) uint_lt_config: UIntLimbsLTConfig<E>,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanImmInstruction<E, I> {
    type InstructionConfig = SetLessThanImmConfig<E>;
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
        assert_eq!(UINT_LIMBS, 2);
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm = cb.create_witin(|| "imm");
        // a bool witness to mark sign extend of imm no matter sign/unsign
        let imm_sign = cb.create_witin(|| "imm_sign");
        let imm_sign_extend = UInt::from_exprs_unchecked(
            imm_sign_extend_circuit::<E>(true, imm_sign.expr(), imm.expr()).to_vec(),
        );
        let uint_lt_config = match I::INST_KIND {
            InsnKind::SLTIU => {
                UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_sign_extend, false)?
            }
            InsnKind::SLTI => {
                UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_sign_extend, true)?
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let rd_written = UInt::from_exprs_unchecked(vec![uint_lt_config.is_lt()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            imm_sign_extend.expr().remove(0),
            imm_sign.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(SetLessThanImmConfig {
            i_insn,
            rs1_read,
            imm,
            imm_sign,
            rd_written,
            uint_lt_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .i_insn
            .assign_instance(instance, shard_ctx, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let rs1_value = Value::new_unchecked(rs1 as Word);
        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));

        let imm = step.insn().imm as i16 as u16;
        set_val!(instance, config.imm, E::BaseField::from_canonical_u16(imm));
        // according to riscvim32 spec, imm always do signed extension
        let imm_sign_extend = imm_sign_extend(true, step.insn().imm as i16);
        set_val!(
            instance,
            config.imm_sign,
            E::BaseField::from_bool(imm_sign_extend[1] > 0)
        );

        UIntLimbsLT::<E>::assign(
            &config.uint_lt_config,
            instance,
            lkm,
            rs1_value.as_u16_limbs(),
            &imm_sign_extend,
            matches!(step.insn().kind, InsnKind::SLTI),
        )?;
        Ok(())
    }

    fn collect_side_effects_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let shard_ctx_ptr = shard_ctx as *mut ShardContext;
        let shard_ctx_view = unsafe { &*shard_ctx_ptr };
        let mut sink = unsafe { CpuSideEffectSink::from_raw(shard_ctx_ptr, lkm) };
        config
            .i_insn
            .collect_side_effects(&mut sink, shard_ctx_view, step);

        let rs1_value = Value::new_unchecked(step.rs1().unwrap().value);
        let rs1_limbs = rs1_value.as_u16_limbs();
        let imm_sign_extend = imm_sign_extend(true, step.insn().imm as i16);
        emit_uint_limbs_lt_ops(
            &mut sink,
            matches!(I::INST_KIND, InsnKind::SLTI),
            &rs1_limbs,
            &imm_sign_extend,
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
            .i_insn
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
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), crate::error::ZKVMError> {
        use crate::instructions::riscv::gpu::witgen_gpu;
        let is_signed = match I::INST_KIND {
            InsnKind::SLTI => 1u32,
            InsnKind::SLTIU => 0u32,
            _ => unreachable!(),
        };
        if let Some(result) = witgen_gpu::try_gpu_assign_instances::<E, Self>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            witgen_gpu::GpuWitgenKind::Slti(is_signed),
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
