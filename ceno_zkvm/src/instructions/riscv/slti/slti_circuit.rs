use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::SignedExtendConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{LIMB_BITS, UINT_LIMBS, UInt},
            i_insn::IInstructionConfig,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, SWord, StepRecord, Word};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::gadgets::IsLtConfig;
use multilinear_extensions::{ToExpr, WitIn};
use std::marker::PhantomData;
use witness::set_val;

#[derive(Debug)]
pub struct SetLessThanImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    #[allow(dead_code)]
    pub(crate) rd_written: UInt<E>,
    lt: IsLtConfig,

    // SLTI
    is_rs1_neg: Option<SignedExtendConfig<E>>,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanImmInstruction<E, I> {
    type InstructionConfig = SetLessThanImmConfig<E>;
    type InsnType = InsnKind;

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
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm = cb.create_witin(|| "imm");

        let (value_expr, is_rs1_neg) = match I::INST_KIND {
            InsnKind::SLTIU => (rs1_read.value(), None),
            InsnKind::SLTI => {
                let is_rs1_neg = rs1_read.is_negative(cb)?;
                (rs1_read.to_field_expr(is_rs1_neg.expr()), Some(is_rs1_neg))
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let lt = IsLtConfig::construct_circuit(
            cb,
            || "rs1 < imm",
            value_expr,
            imm.expr(),
            UINT_LIMBS * LIMB_BITS,
        )?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            imm.expr(),
            #[cfg(feature = "u16limb_circuit")]
            E::BaseField::ZERO.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(SetLessThanImmConfig {
            i_insn,
            rs1_read,
            imm,
            rd_written,
            is_rs1_neg,
            lt,
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

        let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn());
        set_val!(instance, config.imm, imm.1);

        match I::INST_KIND {
            InsnKind::SLTIU => {
                config
                    .lt
                    .assign_instance(instance, lkm, rs1 as u64, imm.0 as u64)?;
            }
            InsnKind::SLTI => {
                config.is_rs1_neg.as_ref().unwrap().assign_instance(
                    instance,
                    lkm,
                    *rs1_value.as_u16_limbs().last().unwrap() as u64,
                )?;
                let (rs1, imm) = (rs1 as SWord, imm.0 as SWord);
                config
                    .lt
                    .assign_instance_signed(instance, lkm, rs1 as i64, imm as i64)?;
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }

        Ok(())
    }
}
