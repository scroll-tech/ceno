use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::{UIntLimbsLT, UIntLimbsLTConfig},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{UINT_LIMBS, UInt},
            i_insn::IInstructionConfig,
        },
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

#[derive(Debug)]
pub struct SetLessThanImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    // 0 positive, 1 negative
    imm_sign: Option<WitIn>,
    #[allow(dead_code)]
    pub(crate) rd_written: UInt<E>,

    uint_lt_config: UIntLimbsLTConfig<E>,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanImmInstruction<E, I> {
    type InstructionConfig = SetLessThanImmConfig<E>;

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

        let (uint_lt_config, imm_sign_extend, imm_sign) = match I::INST_KIND {
            InsnKind::SLTIU => {
                let imm_sign = cb.create_witin(|| "imm_sign");
                let imm_sign_extend = UInt::from_exprs_unchecked(
                    imm_sign_extend_circuit::<E>(true, imm_sign.expr(), imm.expr()).to_vec(),
                );
                (
                    UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_sign_extend, false)?,
                    imm_sign_extend,
                    Some(imm_sign),
                )
            }
            InsnKind::SLTI => {
                let imm_sign = cb.create_witin(|| "imm_sign");
                let imm_sign_extend = UInt::from_exprs_unchecked(
                    imm_sign_extend_circuit::<E>(true, imm_sign.expr(), imm.expr()).to_vec(),
                );
                (
                    UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_sign_extend, true)?,
                    imm_sign_extend,
                    Some(imm_sign),
                )
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let rd_written = UInt::from_exprs_unchecked(vec![uint_lt_config.is_lt()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            imm_sign_extend.expr().remove(0),
            imm_sign.map(|imm_sign| imm_sign.expr()).unwrap_or(0.into()),
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
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.i_insn.assign_instance(instance, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let rs1_value = Value::new_unchecked(rs1 as Word);
        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));

        let imm = step.insn().imm as i16 as u16;
        let is_signed = matches!(step.insn().kind, InsnKind::SLTI);
        set_val!(instance, config.imm, E::BaseField::from_canonical_u16(imm));
        // accroding to riscvim32 spec, imm always do signed extension
        let imm_sign_extend = imm_sign_extend(true, step.insn().imm as i16);
        // if is_signed {
        set_val!(
            instance,
            config.imm_sign.as_ref().unwrap(),
            E::BaseField::from_bool(imm_sign_extend[1] > 0)
        );
        // }

        UIntLimbsLT::<E>::assign(
            &config.uint_lt_config,
            instance,
            lkm,
            rs1_value.as_u16_limbs(),
            &imm_sign_extend,
            is_signed,
        )?;
        Ok(())
    }
}
