use crate::{
    Value,
    error::ZKVMError,
    gadgets::SignedLtConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{LIMB_BITS, UINT_LIMBS, UInt},
            r_insn::RInstructionConfig,
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, SWord, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{circuit_builder::CircuitBuilder, gadgets::IsLtConfig};
use std::marker::PhantomData;

pub struct SetLessThanInstruction<E, I>(PhantomData<(E, I)>);

/// This config handles R-Instructions that represent registers values as 2 * u16.
pub struct SetLessThanConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    #[allow(dead_code)]
    pub(crate) rd_written: UInt<E>,

    deps: SetLessThanDependencies<E>,
}

enum SetLessThanDependencies<E: ExtensionField> {
    Slt { signed_lt: SignedLtConfig<E> },
    Sltu { is_lt: IsLtConfig },
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanInstruction<E, I> {
    type InstructionConfig = SetLessThanConfig<E>;

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

        let (deps, rd_written) = match I::INST_KIND {
            InsnKind::SLT => {
                let signed_lt =
                    SignedLtConfig::construct_circuit(cb, || "rs1 < rs2", &rs1_read, &rs2_read)?;
                let rd_written = UInt::from_exprs_unchecked(vec![signed_lt.expr()]);
                (SetLessThanDependencies::Slt { signed_lt }, rd_written)
            }
            InsnKind::SLTU => {
                let is_lt = IsLtConfig::construct_circuit(
                    cb,
                    || "rs1 < rs2",
                    rs1_read.value(),
                    rs2_read.value(),
                    UINT_LIMBS * LIMB_BITS,
                )?;
                let rd_written = UInt::from_exprs_unchecked(vec![is_lt.expr()]);
                (SetLessThanDependencies::Sltu { is_lt }, rd_written)
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
            deps,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.r_insn.assign_instance(instance, lkm, step)?;

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

        match &config.deps {
            SetLessThanDependencies::Slt { signed_lt } => {
                signed_lt.assign_instance(instance, lkm, rs1 as SWord, rs2 as SWord)?
            }
            SetLessThanDependencies::Sltu { is_lt } => {
                is_lt.assign_instance(instance, lkm, rs1.into(), rs2.into())?
            }
        }

        Ok(())
    }
}
