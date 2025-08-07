use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::{SignedExtendConfig, UIntLimbsLT, UIntLimbsLTConfig},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{UINT_LIMBS, UInt},
            i_insn::IInstructionConfig,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, SWord, StepRecord, Word};
use ff_ext::ExtensionField;
use gkr_iop::{gadgets::IsLtConfig, utils::i64_to_base};
use multilinear_extensions::{ToExpr, WitIn};
use std::marker::PhantomData;
use witness::set_val;

#[derive(Debug)]
pub struct SetLessThanImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    #[allow(dead_code)]
    rd_written: UInt<E>,

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
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm = cb.create_witin(|| "imm");
        let imm_uint = UInt::from_exprs_unchecked(vec![imm.expr()]);

        let uint_lt_config = match I::INST_KIND {
            InsnKind::SLTIU => UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_uint, false)?,
            InsnKind::SLTI => UIntLimbsLT::construct_circuit(cb, &rs1_read, &imm_uint, true)?,
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let rd_written = UInt::from_exprs_unchecked(vec![uint_lt_config.is_lt()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(SetLessThanImmConfig {
            i_insn,
            rs1_read,
            imm,
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

        let imm = InsnRecord::imm_internal(&step.insn());
        set_val!(instance, config.imm, i64_to_base::<E::BaseField>(imm));

        let is_signed = matches!(step.insn().kind, InsnKind::SLT);
        UIntLimbsLT::<E>::assign(
            &config.uint_lt_config,
            instance,
            lkm,
            rs1_read.as_u16_limbs(),
            rs2_read.as_u16_limbs(),
            is_signed,
        )?;
        match I::INST_KIND {
            InsnKind::SLTIU => {
                config
                    .lt
                    .assign_instance(instance, lkm, rs1 as u64, imm as u64)?;
            }
            InsnKind::SLTI => {
                config.is_rs1_neg.as_ref().unwrap().assign_instance(
                    instance,
                    lkm,
                    *rs1_value.as_u16_limbs().last().unwrap() as u64,
                )?;
                let (rs1, imm) = (rs1 as SWord, imm as SWord);
                config
                    .lt
                    .assign_instance_signed(instance, lkm, rs1 as i64, imm as i64)?;
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }

        Ok(())
    }
}
