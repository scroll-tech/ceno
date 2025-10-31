use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{RIVInstruction, constants::UInt, i_insn::IInstructionConfig},
    },
    structs::ProgramParams,
    utils::{imm_sign_extend, imm_sign_extend_circuit},
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::marker::PhantomData;
use witness::set_val;

pub struct AddiInstruction<E>(PhantomData<E>);

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    // 0 positive, 1 negative
    imm_sign: WitIn,
    rd_written: UInt<E>,
}

impl<E: ExtensionField> Instruction<E> for AddiInstruction<E> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = circuit_builder.create_witin(|| "imm");
        let imm_sign = circuit_builder.create_witin(|| "imm_sign");
        let imm_sign_extend = UInt::from_exprs_unchecked(
            imm_sign_extend_circuit::<E>(true, imm_sign.expr(), imm.expr()).to_vec(),
        );
        let rd_written =
            rs1_read.add(|| "rs1_read + imm", circuit_builder, &imm_sign_extend, true)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            imm_sign_extend.expr().remove(0),
            imm_sign.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(InstructionConfig {
            i_insn,
            rs1_read,
            imm,
            imm_sign,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);

        let imm = step.insn().imm as i16 as u16;
        set_val!(instance, config.imm, E::BaseField::from_canonical_u16(imm));
        let imm_sign_extend = imm_sign_extend(true, step.insn().imm as i16);

        set_val!(
            instance,
            config.imm_sign,
            E::BaseField::from_bool(imm_sign_extend[1] > 0)
        );

        let imm_sign_extend = Value::from_limb_slice_unchecked(&imm_sign_extend);
        let result = rs1_read.add(&imm_sign_extend, lk_multiplicity, true);
        config.rs1_read.assign_value(instance, rs1_read);
        config.rd_written.assign_add_outcome(instance, &result);

        config
            .i_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        Ok(())
    }
}
