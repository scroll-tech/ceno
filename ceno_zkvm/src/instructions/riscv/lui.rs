use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{BIT_WIDTH, PC_BITS, UInt, UInt8},
            i_insn::IInstructionConfig,
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, PC_STEP_SIZE};
use gkr_iop::tables::LookupTable;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;

pub struct LuiConfig<E: ExtensionField> {
    pub j_insn: IInstructionConfig<E>,
    pub imm: WitIn,
    pub rd_written: UInt8<E>,
}

pub struct LuiInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for LuiInstruction<E> {
    type InstructionConfig = LuiConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::LUI)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<LuiConfig<E>, ZKVMError> {
        let rd_written = UInt8::new(|| "rd_written", circuit_builder)?;
        let rd_exprs = rd_written.expr();
        let imm = circuit_builder.create_witin(|| "imm");
        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            InsnKind::LUI,
            imm.expr(),
            #[cfg(feature = "u16limb_circuit")]
            0.into(),
            [0.into(), 0.into()],
            rd_written.register_expr(),
            false,
        )?;

        let intermed_val =
            rd_exprs
                .iter()
                .skip(1)
                .enumerate()
                .fold(Expression::ZERO, |acc, (i, &val)| {
                    acc + val.expr()
                        * E::BaseField::from_canonical_u32(1 << (i * UInt8::LIMB_BITS)).expr()
                });

        // imm * 2^4 is the correct composition of intermed_val in case of LUI
        circuit_builder.require_equal(
            || "imm * 2^4 is the correct composition of intermed_val in case of LUI",
            intermed_val.expr(),
            imm * E::BaseField::from_canonical_u32(1 << (12 - UInt8::LIMB_BITS)),
        )?;

        circuit_builder.require_equal(
            || "jal rd_written",
            rd_written.value(),
            i_insn.vm_state.pc.expr() + PC_STEP_SIZE,
        )?;

        Ok(JalConfig { j_insn, rd_written })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .j_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        config.rd_written.assign_value(instance, rd_written);

        Ok(())
    }
}
