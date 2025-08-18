use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{BIT_WIDTH, PC_BITS, UInt, UInt8},
            j_insn::JInstructionConfig,
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, PC_STEP_SIZE};
use gkr_iop::tables::LookupTable;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;

pub struct JalConfig<E: ExtensionField> {
    pub j_insn: JInstructionConfig<E>,
    pub imm: WitIn,
    pub rd_written: UInt8<E>,
}

pub struct JalInstruction<E>(PhantomData<E>);

/// JAL instruction circuit
///
/// Note: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
///
/// Assumption: values for valid initial program counter must lie between
///   2^20 and 2^32 - 2^20 + 2 inclusive, probably enforced by the static
///   program lookup table. If this assumption does not hold, then resulting
///   value for next_pc may not correctly wrap mod 2^32 because of the use
///   of native WitIn values for address space arithmetic.
impl<E: ExtensionField> Instruction<E> for JalInstruction<E> {
    type InstructionConfig = JalConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::JAL)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<JalConfig<E>, ZKVMError> {
        let rd_written = UInt8::new(|| "rd_written", circuit_builder)?;
        let rd_exprs = rd_written.expr();
        let imm = circuit_builder.create_witin(|| "imm");

        let intermed_val =
            rd_exprs
                .iter()
                .skip(1)
                .enumerate()
                .fold(Expression::ZERO, |acc, (i, val)| {
                    acc + val.expr()
                        * E::BaseField::from_canonical_u32(1 << (i * UInt8::<E>::LIMB_BITS)).expr()
                });

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::JAL,
            rd_written.register_expr(),
        )?;

        // constrain rd_exprs [PC_BITS .. u32::BITS] are all 0 via xor
        let last_limb_bits = PC_BITS - UInt8::<E>::LIMB_BITS * (UInt8::<E>::NUM_LIMBS - 1);
        let additional_bits = (last_limb_bits..UInt8::<E>::LIMB_BITS).fold(0, |acc, x| acc + (1 << x));
        let additional_bits = E::BaseField::from_canonical_u32(additional_bits);
        circuit_builder.logic_u8(
            LookupTable::Xor,
            rd_exprs[3].expr(),
            additional_bits.expr(),
            rd_exprs[3].expr() + additional_bits.expr(),
        )?;
        // circuit_builder.require_equal(
        //     intermed_val,
        //     j_insn. + E::BaseField::from_canonical_u32(DEFAULT_PC_STEP),
        // );

        circuit_builder.require_equal(
            || "jal rd_written",
            rd_written.value(),
            j_insn.vm_state.pc.expr() + PC_STEP_SIZE,
        )?;

        Ok(JalConfig {
            j_insn,
            imm,
            rd_written,
        })
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
