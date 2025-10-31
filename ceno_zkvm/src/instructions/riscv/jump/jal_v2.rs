use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{PC_BITS, UINT_BYTE_LIMBS, UInt8},
            j_insn::JInstructionConfig,
        },
    },
    structs::ProgramParams,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, PC_STEP_SIZE};
use gkr_iop::tables::{LookupTable, ops::XorTable};
use multilinear_extensions::{Expression, ToExpr};
use p3::field::FieldAlgebra;

pub struct JalConfig<E: ExtensionField> {
    pub j_insn: JInstructionConfig<E>,
    pub rd_written: UInt8<E>,
}

#[derive(Default)]
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

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::JAL,
            rd_written.register_expr(),
        )?;

        // constrain rd_exprs [PC_BITS .. u32::BITS] are all 0 via xor
        let last_limb_bits = PC_BITS - UInt8::<E>::LIMB_BITS * (UInt8::<E>::NUM_LIMBS - 1);
        let additional_bits =
            (last_limb_bits..UInt8::<E>::LIMB_BITS).fold(0, |acc, x| acc + (1 << x));
        let additional_bits = E::BaseField::from_canonical_u32(additional_bits);
        circuit_builder.logic_u8(
            LookupTable::Xor,
            rd_exprs[3].expr(),
            additional_bits.expr(),
            rd_exprs[3].expr() + additional_bits.expr(),
        )?;

        circuit_builder.require_equal(
            || "jal rd_written",
            rd_exprs
                .iter()
                .enumerate()
                .fold(Expression::ZERO, |acc, (i, val)| {
                    acc + val.expr()
                        * E::BaseField::from_canonical_u32(1 << (i * UInt8::<E>::LIMB_BITS)).expr()
                }),
            j_insn.vm_state.pc.expr() + PC_STEP_SIZE,
        )?;

        Ok(JalConfig { j_insn, rd_written })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .j_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        config.rd_written.assign_limbs(instance, &rd_written);
        for chunk in rd_written.chunks(2) {
            if chunk.len() == 2 {
                lk_multiplicity.assert_double_u8(chunk[0] as u64, chunk[1] as u64)
            } else {
                lk_multiplicity.assert_const_range(chunk[0] as u64, 8);
            }
        }

        // constrain pc msb limb range via xor
        let last_limb_bits = PC_BITS - UInt8::<E>::LIMB_BITS * (UINT_BYTE_LIMBS - 1);
        let additional_bits =
            (last_limb_bits..UInt8::<E>::LIMB_BITS).fold(0, |acc, x| acc + (1 << x));
        lk_multiplicity.logic_u8::<XorTable>(rd_written[3] as u64, additional_bits as u64);

        Ok(())
    }
}
