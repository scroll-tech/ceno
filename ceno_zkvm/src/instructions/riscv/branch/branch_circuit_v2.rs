use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::SignedLtConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            b_insn::BInstructionConfig,
            constants::{LIMB_BITS, UINT_LIMBS, UInt},
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::gadgets::{IsEqualConfig, IsLtConfig};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::{array, marker::PhantomData, ops::Neg};

pub struct BranchCircuit<E, I>(PhantomData<(E, I)>);

pub struct BranchConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,

    // Most significant limb of a and b respectively as a field element, will be range
    // checked to be within [-128, 127) if signed and [0, 256) if unsigned.
    pub read_rs1_msb_f: WitIn,
    pub read_rs2_msb_f: WitIn,

    // 1 at the most significant index i such that read_rs1[i] != read_rs2[i], otherwise 0. If such
    // an i exists, diff_val = read_rs2[i] - read_rs1[i].
    pub diff_marker: [WitIn; UINT_LIMBS],
    pub diff_val: WitIn,

    // 1 if read_rs1 < read_rs2, 0 otherwise.
    pub cmp_lt: WitIn,

    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BranchCircuit<E, I> {
    type InstructionConfig = BranchConfig<E>;

    fn name() -> String {
        todo!()
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // 1 if a < b, 0 otherwise.
        let cmp_lt = circuit_builder.create_bit(|| "cmp_lt")?;

        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        let read_rs1_expr = read_rs1.expr();
        let read_rs2_expr = read_rs2.expr();

        let read_rs1_msb_f = circuit_builder.create_witin(|| "read_rs1_msb_f");
        let read_rs2_msb_f = circuit_builder.create_witin(|| "read_rs2_msb_f");
        let diff_marker: [WitIn; UINT_LIMBS] = array::from_fn(|_| {
            circuit_builder
                .create_bit(|| "diff_maker")
                .expect("create_bit_error")
        });
        let diff_val = circuit_builder.create_witin(|| "diff_val");

        // Check if read_rs1_msb_f and read_rs2_msb_f are signed values of read_rs1[NUM_LIMBS - 1] and read_rs2[NUM_LIMBS - 1] in prime field F.
        let read_rs1_diff = read_rs1_expr[UINT_LIMBS - 1].expr() - read_rs1_msb_f.expr();
        let read_rs2_diff = read_rs2_expr[UINT_LIMBS - 1].expr() - read_rs2_msb_f.expr();

        circuit_builder.require_zero(
            || "read_rs1_diff",
            read_rs1_diff.expr()
                * (E::BaseField::from_canonical_u32(1 << LIMB_BITS).expr() - read_rs1_diff.expr()),
        )?;
        circuit_builder.require_zero(
            || "read_rs2_diff",
            read_rs2_diff.expr()
                * (E::BaseField::from_canonical_u32(1 << LIMB_BITS).expr() - read_rs2_diff.expr()),
        )?;

        let mut prefix_sum = Expression::ZERO;

        for i in (0..UINT_LIMBS).rev() {
            let diff = (if i == UINT_LIMBS - 1 {
                read_rs2_msb_f.expr() - read_rs1_msb_f.expr()
            } else {
                read_rs2_expr[i].expr() - read_rs1_expr[i].expr()
            }) * (E::BaseField::from_canonical_u8(2).expr() * cmp_lt.expr()
                - E::BaseField::ONE.expr());
            prefix_sum += diff_marker[i].expr();
            circuit_builder.require_zero(
                || format!("prefix_diff_zero_{i}"),
                (prefix_sum.clone() * diff.clone()).neg(),
            )?;
            circuit_builder.condition_require_zero(
                || format!("diff_maker_conditional_equal_{i}"),
                diff_marker[i].expr(),
                diff_val.expr() - diff.expr(),
            )?;
        }

        // - If x != y, then prefix_sum = 1 so marker[i] must be 1 iff i is the first index where diff != 0.
        //   Constrains that diff == diff_val where diff_val is non-zero.
        // - If x == y, then prefix_sum = 0 and cmp_lt = 0.
        //   Here, prefix_sum cannot be 1 because all diff are zero, making diff == diff_val fails.

        circuit_builder.assert_bit(|| "prefix_sum_bit", prefix_sum.expr())?;
        circuit_builder.condition_require_zero(
            || "cmp_lt_conditional_zero",
            prefix_sum.expr().neg(),
            cmp_lt.expr(),
        )?;

        // Range check to ensure diff_val is non-zero.
        circuit_builder.assert_ux::<_, _, 8>(
            || "diff_val is non-zero",
            prefix_sum.expr() * (diff_val.expr() - E::BaseField::ONE.expr()),
        )?;

        let branch_taken_bit = match I::INST_KIND {
            InsnKind::BLT => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;

                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;
                cmp_lt.expr()
            }
            InsnKind::BGE => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;

                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;
                Expression::ONE - cmp_lt.expr()
            }
            InsnKind::BLTU => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr(),
                )?;

                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr(),
                )?;
                cmp_lt.expr()
            }
            InsnKind::BGEU => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr(),
                )?;

                circuit_builder.assert_ux::<_, _, 8>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr(),
                )?;
                Expression::ONE - cmp_lt.expr()
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            branch_taken_bit,
        )?;

        Ok(BranchConfig {
            b_insn,
            read_rs1,
            read_rs2,

            read_rs1_msb_f,
            read_rs2_msb_f,
            diff_marker,
            diff_val,
            cmp_lt,
            phantom: Default::default(),
        })
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
