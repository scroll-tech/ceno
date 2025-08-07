use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
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
use ff_ext::{ExtensionField, FieldInto, SmallField};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::{array, marker::PhantomData};
use witness::set_val;

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
        format!("{:?}", I::INST_KIND)
    }

    /// circuit implementation refer from https://github.com/openvm-org/openvm/blob/ca36de3803213da664b03d111801ab903d55e360/extensions/rv32im/circuit/src/branch_lt/core.rs
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
        let diff_marker: [WitIn; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_bit(|| format!("diff_maker_{i}"))
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
                (E::BaseField::ONE.expr() - prefix_sum.expr()) * diff.clone(),
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
            E::BaseField::ONE.expr() - prefix_sum.expr(),
            cmp_lt.expr(),
        )?;

        // Range check to ensure diff_val is non-zero.
        circuit_builder.assert_ux::<_, _, LIMB_BITS>(
            || "diff_val is non-zero",
            prefix_sum.expr() * (diff_val.expr() - E::BaseField::ONE.expr()),
        )?;

        let branch_taken_bit = match I::INST_KIND {
            InsnKind::BLT => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-32768, 32767) if signed, [0, 65536) if unsigned.
                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;

                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;
                cmp_lt.expr()
            }
            InsnKind::BGE => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;

                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr()
                        + E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr(),
                )?;
                Expression::ONE - cmp_lt.expr()
            }
            InsnKind::BLTU => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr(),
                )?;

                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs2_msb_f_signed_range_check",
                    read_rs2_msb_f.expr(),
                )?;
                cmp_lt.expr()
            }
            InsnKind::BGEU => {
                // Check if read_rs1_msb_f and read_rs2_msb_f are in [-128, 127) if signed, [0, 256) if unsigned.
                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
                    || "read_rs1_msb_f_signed_range_check",
                    read_rs1_msb_f.expr(),
                )?;

                circuit_builder.assert_ux::<_, _, LIMB_BITS>(
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
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .b_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs1_limbs = rs1.as_u16_limbs();
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let rs2_limbs = rs2.as_u16_limbs();
        config.read_rs1.assign_limbs(instance, rs1_limbs);
        config.read_rs2.assign_limbs(instance, rs2_limbs);

        let (cmp_result, diff_idx, rs1_sign, rs2_sign) =
            run_cmp::<E>(step.insn.kind, rs1_limbs, rs2_limbs);
        config
            .diff_marker
            .iter()
            .enumerate()
            .for_each(|(i, witin)| {
                set_val!(instance, witin, (i == diff_idx) as u64);
            });

        let is_signed = matches!(step.insn().kind, InsnKind::BLT | InsnKind::BGE);
        let is_ge = matches!(step.insn().kind, InsnKind::BGE | InsnKind::BGEU);

        let cmp_lt = cmp_result ^ is_ge;
        set_val!(instance, config.cmp_lt, cmp_lt as u64);

        // We range check (read_rs1_msb_f + 128) and (read_rs2_msb_f + 128) if signed,
        // read_rs1_msb_f and read_rs2_msb_f if not
        let (read_rs1_msb_f, a_msb_range) = if rs1_sign {
            (
                -E::BaseField::from_canonical_u32(
                    (1 << LIMB_BITS) - rs1_limbs[UINT_LIMBS - 1] as u32,
                ),
                rs1_limbs[UINT_LIMBS - 1] - (1 << (LIMB_BITS - 1)),
            )
        } else {
            (
                E::BaseField::from_canonical_u16(rs1_limbs[UINT_LIMBS - 1]),
                rs1_limbs[UINT_LIMBS - 1] + ((is_signed as u16) << (LIMB_BITS - 1)),
            )
        };
        let (read_rs2_msb_f, b_msb_range) = if rs2_sign {
            (
                -E::BaseField::from_canonical_u32(
                    (1 << LIMB_BITS) - rs2_limbs[UINT_LIMBS - 1] as u32,
                ),
                rs2_limbs[UINT_LIMBS - 1] - (1 << (LIMB_BITS - 1)),
            )
        } else {
            (
                E::BaseField::from_canonical_u16(rs2_limbs[UINT_LIMBS - 1]),
                rs2_limbs[UINT_LIMBS - 1] + ((is_signed as u16) << (LIMB_BITS - 1)),
            )
        };

        set_val!(instance, config.read_rs1_msb_f, read_rs1_msb_f);
        set_val!(instance, config.read_rs2_msb_f, read_rs2_msb_f);

        let diff_val = if diff_idx == UINT_LIMBS {
            0
        } else if diff_idx == (UINT_LIMBS - 1) {
            if cmp_lt {
                read_rs2_msb_f - read_rs1_msb_f
            } else {
                read_rs1_msb_f - read_rs2_msb_f
            }
            .to_canonical_u64() as u16
        } else if cmp_lt {
            rs2_limbs[diff_idx] - rs1_limbs[diff_idx]
        } else {
            rs1_limbs[diff_idx] - rs2_limbs[diff_idx]
        };
        set_val!(instance, config.diff_val, diff_val as u64);

        if diff_idx != UINT_LIMBS {
            lk_multiplicity.assert_ux::<LIMB_BITS>((diff_val - 1) as u64);
        } else {
            lk_multiplicity.assert_ux::<LIMB_BITS>(0);
        }

        lk_multiplicity.assert_ux::<LIMB_BITS>(a_msb_range as u64);
        lk_multiplicity.assert_ux::<LIMB_BITS>(b_msb_range as u64);

        Ok(())
    }
}

// returns (cmp_result, diff_idx, x_sign, y_sign)
pub(super) fn run_cmp<E: ExtensionField>(
    local_opcode: InsnKind,
    x: &[u16],
    y: &[u16],
) -> (bool, usize, bool, bool) {
    let signed = matches!(local_opcode, InsnKind::BLT | InsnKind::BGE);
    let ge_op = matches!(local_opcode, InsnKind::BGE | InsnKind::BGEU);
    let x_sign = (x[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1) && signed;
    let y_sign = (y[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1) && signed;
    for i in (0..UINT_LIMBS).rev() {
        if x[i] != y[i] {
            return ((x[i] < y[i]) ^ x_sign ^ y_sign ^ ge_op, i, x_sign, y_sign);
        }
    }
    (ge_op, UINT_LIMBS, x_sign, y_sign)
}
