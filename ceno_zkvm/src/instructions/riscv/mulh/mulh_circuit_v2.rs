use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{LIMB_BITS, UINT_LIMBS, UInt},
            r_insn::RInstructionConfig,
        },
    },
    structs::ProgramParams,
    uint::Value,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr as _, WitIn};
use p3::field::{Field, FieldAlgebra};
use witness::set_val;

use std::{array, marker::PhantomData};

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulhConfig<E: ExtensionField> {
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,
    r_insn: RInstructionConfig<E>,
    rd_low: [WitIn; UINT_LIMBS],
    carry: [WitIn; UINT_LIMBS * 2],
    rs1_ext: WitIn,
    rs2_ext: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(UInt::<E>::LIMB_BITS, 16);
        assert_eq!(UInt::<E>::NUM_LIMBS, 2);

        // 0. Registers and instruction lookup
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        let rs1_expr = rs1_read.expr();
        let rs2_expr = rs2_read.expr();
        let rd_expr = rd_written.expr();

        let carry_divide = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

        let rd_low: [_; UINT_LIMBS] =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("rd_mul_{i}")));
        let carry: [_; UINT_LIMBS * 2] =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("carry_{i}")));

        let mut carry_low: [Expression<E>; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_witin(|| format!("carry_low_{i}"))
                .expr()
        });

        for i in 0..UINT_LIMBS {
            let expected_limb = if i == 0 {
                E::BaseField::ZERO.expr()
            } else {
                carry_low[i - 1].clone()
            } + (0..=i).fold(E::BaseField::ZERO.expr(), |ac, k| {
                ac + (rs1_expr[k].clone() * rs2_expr[i - k].clone())
            });
            carry_low[i] = carry_divide.expr() * (expected_limb - rd_low[i].expr());
        }

        for (i, (rd_low, carry_low)) in rd_low.iter().zip(carry[0..UINT_LIMBS].iter()).enumerate() {
            circuit_builder
                .assert_ux::<_, _, 16>(|| format!("range_check_low_{i}"), rd_low.expr())?;
            circuit_builder
                .assert_ux::<_, _, 16>(|| format!("range_check_carry_low_{i}"), carry_low.expr())?;
        }

        for (i, (carry_low_expr, carry_low_witin)) in carry_low
            .iter()
            .zip(carry[0..UINT_LIMBS].iter())
            .enumerate()
        {
            circuit_builder.require_equal(
                || format!("carry_low_check_witin_{i}"),
                carry_low_expr.clone(),
                carry_low_witin.expr(),
            )?;
        }

        let mut carry_high: [Expression<E>; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_witin(|| format!("carry_high_{i}"))
                .expr()
        });

        let rs1_ext = circuit_builder.create_witin(|| format!("rs1_ext"));
        let rs2_ext = circuit_builder.create_witin(|| format!("rs2_ext"));

        for j in 0..UINT_LIMBS {
            let expected_limb =
                if j == 0 {
                    carry_low[UINT_LIMBS - 1].clone()
                } else {
                    carry_high[j - 1].clone()
                } + ((j + 1)..UINT_LIMBS).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (rs1_expr[k].clone() * rs2_expr[UINT_LIMBS + j - k].clone())
                }) + (0..(j + 1)).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (rs1_expr[k].clone() * rs2_ext.expr())
                        + (rs2_expr[k].clone() * rs1_ext.expr())
                });
            carry_high[j] =
                E::BaseField::from(carry_divide).expr() * (expected_limb - rd_expr[j].clone());
        }

        for (i, (rd_high, carry_high)) in rd_expr.iter().zip(carry[UINT_LIMBS..].iter()).enumerate()
        {
            circuit_builder
                .assert_ux::<_, _, 16>(|| format!("range_check_high_{i}"), rd_high.clone())?;
            circuit_builder.assert_ux::<_, _, 16>(
                || format!("range_check_carry_high_{i}"),
                carry_high.expr(),
            )?;
        }

        for (i, (carry_high_expr, carry_high_witin)) in carry_high
            .iter()
            .zip(carry[UINT_LIMBS..].iter())
            .enumerate()
        {
            circuit_builder.require_equal(
                || format!("carry_high_check_witin_{i}"),
                carry_high_expr.clone(),
                carry_high_witin.expr(),
            )?;
        }

        let sign_mask = E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1));
        let ext_inv = E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).inverse();
        let rs1_sign: Expression<E> = rs1_ext.expr() * ext_inv.expr();
        let rs2_sign: Expression<E> = rs2_ext.expr() * ext_inv.expr();

        circuit_builder.assert_bit(|| "rs1_sign_bool", rs1_sign.clone())?;
        circuit_builder.assert_bit(|| "rs2_sign_bool", rs2_sign.clone())?;

        match I::INST_KIND {
            InsnKind::MULH => {
                // Implement MULH circuit here
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulh_range_check_rs1_last",
                    E::BaseField::from_canonical_u32(2).expr() * rs1_expr[UINT_LIMBS - 1].clone()
                        - rs1_sign * sign_mask.expr(),
                )?;
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulh_range_check_rs2_last",
                    E::BaseField::from_canonical_u32(2).expr() * rs2_expr[UINT_LIMBS - 1].clone()
                        - rs2_sign * sign_mask.expr(),
                )?;
            }
            InsnKind::MULHU => {
                // Implement MULHU circuit here
                circuit_builder.require_zero(|| "mulhu_rs1_sign_zero", rs1_sign.clone())?;
                circuit_builder.require_zero(|| "mulhu_rs2_sign_zero", rs2_sign.clone())?;
            }
            InsnKind::MULHSU => {
                // Implement MULHSU circuit here
                circuit_builder.require_zero(|| "mulhsu_rs2_sign_zero", rs2_sign.clone())?;
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulhsu_range_check_rs1_last",
                    E::BaseField::from_canonical_u32(2).expr() * rs1_expr[UINT_LIMBS - 1].clone()
                        - rs1_sign * sign_mask.expr(),
                )?;
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulhsu_range_check_rs2_last",
                    rs2_expr[UINT_LIMBS - 1].clone() - rs2_sign * sign_mask.expr(),
                )?;
            }
            InsnKind::MUL => {
                // Implement MUL circuit here
            }
            _ => unreachable!("Unsupported instruction kind"),
        }

        Ok(MulhConfig {
            rs1_read,
            rs2_read,
            rd_written,
            r_insn,
            rd_low,
            carry,
            rs1_ext,
            rs2_ext,
            phantom: PhantomData,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // Read registers from step
        let rs1 = step.rs1().unwrap().value;
        let rs1_val = Value::new_unchecked(rs1);
        let rs1_limbs = rs1_val.as_u16_limbs();
        config.rs1_read.assign_limbs(instance, rs1_limbs);

        let rs2 = step.rs2().unwrap().value;
        let rs2_val = Value::new_unchecked(rs2);
        let rs2_limbs = rs2_val.as_u16_limbs();
        config.rs2_read.assign_limbs(instance, rs2_limbs);

        let rd = step.rd().unwrap().value.after;
        let rd_val = Value::new(rd, lk_multiplicity);
        config
            .rd_written
            .assign_limbs(instance, rd_val.as_u16_limbs());

        // R-type instruction
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let (rd_high, rd_low, carry, rs1_ext, rs2_ext) = run_mulh::<UINT_LIMBS, LIMB_BITS>(
            I::INST_KIND,
            rs1_val
                .as_u16_limbs()
                .iter()
                .map(|x| *x as u32)
                .collect::<Vec<_>>()
                .as_slice(),
            rs2_val
                .as_u16_limbs()
                .iter()
                .map(|x| *x as u32)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        for i in 0..UINT_LIMBS {
            set_val!(instance, config.rd_low[i], rd_low[i] as u64);
        }
        for i in 0..UINT_LIMBS * 2 {
            set_val!(instance, config.carry[i], carry[i] as u64);
        }
        set_val!(instance, config.rs1_ext, rs1_ext as u64);
        set_val!(instance, config.rs2_ext, rs2_ext as u64);

        for (rd_low, carry_low) in rd_low.iter().zip(carry[0..UINT_LIMBS].iter()) {
            lk_multiplicity.assert_ux::<16>(*rd_low as u64);
            lk_multiplicity.assert_ux::<16>(*carry_low as u64);
        }

        for (rd_high, carry_high) in rd_high.iter().zip(carry[UINT_LIMBS..].iter()) {
            lk_multiplicity.assert_ux::<16>(*rd_high as u64);
            lk_multiplicity.assert_ux::<16>(*carry_high as u64);
        }

        let sign_mask = 1 << (UINT_LIMBS - 1);
        let ext = (1 << UINT_LIMBS) - 1;
        let rs1_sign = rs1_ext / ext;
        let rs2_sign = rs2_ext / ext;

        match I::INST_KIND {
            InsnKind::MULH => {}
            InsnKind::MULHU => {
                lk_multiplicity.assert_ux::<16>(
                    (2 * rs1_limbs[UINT_LIMBS - 1] as u32 - rs1_sign * sign_mask) as u64,
                );
                lk_multiplicity.assert_ux::<16>(
                    (2 * rs2_limbs[UINT_LIMBS - 1] as u32 - rs2_sign * sign_mask) as u64,
                );
            }
            InsnKind::MULHSU => {
                lk_multiplicity.assert_ux::<16>(
                    (2 * rs1_limbs[UINT_LIMBS - 1] as u32 - rs1_sign * sign_mask) as u64,
                );
                lk_multiplicity.assert_ux::<16>(
                    (rs2_limbs[UINT_LIMBS - 1] as u32 - rs2_sign * sign_mask) as u64,
                );
            }
            InsnKind::MUL => {}
            _ => unreachable!("Unsupported instruction kind"),
        }

        Ok(())
    }
}

fn run_mulh<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    kind: InsnKind,
    x: &[u32],
    y: &[u32],
) -> ([u32; NUM_LIMBS], [u32; NUM_LIMBS], Vec<u32>, u32, u32) {
    let mut mul = [0u64; NUM_LIMBS];
    let mut carry = vec![0; 2 * NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        if i > 0 {
            mul[i] = carry[i - 1];
        }
        for j in 0..=i {
            mul[i] += (x[j] * y[i - j]) as u64;
        }
        carry[i] = mul[i] >> LIMB_BITS;
        mul[i] %= 1 << LIMB_BITS;
    }

    let x_ext = (x[NUM_LIMBS - 1] >> (LIMB_BITS - 1))
        * if kind == InsnKind::MULHU {
            0
        } else {
            (1 << LIMB_BITS) - 1
        };
    let y_ext = (y[NUM_LIMBS - 1] >> (LIMB_BITS - 1))
        * if kind == InsnKind::MULH {
            (1 << LIMB_BITS) - 1
        } else {
            0
        };

    let mut mulh = [0; NUM_LIMBS];
    let mut x_prefix = 0;
    let mut y_prefix = 0;

    for i in 0..NUM_LIMBS {
        x_prefix += x[i];
        y_prefix += y[i];
        mulh[i] = carry[NUM_LIMBS + i - 1] + (x_prefix * y_ext) as u64 + (y_prefix * x_ext) as u64;
        for j in (i + 1)..NUM_LIMBS {
            mulh[i] += (x[j] * y[NUM_LIMBS + i - j]) as u64;
        }
        carry[NUM_LIMBS + i] = mulh[i] >> LIMB_BITS;
        mulh[i] %= 1 << LIMB_BITS;
    }

    let mut mulh_u32 = [0u32; NUM_LIMBS];
    let mut mul_u32 = [0u32; NUM_LIMBS];
    let mut carry_u32 = vec![0u32; 2 * NUM_LIMBS];

    for i in 0..NUM_LIMBS {
        mul_u32[i] = mul[i] as u32;
        mulh_u32[i] = mulh[i] as u32;
        carry_u32[i] = carry[i] as u32;
        carry_u32[i + NUM_LIMBS] = carry[i + NUM_LIMBS] as u32;
    }

    (mulh_u32, mul_u32, carry_u32, x_ext, y_ext)
}
