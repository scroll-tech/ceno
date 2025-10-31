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

use crate::e2e::ShardContext;
use itertools::Itertools;
use std::{array, marker::PhantomData};

#[derive(Default)]
pub struct MulhInstructionBase<E, I: Default>(PhantomData<(E, I)>);

pub struct MulhConfig<E: ExtensionField> {
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    r_insn: RInstructionConfig<E>,
    rd_low: [WitIn; UINT_LIMBS],
    rd_high: Option<[WitIn; UINT_LIMBS]>,
    rs1_ext: Option<WitIn>,
    rs2_ext: Option<WitIn>,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;
    type Record = StepRecord;

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

        let rs1_expr = rs1_read.expr();
        let rs2_expr = rs2_read.expr();

        let carry_divide = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

        let rd_low: [_; UINT_LIMBS] =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("rd_low_{i}")));

        let mut carry_low: [Expression<E>; UINT_LIMBS] =
            array::from_fn(|_| E::BaseField::ZERO.expr());

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

        for (i, (rd_low, carry_low)) in rd_low.iter().zip(carry_low.iter()).enumerate() {
            circuit_builder.assert_dynamic_range(
                || format!("range_check_rd_low_{i}"),
                rd_low.expr(),
                E::BaseField::from_canonical_u32(16).expr(),
            )?;
            circuit_builder.assert_dynamic_range(
                || format!("range_check_carry_low_{i}"),
                carry_low.expr(),
                E::BaseField::from_canonical_u32(18).expr(),
            )?;
        }

        let (rd_high, rs1_ext, rs2_ext) = match I::INST_KIND {
            InsnKind::MULH | InsnKind::MULHU | InsnKind::MULHSU => {
                let rd_high: [_; UINT_LIMBS] =
                    array::from_fn(|i| circuit_builder.create_witin(|| format!("rd_high_{i}")));

                let rs1_ext = circuit_builder.create_witin(|| "rs1_ext".to_string());
                let rs2_ext = circuit_builder.create_witin(|| "rs2_ext".to_string());

                let mut carry_high: [Expression<E>; UINT_LIMBS] =
                    array::from_fn(|_| E::BaseField::ZERO.expr());
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
                    carry_high[j] = carry_divide.expr() * (expected_limb - rd_high[j].expr());
                }

                for (i, (rd_high, carry_high)) in rd_high.iter().zip(carry_high.iter()).enumerate()
                {
                    circuit_builder.assert_dynamic_range(
                        || format!("range_check_high_{i}"),
                        rd_high.expr(),
                        E::BaseField::from_canonical_u32(16).expr(),
                    )?;
                    circuit_builder.assert_dynamic_range(
                        || format!("range_check_carry_high_{i}"),
                        carry_high.expr(),
                        E::BaseField::from_canonical_u32(18).expr(),
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
                        circuit_builder.assert_dynamic_range(
                            || "mulh_range_check_rs1_last",
                            E::BaseField::from_canonical_u32(2).expr()
                                * (rs1_expr[UINT_LIMBS - 1].clone() - rs1_sign * sign_mask.expr()),
                            E::BaseField::from_canonical_u32(16).expr(),
                        )?;
                        circuit_builder.assert_dynamic_range(
                            || "mulh_range_check_rs2_last",
                            E::BaseField::from_canonical_u32(2).expr()
                                * (rs2_expr[UINT_LIMBS - 1].clone() - rs2_sign * sign_mask.expr()),
                            E::BaseField::from_canonical_u32(16).expr(),
                        )?;
                    }
                    InsnKind::MULHU => {
                        // Implement MULHU circuit here
                        circuit_builder.require_zero(|| "mulhu_rs1_sign_zero", rs1_sign.clone())?;
                        circuit_builder.require_zero(|| "mulhu_rs2_sign_zero", rs2_sign.clone())?;
                    }
                    InsnKind::MULHSU => {
                        // Implement MULHSU circuit here
                        circuit_builder
                            .require_zero(|| "mulhsu_rs2_sign_zero", rs2_sign.clone())?;
                        circuit_builder.assert_dynamic_range(
                            || "mulhsu_range_check_rs1_last",
                            E::BaseField::from_canonical_u32(2).expr()
                                * (rs1_expr[UINT_LIMBS - 1].clone() - rs1_sign * sign_mask.expr()),
                            E::BaseField::from_canonical_u32(16).expr(),
                        )?;
                        circuit_builder.assert_dynamic_range(
                            || "mulhsu_range_check_rs2_last",
                            rs2_expr[UINT_LIMBS - 1].clone() - rs2_sign * sign_mask.expr(),
                            E::BaseField::from_canonical_u32(16).expr(),
                        )?;
                    }
                    InsnKind::MUL => (),
                    _ => unreachable!("Unsupported instruction kind"),
                }

                Some((rd_high, rs1_ext, rs2_ext))
            }
            InsnKind::MUL => None,
            _ => unreachable!("unsupported instruction kind"),
        }
        .map(|(rd_high, rs1_ext, rs2_ext)| (Some(rd_high), Some(rs1_ext), Some(rs2_ext)))
        .unwrap_or_else(|| (None, None, None));

        let rd_written = match I::INST_KIND {
            InsnKind::MULH | InsnKind::MULHU | InsnKind::MULHSU => UInt::from_exprs_unchecked(
                rd_high
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|w| w.expr())
                    .collect_vec(),
            ),
            InsnKind::MUL => {
                UInt::from_exprs_unchecked(rd_low.iter().map(|w| w.expr()).collect_vec())
            }
            _ => unreachable!("unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(MulhConfig {
            rs1_read,
            rs2_read,
            r_insn,
            rd_high,
            rd_low,
            // carry,
            rs1_ext,
            rs2_ext,
            phantom: PhantomData,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
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

        // R-type instruction
        config
            .r_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

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

        for (rd_low, carry_low) in rd_low.iter().zip(carry[0..UINT_LIMBS].iter()) {
            lk_multiplicity.assert_dynamic_range(*rd_low as u64, 16);
            lk_multiplicity.assert_dynamic_range(*carry_low as u64, 18);
        }

        for i in 0..UINT_LIMBS {
            set_val!(instance, config.rd_low[i], rd_low[i] as u64);
        }
        match I::INST_KIND {
            InsnKind::MULH | InsnKind::MULHU | InsnKind::MULHSU => {
                for i in 0..UINT_LIMBS {
                    set_val!(
                        instance,
                        config.rd_high.as_ref().unwrap()[i],
                        rd_high[i] as u64
                    );
                }
                set_val!(instance, config.rs1_ext.as_ref().unwrap(), rs1_ext as u64);
                set_val!(instance, config.rs2_ext.as_ref().unwrap(), rs2_ext as u64);

                for (rd_high, carry_high) in rd_high.iter().zip(carry[UINT_LIMBS..].iter()) {
                    lk_multiplicity.assert_dynamic_range(*rd_high as u64, 16);
                    lk_multiplicity.assert_dynamic_range(*carry_high as u64, 18);
                }
            }
            _ => (),
        }

        let sign_mask = 1 << (LIMB_BITS - 1);
        let ext = (1 << LIMB_BITS) - 1;
        let rs1_sign = rs1_ext / ext;
        let rs2_sign = rs2_ext / ext;

        match I::INST_KIND {
            InsnKind::MULH => {
                lk_multiplicity.assert_dynamic_range(
                    (2 * (rs1_limbs[UINT_LIMBS - 1] as u32 - rs1_sign * sign_mask)) as u64,
                    16,
                );
                lk_multiplicity.assert_dynamic_range(
                    (2 * (rs2_limbs[UINT_LIMBS - 1] as u32 - rs2_sign * sign_mask)) as u64,
                    16,
                );
            }
            InsnKind::MULHU => {}
            InsnKind::MULHSU => {
                lk_multiplicity.assert_dynamic_range(
                    (2 * (rs1_limbs[UINT_LIMBS - 1] as u32 - rs1_sign * sign_mask)) as u64,
                    16,
                );
                lk_multiplicity.assert_dynamic_range(
                    (rs2_limbs[UINT_LIMBS - 1] as u32 - rs2_sign * sign_mask) as u64,
                    16,
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
        mulh[i] = carry[NUM_LIMBS + i - 1]
            + (x_prefix as u64 * y_ext as u64)
            + (y_prefix as u64 * x_ext as u64);
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
