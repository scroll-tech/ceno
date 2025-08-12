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
use ff_ext::ExtensionField;
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

        for (rd_low, carry_low) in rd_low.iter().zip(carry_low.iter()) {
            circuit_builder.assert_ux::<_, _, 16>(|| "range_check_low", rd_low.expr())?;
            circuit_builder.assert_ux::<_, _, 16>(|| "range_check_carry_low", carry_low.clone())?;
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

        for (rd_high, carry_high) in rd_expr.iter().zip(carry_high.iter()) {
            circuit_builder.assert_ux::<_, _, 16>(|| "range_check_high", rd_high.clone())?;
            circuit_builder
                .assert_ux::<_, _, 16>(|| "range_check_carry_high", carry_high.clone())?;
        }

        let sign_mask = E::BaseField::from_canonical_u32(1 << (UINT_LIMBS - 1));
        let ext_inv = E::BaseField::from_canonical_u32((1 << UINT_LIMBS) - 1).inverse();
        let rs1_sign: Expression<E> = rs1_ext.expr() * ext_inv.expr();
        let rs2_sign: Expression<E> = rs2_ext.expr() * ext_inv.expr();

        circuit_builder.assert_bit(|| "rs1_sign_bool", rs1_sign.clone())?;
        circuit_builder.assert_bit(|| "rs2_sign_bool", rs2_sign.clone())?;

        match I::INST_KIND {
            InsnKind::MULH => {
                // Implement MULH circuit here
            }
            InsnKind::MULHU => {
                // Implement MULHU circuit here
                circuit_builder.require_zero(|| "mulhu_rs1_sign_zero", rs1_sign.clone())?;
                circuit_builder.require_zero(|| "mulhu_rs2_sign_zero", rs2_sign.clone())?;
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulhu_range_check_rs1_last",
                    E::BaseField::from_canonical_u32(2).expr() * rs1_expr[UINT_LIMBS - 1].clone()
                        - rs1_sign * sign_mask.expr(),
                )?;
                circuit_builder.assert_ux::<_, _, 16>(
                    || "mulhu_range_check_rs2_last",
                    E::BaseField::from_canonical_u32(2).expr() * rs2_expr[UINT_LIMBS - 1].clone()
                        - rs2_sign * sign_mask.expr(),
                )?;
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
        config
            .rs1_read
            .assign_limbs(instance, rs1_val.as_u16_limbs());

        let rs2 = step.rs2().unwrap().value;
        let rs2_val = Value::new_unchecked(rs2);
        config
            .rs2_read
            .assign_limbs(instance, rs2_val.as_u16_limbs());

        let rd = step.rd().unwrap().value.after;
        let rd_val = Value::new(rd, lk_multiplicity);
        config
            .rd_written
            .assign_limbs(instance, rd_val.as_u16_limbs());

        // R-type instruction
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let (_, rd_low, carry, rs1_ext, rs2_ext) = run_mulh::<UINT_LIMBS, LIMB_BITS>(
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

        set_val!(instance, config.rd_low, rd_low);
        set_val!(instance, config.rs1_ext, rs1_ext);
        set_val!(instance, config.rs2_ext, rs2_ext);

        Ok(())
    }
}

fn run_mulh<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    kind: InsnKind,
    x: &[u32],
    y: &[u32],
) -> ([u32; NUM_LIMBS], [u32; NUM_LIMBS], Vec<u32>, u32, u32) {
    let mut mul = [0; NUM_LIMBS];
    let mut carry = vec![0; 2 * NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        if i > 0 {
            mul[i] = carry[i - 1];
        }
        for j in 0..=i {
            mul[i] += x[j] * y[i - j];
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
        mulh[i] = carry[NUM_LIMBS + i - 1] + x_prefix * y_ext + y_prefix * x_ext;
        for j in (i + 1)..NUM_LIMBS {
            mulh[i] += x[j] * y[NUM_LIMBS + i - j];
        }
        carry[NUM_LIMBS + i] = mulh[i] >> LIMB_BITS;
        mulh[i] %= 1 << LIMB_BITS;
    }

    (mulh, mul, carry, x_ext, y_ext)
}
