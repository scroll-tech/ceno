use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::riscv::{constants::UInt, insn_base::MemAddr},
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use either::Either;
use ff_ext::{ExtensionField, FieldInto};
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use witness::set_val;

pub struct MemWordUtil<E: ExtensionField, const N_ZEROS: usize> {
    prev_limb_bytes: Vec<WitIn>,
    rs2_limb_bytes: Vec<WitIn>,

    expected_limb: Option<WitIn>,
    expect_limbs_expr: [Expression<E>; 2],
}

impl<E: ExtensionField, const N_ZEROS: usize> MemWordUtil<E, N_ZEROS> {
    pub(crate) fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        addr: &MemAddr<E>,
        prev_word: &UInt<E>,
        rs2_word: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        let alloc_bytes = |cb: &mut CircuitBuilder<E>,
                           anno: &str,
                           num_bytes: usize|
         -> Result<Vec<WitIn>, ZKVMError> {
            (0..num_bytes)
                .map(|i| {
                    let byte = cb.create_witin(|| format!("{}.le_bytes[{}]", anno, i));
                    cb.assert_ux::<_, _, 8>(|| "byte range check", byte.expr())?;

                    Ok(byte)
                })
                .collect()
        };

        let decompose_limb = |cb: &mut CircuitBuilder<E>,
                              limb_anno: &str,
                              limb: &Expression<E>,
                              num_bytes: usize|
         -> Result<Vec<WitIn>, ZKVMError> {
            let bytes = alloc_bytes(cb, limb_anno, num_bytes)?;

            cb.require_equal(
                || format!("decompose {} into {} bytes", limb_anno, num_bytes),
                limb.clone(),
                bytes
                    .iter()
                    .enumerate()
                    .map(|(idx, byte)| byte.expr() << (idx * 8))
                    .sum(),
            )?;

            Ok(bytes)
        };

        assert!(prev_word.wits_in().is_some() && rs2_word.wits_in().is_some());

        let low_bits = addr.low_bit_exprs();
        let prev_limbs = prev_word.expr();
        let rs2_limbs = rs2_word.expr();

        assert_eq!(UInt::<E>::NUM_LIMBS, 2);
        // for sb (n_zeros = 0)
        let (expected_limb, prev_limb_bytes, rs2_limb_bytes) = match N_ZEROS {
            0 => {
                let expected_limb = cb.create_witin(|| "expected_limb");

                // degree 2 expression
                let prev_target_limb = cb.select(&low_bits[1], &prev_limbs[1], &prev_limbs[0]);
                let prev_limb_bytes = decompose_limb(cb, "prev_limb", &prev_target_limb, 2)?;

                // extract the least significant byte from u16 limb
                let rs2_limb_bytes = alloc_bytes(cb, "rs2_limb[0]", 1)?;
                let u8_base_inv = E::BaseField::from_canonical_u64(1 << 8).inverse();
                cb.assert_ux::<_, _, 8>(
                    || "rs2_limb[0].le_bytes[1]",
                    u8_base_inv.expr() * (&rs2_limbs[0] - rs2_limb_bytes[0].expr()),
                )?;

                cb.condition_require_equal(
                    || "expected_limb = select(low_bits[0], rs2_limb_bytes[0] ++ prev_limb_bytes[0], prev_limb_bytes[1] ++ rs2_limb_bytes[0])",
                    low_bits[0].clone(),
                    expected_limb.expr(),
                    (rs2_limb_bytes[0].expr() << 8) + prev_limb_bytes[0].expr(),
                    (prev_limb_bytes[1].expr() << 8) + rs2_limb_bytes[0].expr(),
                )?;

                (Either::Left(expected_limb), prev_limb_bytes, rs2_limb_bytes)
            }
            // for sh (n_zeros = 1)
            1 => (Either::Right(rs2_limbs[0].expr()), vec![], vec![]),
            _ => unreachable!("N_ZEROS cannot be larger than 1"),
        };

        let hi_limb = cb.select(
            &low_bits[1],
            &expected_limb
                .as_ref()
                .map_either(|witin| witin.expr(), |expr| expr.expr())
                .into_inner(),
            &prev_limbs[1],
        );

        let lo_limb = cb.select(
            &low_bits[1],
            &prev_limbs[0],
            &expected_limb
                .as_ref()
                .map_either(|witin| witin.expr(), |expr| expr.expr())
                .into_inner(),
        );

        Ok(MemWordUtil {
            prev_limb_bytes,
            rs2_limb_bytes,
            expected_limb: expected_limb.map_either(Some, |_| None).into_inner(),
            expect_limbs_expr: [lo_limb, hi_limb],
        })
    }

    pub(crate) fn as_lo_hi(&self) -> &[Expression<E>; 2] {
        &self.expect_limbs_expr
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
        shift: u32,
    ) -> Result<(), ZKVMError> {
        let memory_op = step.memory_op().clone().unwrap();
        let prev_value = Value::new_unchecked(memory_op.value.before);
        let rs2_value = Value::new_unchecked(step.rs2().unwrap().value);

        let low_bits = [shift & 1, (shift >> 1) & 1];
        let prev_limb = prev_value.as_u16_limbs()[low_bits[1] as usize];
        let rs2_limb = rs2_value.as_u16_limbs()[0];

        match N_ZEROS {
            0 => {
                for (&col, byte) in izip!(&self.prev_limb_bytes, prev_limb.to_le_bytes()) {
                    set_val!(instance, col, E::BaseField::from_canonical_u8(byte));
                    lk_multiplicity.assert_ux::<8>(byte as u64);
                }

                let Some(expected_limb_witin) = self.expected_limb.as_ref() else {
                    unreachable!()
                };

                set_val!(
                    instance,
                    self.rs2_limb_bytes[0],
                    E::BaseField::from_canonical_u8(rs2_limb.to_le_bytes()[0])
                );

                rs2_limb.to_le_bytes().into_iter().for_each(|byte| {
                    lk_multiplicity.assert_ux::<8>(byte as u64);
                });
                let change = if low_bits[0] == 0 {
                    E::BaseField::from_canonical_u16((prev_limb.to_le_bytes()[1] as u16) << 8)
                        + E::BaseField::from_canonical_u8(rs2_limb.to_le_bytes()[0])
                } else {
                    E::BaseField::from_canonical_u16((rs2_limb.to_le_bytes()[0] as u16) << 8)
                        + E::BaseField::from_canonical_u8(prev_limb.to_le_bytes()[0])
                };
                set_val!(instance, expected_limb_witin, change);
            }
            1 => {
                // do nothing
            }
            _ => unreachable!("N_ZEROS cannot be larger than 1"),
        }

        Ok(())
    }
}
