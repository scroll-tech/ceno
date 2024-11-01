use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::{constants::UInt, insn_base::MemAddr},
    set_val,
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff::Field;
use ff_ext::ExtensionField;
use itertools::izip;
use std::mem::MaybeUninit;

pub struct MemWordChange<const N_ZEROS: usize> {
    prev_limb_bytes: Vec<WitIn>,
    rs2_limb_bytes: Vec<WitIn>,

    expected_changes: Vec<WitIn>,
}

impl<const N_ZEROS: usize> MemWordChange<N_ZEROS> {
    pub(crate) fn construct_circuit<E: ExtensionField>(
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

        assert_eq!(UInt::<E>::NUM_LIMBS, 2);
        // for sb (n_zeros = 0)
        match N_ZEROS {
            0 => {
                assert!(prev_word.wits_in().is_some() && rs2_word.wits_in().is_some());

                let low_bits = addr.low_bit_exprs();
                let prev_limbs = prev_word.expr();
                let rs2_limbs = rs2_word.expr();

                // degree 2 expression
                let prev_target_limb = cb.select(&low_bits[1], &prev_limbs[1], &prev_limbs[0]);
                let prev_limb_bytes = decompose_limb(cb, "prev_limb", &prev_target_limb, 2)?;

                // extract the least significant byte from u16 limb
                let rs2_limb_bytes = alloc_bytes(cb, "rs2_limb[0]", 1)?;
                let u8_base_inv = E::BaseField::from(1 << 8).invert().unwrap();
                cb.assert_ux::<_, _, 8>(
                    || "rs2_limb[0].le_bytes[1]",
                    u8_base_inv.expr() * (&rs2_limbs[0] - rs2_limb_bytes[0].expr()),
                )?;

                // alloc a new witIn to cache degree 2 expression
                let expected_limb_change = cb.create_witin(|| "expected_limb_change");
                cb.condition_require_equal(
                    || "expected_limb_change = select(low_bits[0], rs2 - prev)",
                    low_bits[0].clone(),
                    expected_limb_change.expr(),
                    (rs2_limb_bytes[0].expr() - prev_limb_bytes[1].expr()) << 8,
                    rs2_limb_bytes[0].expr() - prev_limb_bytes[0].expr(),
                )?;

                // alloc a new witIn to cache degree 2 expression
                let expected_change = cb.create_witin(|| "expected_change");
                cb.condition_require_equal(
                    || "expected_change = select(low_bits[1], limb_change*2^16, limb_change)",
                    low_bits[1].clone(),
                    expected_change.expr(),
                    expected_limb_change.expr() << 16,
                    expected_limb_change.expr(),
                )?;

                Ok(MemWordChange {
                    prev_limb_bytes,
                    rs2_limb_bytes,
                    expected_changes: vec![expected_limb_change, expected_change],
                })
            }
            // for sh (n_zeros = 1)
            1 => {
                assert!(prev_word.wits_in().is_some() && rs2_word.wits_in().is_some());

                let low_bits = addr.low_bit_exprs();
                let prev_limbs = prev_word.expr();
                let rs2_limbs = rs2_word.expr();

                let expected_change = cb.create_witin(|| "expected_change");

                // alloc a new witIn to cache degree 2 expression
                cb.condition_require_equal(
                    || "expected_change = select(low_bits[1], 2^16*(limb_change))",
                    // degree 2 expression
                    low_bits[1].clone(),
                    expected_change.expr(),
                    (&rs2_limbs[0] - &prev_limbs[1]) << 16,
                    &rs2_limbs[0] - &prev_limbs[0],
                )?;

                Ok(MemWordChange {
                    prev_limb_bytes: vec![],
                    rs2_limb_bytes: vec![],
                    expected_changes: vec![expected_change],
                })
            }
            _ => unreachable!("N_ZEROS cannot be larger than 1"),
        }
    }

    pub(crate) fn value<E: ExtensionField>(&self) -> Expression<E> {
        assert!(N_ZEROS <= 1);

        self.expected_changes[1 - N_ZEROS].expr()
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
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
                    set_val!(instance, col, E::BaseField::from(byte as u64));
                    lk_multiplicity.assert_ux::<8>(byte as u64);
                }

                set_val!(
                    instance,
                    self.rs2_limb_bytes[0],
                    E::BaseField::from(rs2_limb.to_le_bytes()[0] as u64)
                );

                rs2_limb.to_le_bytes().into_iter().for_each(|byte| {
                    lk_multiplicity.assert_ux::<8>(byte as u64);
                });
                let change = if low_bits[0] == 0 {
                    E::BaseField::from(rs2_limb.to_le_bytes()[0] as u64)
                        - E::BaseField::from(prev_limb.to_le_bytes()[0] as u64)
                } else {
                    E::BaseField::from((rs2_limb.to_le_bytes()[0] as u64) << 8)
                        - E::BaseField::from((prev_limb.to_le_bytes()[1] as u64) << 8)
                };
                let final_change = if low_bits[1] == 0 {
                    change
                } else {
                    E::BaseField::from(1u64 << 16) * change
                };
                set_val!(instance, self.expected_changes[0], change);
                set_val!(instance, self.expected_changes[1], final_change);
            }
            1 => {
                let final_change = if low_bits[1] == 0 {
                    E::BaseField::from(rs2_limb as u64) - E::BaseField::from(prev_limb as u64)
                } else {
                    E::BaseField::from((rs2_limb as u64) << 16)
                        - E::BaseField::from((prev_limb as u64) << 16)
                };
                set_val!(instance, self.expected_changes[0], final_change);
            }
            _ => unreachable!("N_ZEROS cannot be larger than 1"),
        }

        Ok(())
    }
}
