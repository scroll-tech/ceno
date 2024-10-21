use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::{constants::UInt, insn_base::MemAddr},
};
use ff_ext::ExtensionField;

pub struct MemWordChange<const N_ZEROS: usize> {
    // decompose limb into bytes iff N_ZEROS == 0
    old_limb_bytes: Vec<WitIn>,
    rs2_limb_bytes: Vec<WitIn>,

    // its length + N_ZEROS equals to 2
    expected_changes: Vec<WitIn>,
}

impl<E: ExtensionField, const N_ZEROS: usize> MemWordChange<N_ZEROS> {
    pub(crate) fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        addr: &MemAddr<E>,
        prev_word: &UInt<E>,
        rs2_word: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        let select =
            |bit: &Expression<E>, when_true: &Expression<E>, when_false: &Expression<E>| {
                bit.clone() * when_true.clone() + (1 - bit.clone()) * when_false.clone()
            };

        let decompose_limb = |limb_anno: &str,
                              limb: &Expression<E>,
                              num_bytes: usize|
         -> Result<Vec<WitIn>, ZKVMError> {
            let bytes = (0..num_bytes)
                .into_iter()
                .map(|i| cb.create_witin(|| format!("{}.le_bytes[{}]", limb_anno, i)))
                .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

            cb.require_equal(
                || format!("decompose {} into {} bytes", limb_anno, num_bytes),
                limb.clone(),
                bytes
                    .iter()
                    .enumerate()
                    .fold(Expression::ZERO, |acc, (idx, byte)| {
                        acc + E::BaseField::from(1 << (idx * 8)) * byte.expr()
                    }),
            )?;

            Ok(bytes)
        };

        // for sb (n_zeros = 0)
        match N_ZEROS {
            0 => {
                assert!(prev_word.wits_in().is_some() && rs2_word.wits_in().is_some());

                let low_bits = addr.low_bit_exprs();
                let prev_limbs = prev_word.expr();
                let rs2_limbs = rs2_word.expr();

                // degree == 2
                let prev_target_limb = select(&low_bits[1], &prev_limbs[1], &prev_limbs[0]);
                let rs2_target_limb = select(&low_bits[1], &rs2_limbs[1], &rs2_limbs[0]);

                let prev_limb_bytes = decompose_limb("prev_limb", &prev_target_limb, 2)?;
                let rs2_limb_bytes = decompose_limb("rs2_limb", &rs2_target_limb, 2)?;

                let expected_limb_change = cb.create_witin(|| "expected_limb_change")?;
                cb.require_equal(
                    || "expected_limb_change = select(low_bits[0], rs2 - prev)",
                    // degree 2 expression
                    select(
                        &low_bits[0],
                        E::BaseField::from(1 << 8)
                            * (rs2_limb_bytes[1].expr() - prev_limb_bytes[1].expr()),
                        E::BaseField::from(1)
                            * (rs2_limb_bytes[0].expr() - prev_limb_bytes[0].expr()),
                    ),
                    expected_limb_change.expr(),
                )?;

                let expected_change = cb.create_witin(|| "expected_change")?;
                cb.require_equal(
                    || "expected_change = select(low_bits[1], limb_change*2^16, limb_change)",
                    // degree 2 expression
                    select(
                        &low_bits[1],
                        E::BaseField::from(1 << 16) * expected_limb_change.expr(),
                        E::BaseField::from(1) * expected_limb_change.expr(),
                    ),
                    expected_change.expr(),
                )?;

                Ok(MemWordChange {
                    old_limb_bytes: prev_limb_bytes,
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

                let expected_change = cb.create_witin(|| "expected_change")?;

                cb.require_equal(
                    || "expected_change = select(low_bits[1], 2^16*(limb_change))",
                    // degree 2 expression
                    select(
                        &low_bits[1],
                        &E::BaseField::from(1 << 16)
                            * (rs2_limbs[1].clone() - prev_limbs[1].clone()),
                        &E::BaseField::from(1) * (rs2_limbs[1].clone() - prev_limbs[0].clone()),
                    ),
                    expected_change.expr(),
                )?;

                Ok(MemWordChange {
                    old_limb_bytes: vec![],
                    rs2_limb_bytes: vec![],
                    expected_changes: vec![expected_change],
                })
            }
            _ => unreachable!("N_ZEROS cannot be larger than 1"),
        }
    }

    pub(crate) fn value(&self) -> Expression<E> {
        assert!(N_ZEROS <= 1);

        self.expected_changes[1 - N_ZEROS].expr()
    }
}
