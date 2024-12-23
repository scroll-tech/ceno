use std::fmt::Display;

use ceno_emul::{SWord, Word};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::izip;

use crate::{
    Value,
    chip_handler::utils::power_sequence,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::constants::{UINT_LIMBS, UInt},
    set_val,
    utils::i64_to_base,
    witness::LkMultiplicity,
};

use super::SignedExtendConfig;

#[derive(Debug, Clone)]
pub struct AssertLtConfig(InnerLtConfig);

impl AssertLtConfig {
    pub fn construct_circuit<
        E: ExtensionField,
        NR: Into<String> + Display + Clone,
        N: FnOnce() -> NR,
    >(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: Expression<E>,
        rhs: Expression<E>,
        max_num_u16_limbs: usize,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(
            || "assert_lt",
            |cb| {
                let name = name_fn();
                let config = InnerLtConfig::construct_circuit(
                    cb,
                    name,
                    lhs,
                    rhs,
                    Expression::ONE,
                    max_num_u16_limbs,
                )?;
                Ok(Self(config))
            },
        )
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: u64,
        rhs: u64,
    ) -> Result<(), ZKVMError> {
        self.0.assign_instance_u64(instance, lkm, lhs, rhs)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct IsLtConfig {
    pub is_lt: WitIn,
    config: InnerLtConfig,
}

impl IsLtConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.is_lt.expr()
    }

    pub fn construct_circuit<
        E: ExtensionField,
        NR: Into<String> + Display + Clone,
        N: FnOnce() -> NR,
    >(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: Expression<E>,
        rhs: Expression<E>,
        max_num_u16_limbs: usize,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(
            || "is_lt",
            |cb| {
                let name = name_fn();
                let is_lt = cb.create_witin(|| format!("{name} is_lt witin"));
                cb.assert_bit(|| "is_lt_bit", is_lt.expr())?;

                let config = InnerLtConfig::construct_circuit(
                    cb,
                    name,
                    lhs,
                    rhs,
                    is_lt.expr(),
                    max_num_u16_limbs,
                )?;
                Ok(Self { is_lt, config })
            },
        )
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: u64,
        rhs: u64,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.is_lt, (lhs < rhs) as u64);
        self.config.assign_instance_u64(instance, lkm, lhs, rhs)?;
        Ok(())
    }

    pub fn assign_instance_signed<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: i64,
        rhs: i64,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.is_lt, (lhs < rhs) as u64);
        self.config.assign_instance_i64(instance, lkm, lhs, rhs)?;
        Ok(())
    }

    pub fn assign_instance_field<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: F,
        rhs: F,
        is_lt: bool,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.is_lt, is_lt as u64);
        self.config
            .assign_instance_field(instance, lkm, lhs, rhs, is_lt)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InnerLtConfig {
    pub diff: Vec<WitIn>,
    pub max_num_u16_limbs: usize,
}

impl InnerLtConfig {
    fn range(max_num_u16_limbs: usize) -> u64 {
        1u64 << (u16::BITS as usize * max_num_u16_limbs)
    }

    /// Construct an `InnerLtConfig` circuit which constrains two input
    /// expressions `lhs` and `rhs` to satisfy the relation
    ///
    /// - `rhs - lhs \in {1, ..., 2^(16*max_num_u16_limbs)}` when `is_lt_expr = 1`; and
    /// - `lhs - rhs \in {0, ..., 2^(16*max_num_u16_limbs) - 1}` when `is_lt_expr = 0`
    ///
    /// In the above, values are to be interpreted as finite field elements.
    ///
    /// This is accomplished by witnessing as a `16*max_num_u16_limbs`-bit value
    /// using 16-bit unsigned limbs either `lhs - rhs` when `lhs` is required to
    /// be at least as large as `rhs`, or `lhs - rhs + 2^ (16*max_num_u16_limbs)`
    /// when `lhs` is required to be smaller than `lhs`.
    ///
    /// Note that the specific values of `lhs` and `rhs` are not relevant to the
    /// above conditions -- this means that the value of `max_num_u16_limbs`
    /// only needs to depend on the size of the *difference* between values,
    /// not on their absolute magnitude.  That is, one limb is sufficient to
    /// express that 2^48 - 12 is less than 2^48 + 71, since their difference
    /// of 83 is within the magnitudes representable by a single 16-bit limb.
    ///
    /// Since there is ambiguity in ordering of values when they are interpreted
    /// as elements in a finite field, several functions are available for
    /// witness assignment which take unsigned or signed inputs (which have a
    /// standard ordering interpretation which is used for the witness
    /// assignment), or field elements with an additional explicit boolean
    /// input indicating directly whether `is_lt_expr` is 0 or 1.
    pub fn construct_circuit<E: ExtensionField, NR: Into<String> + Display + Clone>(
        cb: &mut CircuitBuilder<E>,
        name: NR,
        lhs: Expression<E>,
        rhs: Expression<E>,
        is_lt_expr: Expression<E>,
        max_num_u16_limbs: usize,
    ) -> Result<Self, ZKVMError> {
        assert!(max_num_u16_limbs >= 1);

        let mut witin_u16 = |var_name: String| -> Result<WitIn, ZKVMError> {
            cb.namespace(
                || format!("var {var_name}"),
                |cb| {
                    let witin = cb.create_witin(|| var_name.to_string());
                    cb.assert_ux::<_, _, 16>(|| name.clone(), witin.expr())?;
                    Ok(witin)
                },
            )
        };

        let diff = (0..max_num_u16_limbs)
            .map(|i| witin_u16(format!("diff_{i}")))
            .collect::<Result<Vec<WitIn>, _>>()?;

        let pows = power_sequence((1 << u16::BITS).into());

        let diff_expr = izip!(&diff, pows)
            .map(|(record, beta)| beta * record.expr())
            .sum::<Expression<E>>();

        let range = Self::range(max_num_u16_limbs);

        cb.require_equal(|| name.clone(), lhs - rhs, diff_expr - is_lt_expr * range)?;

        Ok(Self {
            diff,
            max_num_u16_limbs,
        })
    }

    /// Assign instance values to this configuration where the ordering is
    /// determined by u64 value ordering.
    pub fn assign_instance_u64<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: u64,
        rhs: u64,
    ) -> Result<(), ZKVMError> {
        self.assign_instance_field(instance, lkm, lhs.into(), rhs.into(), lhs < rhs)
    }

    /// Assign instance values to this configuration where the ordering is
    /// determined by i64 value ordering.
    pub fn assign_instance_i64<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: i64,
        rhs: i64,
    ) -> Result<(), ZKVMError> {
        let lhs_f = i64_to_base::<F>(lhs);
        let rhs_f = i64_to_base::<F>(rhs);
        self.assign_instance_field(instance, lkm, lhs_f, rhs_f, lhs < rhs)
    }

    /// Assign values to this instance using field inputs, where the intended
    /// ordering of the field values is specified by the `is_lt` boolean input,
    /// indicating whether `lhs` is meant to be less than `rhs`.
    pub fn assign_instance_field<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: F,
        rhs: F,
        is_lt: bool,
    ) -> Result<(), ZKVMError> {
        let range_offset: F = if is_lt {
            Self::range(self.max_num_u16_limbs).into()
        } else {
            F::ZERO
        };
        let diff = (lhs - rhs + range_offset).to_canonical_u64();
        self.diff.iter().enumerate().for_each(|(i, wit)| {
            // extract the 16 bit limb from diff and assign to instance
            let val = (diff >> (i * u16::BITS as usize)) & 0xffff;
            lkm.assert_ux::<16>(val);
            set_val!(instance, wit, val);
        });
        Ok(())
    }
}

pub fn cal_lt_diff(is_lt: bool, max_num_u16_limbs: usize, lhs: u64, rhs: u64) -> u64 {
    (if is_lt {
        InnerLtConfig::range(max_num_u16_limbs)
    } else {
        0
    } + lhs
        - rhs)
}

#[derive(Debug)]
pub struct AssertSignedLtConfig<E> {
    config: InnerSignedLtConfig<E>,
}

impl<E: ExtensionField> AssertSignedLtConfig<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(
            || "assert_signed_lt",
            |cb| {
                let name = name_fn();
                let config =
                    InnerSignedLtConfig::construct_circuit(cb, name, lhs, rhs, Expression::ONE)?;
                Ok(Self { config })
            },
        )
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), ZKVMError> {
        self.config.assign_instance(instance, lkm, lhs, rhs)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SignedLtConfig<E> {
    is_lt: WitIn,
    config: InnerSignedLtConfig<E>,
}

impl<E: ExtensionField> SignedLtConfig<E> {
    pub fn expr(&self) -> Expression<E> {
        self.is_lt.expr()
    }

    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(
            || "is_signed_lt",
            |cb| {
                let name = name_fn();
                let is_lt = cb.create_witin(|| format!("{name} is_signed_lt witin"));
                cb.assert_bit(|| "is_lt_bit", is_lt.expr())?;
                let config =
                    InnerSignedLtConfig::construct_circuit(cb, name, lhs, rhs, is_lt.expr())?;

                Ok(SignedLtConfig { is_lt, config })
            },
        )
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.is_lt, (lhs < rhs) as u64);
        self.config
            .assign_instance(instance, lkm, lhs as SWord, rhs as SWord)?;
        Ok(())
    }
}

#[derive(Debug)]
struct InnerSignedLtConfig<E> {
    is_lhs_neg: SignedExtendConfig<E>,
    is_rhs_neg: SignedExtendConfig<E>,
    config: InnerLtConfig,
}

impl<E: ExtensionField> InnerSignedLtConfig<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone>(
        cb: &mut CircuitBuilder<E>,
        name: NR,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
        is_lt_expr: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        // Extract the sign bit.
        let is_lhs_neg = lhs.is_negative(cb)?;
        let is_rhs_neg = rhs.is_negative(cb)?;

        // Convert to field arithmetic.
        let lhs_value = lhs.to_field_expr(is_lhs_neg.expr());
        let rhs_value = rhs.to_field_expr(is_rhs_neg.expr());
        let config = InnerLtConfig::construct_circuit(
            cb,
            format!("{name} (lhs < rhs)"),
            lhs_value,
            rhs_value,
            is_lt_expr,
            UINT_LIMBS,
        )?;

        Ok(Self {
            is_lhs_neg,
            is_rhs_neg,
            config,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), ZKVMError> {
        let lhs_value = Value::new_unchecked(lhs as Word);
        let rhs_value = Value::new_unchecked(rhs as Word);
        self.is_lhs_neg.assign_instance(
            instance,
            lkm,
            *lhs_value.as_u16_limbs().last().unwrap() as u64,
        )?;
        self.is_rhs_neg.assign_instance(
            instance,
            lkm,
            *rhs_value.as_u16_limbs().last().unwrap() as u64,
        )?;

        self.config
            .assign_instance_i64(instance, lkm, lhs as i64, rhs as i64)?;
        Ok(())
    }
}
