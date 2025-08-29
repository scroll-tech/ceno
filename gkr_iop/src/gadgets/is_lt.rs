use crate::utils::i64_to_base;
use ff_ext::{ExtensionField, FieldInto, SmallField};
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, WitIn, power_sequence};
use p3::field::Field;
use std::fmt::Display;
use witness::set_val;

use crate::{
    circuit_builder::CircuitBuilder, error::CircuitBuilderError,
    utils::lk_multiplicity::LkMultiplicity,
};

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
        max_bits: usize,
    ) -> Result<Self, CircuitBuilderError> {
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
                    max_bits,
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
    ) -> Result<(), CircuitBuilderError> {
        self.0.assign_instance_u64(instance, lkm, lhs, rhs)?;
        Ok(())
    }

    pub fn assign_instance_signed<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: i64,
        rhs: i64,
    ) -> Result<(), CircuitBuilderError> {
        self.0.assign_instance_i64(instance, lkm, lhs, rhs)?;
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
        max_bits: usize,
    ) -> Result<Self, CircuitBuilderError> {
        cb.namespace(
            || "is_lt",
            |cb| {
                let name = name_fn();
                let is_lt = cb.create_witin(|| format!("{name} is_lt witin"));
                cb.assert_bit(|| "is_lt_bit", is_lt.expr())?;

                let config =
                    InnerLtConfig::construct_circuit(cb, name, lhs, rhs, is_lt.expr(), max_bits)?;
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
    ) -> Result<(), CircuitBuilderError> {
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
    ) -> Result<(), CircuitBuilderError> {
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
    ) -> Result<(), CircuitBuilderError> {
        set_val!(instance, self.is_lt, is_lt as u64);
        self.config
            .assign_instance_field(instance, lkm, lhs, rhs, is_lt)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InnerLtConfig {
    pub diff: Vec<WitIn>,
    pub max_bits: usize,
}

impl InnerLtConfig {
    fn range(max_bits: usize) -> u64 {
        1u64 << max_bits
    }

    /// Construct an `InnerLtConfig` circuit which constrains two input
    /// expressions `lhs` and `rhs` to satisfy the relation
    ///
    /// - `rhs - lhs \in {1, ..., 2^(max_bits)}` when `is_lt_expr = 1`; and
    /// - `lhs - rhs \in {0, ..., 2^(max_bits) - 1}` when `is_lt_expr = 0`
    ///
    /// In the above, values are to be interpreted as finite field elements.
    ///
    /// This is accomplished by witnessing as a `max_bits`-bit value
    /// either `lhs - rhs` when `lhs` is required to
    /// be at least as large as `rhs`, or `lhs - rhs + 2^ (max_bits)`
    /// when `lhs` is required to be smaller than `lhs`.
    ///
    /// Note that the specific values of `lhs` and `rhs` are not relevant to the
    /// above conditions -- this means that the value of `max_bits`
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
        max_bits: usize,
    ) -> Result<Self, CircuitBuilderError> {
        assert!(E::BaseField::bits() - 1 > max_bits);
        let mut diff = (0..max_bits / u16::BITS as usize)
            .map(|i| cb.create_u16(|| format!("diff_{i}")))
            .collect::<Result<Vec<WitIn>, _>>()?;
        let remain_bits = max_bits % u16::BITS as usize;
        if remain_bits > 0 {
            let msl = cb.create_witin(|| "msl");
            match remain_bits {
                14 => cb.assert_ux::<_, _, 14>(|| name.clone(), msl.expr())?,
                8 => cb.assert_ux::<_, _, 8>(|| name.clone(), msl.expr())?,
                5 => cb.assert_ux::<_, _, 5>(|| name.clone(), msl.expr())?,
                1 => cb.assert_bit(|| name.clone(), msl.expr())?,
                // TODO refactor range table to support arbitrary range check
                _ => tracing::info!("not implement {} bit range check", remain_bits),
            }
            diff.push(msl);
        }

        let pows = power_sequence((1 << u16::BITS).into());

        // this operation is safe even limb
        let diff_expr = izip!(&diff, pows)
            .map(|(record, beta)| beta * record.expr())
            .sum::<Expression<E>>();

        let range = Self::range(max_bits);

        cb.require_equal(|| name.clone(), lhs - rhs, diff_expr - is_lt_expr * range)?;

        Ok(Self { diff, max_bits })
    }

    /// Assign instance values to this configuration where the ordering is
    /// determined by u64 value ordering.
    pub fn assign_instance_u64<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: u64,
        rhs: u64,
    ) -> Result<(), CircuitBuilderError> {
        self.assign_instance_field(
            instance,
            lkm,
            F::from_canonical_u64(lhs),
            F::from_canonical_u64(rhs),
            lhs < rhs,
        )
    }

    /// Assign instance values to this configuration where the ordering is
    /// determined by i64 value ordering.
    pub fn assign_instance_i64<F: SmallField>(
        &self,
        instance: &mut [F],
        lkm: &mut LkMultiplicity,
        lhs: i64,
        rhs: i64,
    ) -> Result<(), CircuitBuilderError> {
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
    ) -> Result<(), CircuitBuilderError> {
        let range_offset: F = if is_lt {
            Self::range(self.max_bits).into_f()
        } else {
            F::ZERO
        };

        let diff = (lhs - rhs + range_offset).to_canonical_u64();
        (0..self.max_bits / u16::BITS as usize).for_each(|i| {
            let wit = &self.diff[i];
            // extract the 16 bit limb from diff and assign to instance
            let val = (diff >> (i * u16::BITS as usize)) & 0xffff;
            lkm.assert_ux::<16>(val);
            set_val!(instance, wit, val);
        });
        let remain_bits = self.max_bits % u16::BITS as usize;
        if remain_bits > 0 {
            let wit = self.diff.last().unwrap();
            // extract remaining bits limb from diff and assign to instance
            let val = (diff >> ((self.diff.len() - 1) * u16::BITS as usize)) & 0xffff;
            match remain_bits {
                14 => lkm.assert_ux::<14>(val),
                8 => lkm.assert_ux::<8>(val),
                5 => lkm.assert_ux::<5>(val),
                1 => (), // there is nothing to do with bool check
                // TODO refactor range table to support arbitrary range check
                _ => tracing::info!("not implement {} bit range check", remain_bits),
            }
            set_val!(instance, wit, val);
        }
        Ok(())
    }
}

pub fn cal_lt_diff(is_lt: bool, max_bits: usize, lhs: u64, rhs: u64) -> u64 {
    (if is_lt {
        InnerLtConfig::range(max_bits)
    } else {
        0
    } + lhs
        - rhs)
}
