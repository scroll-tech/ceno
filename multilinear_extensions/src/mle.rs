use std::{borrow::Cow, mem, sync::Arc};

use crate::op_mle;
use ark_std::{end_timer, rand::RngCore, start_timer};
use core::hash::Hash;
use ff::Field;
use ff_ext::ExtensionField;
use rayon::iter::IntoParallelRefIterator;
use serde::{Deserialize, Serialize};

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

#[derive(Clone, PartialEq, Eq, Hash, Default, Debug, Serialize, Deserialize)]
#[serde(untagged)]
/// Differentiate inner vector on base/extension field.
pub enum FieldType<E: ExtensionField> {
    Base(#[serde(skip)] Vec<E::BaseField>),
    Ext(Vec<E>),
    #[default]
    Unreachable,
}

impl<E: ExtensionField> FieldType<E> {
    pub fn len(&self) -> usize {
        match self {
            FieldType::Base(content) => content.len(),
            FieldType::Ext(content) => content.len(),
            FieldType::Unreachable => unreachable!(),
        }
    }
}

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct DenseMultilinearExtension<E: ExtensionField> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: FieldType<E>,
    /// Number of variables
    pub num_vars: usize,
}

pub type ArcDenseMultilinearExtension<E> = Arc<DenseMultilinearExtension<E>>;

impl<E: ExtensionField> DenseMultilinearExtension<E> {
    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[E::BaseField]) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<E::BaseField>) -> Self {
        // assert that the number of variables matches the size of evaluations
        // TODO: return error.
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            num_vars,
            evaluations: FieldType::Base(evaluations),
        }
    }

    /// Identical to [`from_evaluations_slice`], with and exception that evaluation vector is in extension field
    pub fn from_evaluations_ext_slice(num_vars: usize, evaluations: &[E]) -> Self {
        Self::from_evaluations_ext_vec(num_vars, evaluations.to_vec())
    }

    /// Identical to [`from_evaluations_vec`], with and exception that evaluation vector is in extension field
    pub fn from_evaluations_ext_vec(num_vars: usize, evaluations: Vec<E>) -> Self {
        // assert that the number of variables matches the size of evaluations
        // TODO: return error.
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            num_vars,
            evaluations: FieldType::Ext(evaluations),
        }
    }

    /// Evaluate the MLE at a give point.
    /// Returns an error if the MLE length does not match the point.
    pub fn evaluate(&self, point: &[E]) -> E {
        // TODO: return error.
        assert_eq!(
            self.num_vars,
            point.len(),
            "MLE size does not match the point"
        );
        let mle = self.fix_variables(point);
        op_mle!(mle, |f| f[0], |v| E::from(v))
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_variables(&self, partial_point: &[E]) -> Self {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut poly = Cow::Borrowed(self);

        // evaluate single variable of partial point from left to right
        // `Cow` type here to skip first evaluation vector copy
        for point in partial_point.iter() {
            match &mut poly {
                poly @ Cow::Borrowed(_) => {
                    *poly = op_mle!(self, |evaluations| {
                        Cow::Owned(DenseMultilinearExtension::from_evaluations_ext_vec(
                            self.num_vars - 1,
                            evaluations
                                .par_iter()
                                .chunks(2)
                                .with_min_len(64)
                                .map(|buf| *point * (*buf[1] - *buf[0]) + *buf[0])
                                .collect(),
                        ))
                    });
                }
                Cow::Owned(poly) => poly.fix_variables_in_place(&[*point]),
            }
        }
        assert!(poly.num_vars == self.num_vars - partial_point.len(),);
        poly.into_owned()
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point` in place
    pub fn fix_variables_in_place(&mut self, partial_point: &[E]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let nv = self.num_vars;
        // evaluate single variable of partial point from left to right
        for (i, point) in partial_point.iter().enumerate() {
            let max_log2_size = nv - i;
            // override buf[b1, b2,..bt, 0] = (1-point) * buf[b1, b2,..bt, 0] + point * buf[b1, b2,..bt, 1] in parallel
            match &mut self.evaluations {
                FieldType::Base(evaluations) => {
                    let evaluations_ext = evaluations
                        .par_iter()
                        .chunks(2)
                        .with_min_len(64)
                        .map(|buf| *point * (*buf[1] - *buf[0]) + *buf[0])
                        .collect();
                    let _ = mem::replace(&mut self.evaluations, FieldType::Ext(evaluations_ext));
                }
                FieldType::Ext(evaluations) => {
                    evaluations
                        .par_iter_mut()
                        .chunks(2)
                        .with_min_len(64)
                        .for_each(|mut buf| *buf[0] = *buf[0] + (*buf[1] - *buf[0]) * point);

                    // sequentially update buf[b1, b2,..bt] = buf[b1, b2,..bt, 0]
                    for index in 0..1 << (max_log2_size - 1) {
                        evaluations[index] = evaluations[index << 1];
                    }
                }
                FieldType::Unreachable => unreachable!(),
            };
        }
        match &mut self.evaluations {
            FieldType::Base(_) => unreachable!(),
            FieldType::Ext(evaluations) => {
                evaluations.truncate(1 << (nv - partial_point.len()));
            }
            FieldType::Unreachable => unreachable!(),
        }

        self.num_vars = nv - partial_point.len();
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point` from high position
    pub fn fix_high_variables(&self, partial_point: &[E]) -> Self {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let current_eval_size = self.evaluations.len();
        let mut poly = Cow::Borrowed(self);
        // `Cow` type here to skip first evaluation vector copy
        for point in partial_point.iter().rev() {
            match &mut poly {
                poly @ Cow::Borrowed(_) => {
                    let half_size = current_eval_size >> 1;
                    *poly = op_mle!(self, |evaluations| Cow::Owned(
                        DenseMultilinearExtension::from_evaluations_ext_vec(self.num_vars - 1, {
                            let (lo, hi) = evaluations.split_at(half_size);
                            lo.par_iter()
                                .zip(hi)
                                .with_min_len(64)
                                .map(|(lo, hi)| *point * (*hi - *lo) + *lo)
                                .collect()
                        })
                    ));
                }
                Cow::Owned(poly) => poly.fix_high_variables_in_place(&[*point]),
            }
        }
        assert!(poly.num_vars == self.num_vars - partial_point.len(),);
        poly.into_owned()
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point` from high position in place
    pub fn fix_high_variables_in_place(&mut self, partial_point: &[E]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let nv = self.num_vars;
        let mut current_eval_size = self.evaluations.len();
        for point in partial_point.iter().rev() {
            let half_size = current_eval_size >> 1;
            match &mut self.evaluations {
                FieldType::Base(evaluations) => {
                    let (lo, hi) = evaluations.split_at(half_size);
                    let evaluations_ext = lo
                        .par_iter()
                        .zip(hi)
                        .with_min_len(64)
                        .map(|(lo, hi)| *point * (*hi - *lo) + *lo)
                        .collect();
                    let _ = mem::replace(&mut self.evaluations, FieldType::Ext(evaluations_ext));
                    current_eval_size = half_size;
                }
                FieldType::Ext(evaluations) => {
                    let (lo, hi) = evaluations.split_at_mut(half_size);
                    lo.par_iter_mut()
                        .zip(hi)
                        .with_min_len(64)
                        .for_each(|(lo, hi)| *lo += (*hi - *lo) * point);
                    current_eval_size = half_size;
                }
                FieldType::Unreachable => unreachable!(),
            };
        }
        match &mut self.evaluations {
            FieldType::Base(_) => {}
            FieldType::Ext(evaluations) => {
                evaluations.truncate(current_eval_size);
            }
            FieldType::Unreachable => unreachable!(),
        }
        self.num_vars = nv - partial_point.len()
    }

    /// Generate a random evaluation of a multilinear poly
    pub fn random(nv: usize, mut rng: &mut impl RngCore) -> Self {
        let eval = (0..1 << nv)
            .map(|_| E::BaseField::random(&mut rng))
            .collect();
        DenseMultilinearExtension::from_evaluations_vec(nv, eval)
    }

    /// Sample a random list of multilinear polynomials.
    /// Returns
    /// - the list of polynomials,
    /// - its sum of polynomial evaluations over the boolean hypercube.
    pub fn random_mle_list(
        nv: usize,
        degree: usize,
        mut rng: &mut impl RngCore,
    ) -> (Vec<ArcDenseMultilinearExtension<E>>, E) {
        let start = start_timer!(|| "sample random mle list");
        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        let mut sum = E::ZERO;

        for _ in 0..(1 << nv) {
            let mut product = E::ONE;

            for e in multiplicands.iter_mut() {
                let val = E::BaseField::random(&mut rng);
                e.push(val);
                product = product * &val;
            }
            sum += product;
        }

        let list = multiplicands
            .into_iter()
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x).into())
            .collect();

        end_timer!(start);
        (list, sum)
    }

    // Build a randomize list of mle-s whose sum is zero.
    pub fn random_zero_mle_list(
        nv: usize,
        degree: usize,
        mut rng: impl RngCore,
    ) -> Vec<ArcDenseMultilinearExtension<E>> {
        let start = start_timer!(|| "sample random zero mle list");

        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        for _ in 0..(1 << nv) {
            multiplicands[0].push(E::BaseField::ZERO);
            for e in multiplicands.iter_mut().skip(1) {
                e.push(E::BaseField::random(&mut rng));
            }
        }

        let list = multiplicands
            .into_iter()
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x).into())
            .collect();

        end_timer!(start);
        list
    }

    pub fn to_ext_field(&self) -> Self {
        op_mle!(self, |evaluations| {
            DenseMultilinearExtension::from_evaluations_ext_vec(
                self.num_vars,
                evaluations.iter().map(|f| E::from(*f)).collect(),
            )
        })
    }
}

#[macro_export]
macro_rules! op_mle {
    ($a:ident, |$tmp_a:ident| $op:expr, |$b_out:ident| $op_b_out:expr) => {
        match &$a.evaluations {
            $crate::mle::FieldType::Base(a) => {
                let $tmp_a = a;
                let $b_out = $op;
                $op_b_out
            }
            $crate::mle::FieldType::Ext(a) => {
                let $tmp_a = a;
                $op
            }
            _ => unreachable!(),
        }
    };
    ($a:ident, |$tmp_a:ident| $op:expr) => {
        op_mle!($a, |$tmp_a| $op, |out| out)
    };
    (|$a:ident| $op:expr, |$b_out:ident| $op_b_out:expr) => {
        op_mle!($a, |$a| $op, |$b_out| $op_b_out)
    };
    (|$a:ident| $op:expr) => {
        op_mle!(|$a| $op, |out| out)
    };
}

/// macro support op(a, b) and tackles type matching internally.
/// Please noted that op must satisfy commutative rule w.r.t op(b, a) operand swap.
#[macro_export]
macro_rules! commutative_op_mle_pair {
    (|$a:ident, $b:ident| $op:expr, |$bb_out:ident| $op_bb_out:expr) => {
        match (&$a.evaluations, &$b.evaluations) {
            ($crate::mle::FieldType::Base(a), $crate::mle::FieldType::Base(b)) => {
                let $a = a;
                let $b = b;
                let $bb_out = $op;
                $op_bb_out
            }
            ($crate::mle::FieldType::Ext(a), $crate::mle::FieldType::Base(b))
            | ($crate::mle::FieldType::Base(b), $crate::mle::FieldType::Ext(a)) => {
                let $a = a;
                let $b = b;
                $op
            }
            ($crate::mle::FieldType::Ext(a), $crate::mle::FieldType::Ext(b)) => {
                let $a = a;
                let $b = b;
                $op
            }
            _ => unreachable!(),
        }
    };
    (|$a:ident, $b:ident| $op:expr) => {
        op_mles!(|$a, $b| $op, |out| out)
    };
}
