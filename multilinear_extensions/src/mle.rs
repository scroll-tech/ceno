use std::{borrow::Cow, sync::Arc};

use ark_std::{end_timer, rand::RngCore, start_timer};
use goldilocks::SmallField;
use rayon::iter::IntoParallelRefIterator;
use serde::{Deserialize, Serialize};

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug, Serialize, Deserialize)]
pub struct DenseMultilinearExtension<F> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: Vec<F>,
    /// Number of variables
    pub num_vars: usize,
}

pub type ArcDenseMultilinearExtension<F> = Arc<DenseMultilinearExtension<F>>;

impl<F: SmallField> DenseMultilinearExtension<F> {
    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<F>) -> Self {
        // assert that the number of variables matches the size of evaluations
        // TODO: return error.
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            num_vars,
            evaluations,
        }
    }

    /// Evaluate the MLE at a give point.
    /// Returns an error if the MLE length does not match the point.
    pub fn evaluate(&self, point: &[F]) -> F {
        // TODO: return error.
        assert_eq!(
            self.num_vars,
            point.len(),
            "MLE size does not match the point"
        );
        self.fix_variables(point).evaluations[0]
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_variables(&self, partial_point: &[F]) -> DenseMultilinearExtension<F> {
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
                    *poly = Cow::Owned(DenseMultilinearExtension::from_evaluations_vec(
                        self.num_vars - 1,
                        self.evaluations
                            .par_iter()
                            .chunks(2)
                            .with_min_len(64)
                            .map(|buf| *buf[0] + (*buf[1] - *buf[0]) * point)
                            .collect(),
                    ));
                }
                Cow::Owned(poly) => poly.fix_variables_in_place(&[*point]),
            }
        }
        assert!(poly.num_vars == self.num_vars - partial_point.len(),);
        poly.into_owned()
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point` in place
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let nv = self.num_vars;
        let poly = &mut self.evaluations;
        // evaluate single variable of partial point from left to right
        for (i, point) in partial_point.iter().enumerate() {
            let max_log2_size = nv - i;
            // override buf[b1, b2,..bt, 0] = (1-point) * buf[b1, b2,..bt, 0] + point * buf[b1, b2,..bt, 1] in parallel
            poly.par_iter_mut()
                .chunks(2)
                .with_min_len(64)
                .for_each(|mut buf| *buf[0] = *buf[0] + (*buf[1] - *buf[0]) * point);

            // sequentially update buf[b1, b2,..bt] = buf[b1, b2,..bt, 0]
            for index in 0..1 << (max_log2_size - 1) {
                poly[index] = poly[index << 1];
            }
        }
        poly.truncate(1 << (nv - partial_point.len()));
        self.num_vars = nv - partial_point.len();
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point` from high position
    pub fn fix_high_variables(&self, partial_point: &[F]) -> DenseMultilinearExtension<F> {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut poly = Cow::Borrowed(self);
        let current_eval_size = poly.evaluations.len();
        // `Cow` type here to skip first evaluation vector copy
        for point in partial_point.iter().rev() {
            match &mut poly {
                poly @ Cow::Borrowed(_) => {
                    let half_size = current_eval_size >> 1;
                    *poly = Cow::Owned(DenseMultilinearExtension::from_evaluations_vec(
                        self.num_vars - 1,
                        {
                            let (lo, hi) = self.evaluations.split_at(half_size);
                            lo.par_iter()
                                .zip(hi)
                                .with_min_len(64)
                                .map(|(lo, hi)| *lo + (*hi - *lo) * point)
                                .collect()
                        },
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
    pub fn fix_high_variables_in_place(&mut self, partial_point: &[F]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let nv = self.num_vars;
        let mut current_eval_size = self.evaluations.len();
        for point in partial_point.iter().rev() {
            let half_size = current_eval_size >> 1;
            let (lo, hi) = self.evaluations.split_at_mut(half_size);
            lo.par_iter_mut()
                .zip(hi)
                .with_min_len(64)
                .for_each(|(lo, hi)| *lo += (*hi - *lo) * point);
            current_eval_size = half_size;
        }
        self.evaluations.truncate(current_eval_size);
        self.num_vars = nv - partial_point.len()
    }

    /// Generate a random evaluation of a multilinear poly
    pub fn random(nv: usize, mut rng: &mut impl RngCore) -> Self {
        let eval = (0..1 << nv).map(|_| F::random(&mut rng)).collect();
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
    ) -> (Vec<ArcDenseMultilinearExtension<F>>, F) {
        let start = start_timer!(|| "sample random mle list");
        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        let mut sum = F::ZERO;

        for _ in 0..(1 << nv) {
            let mut product = F::ONE;

            for e in multiplicands.iter_mut() {
                let val = F::sample_base(&mut rng);
                e.push(val);
                product *= val;
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
    ) -> Vec<ArcDenseMultilinearExtension<F>> {
        let start = start_timer!(|| "sample random zero mle list");

        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        for _ in 0..(1 << nv) {
            multiplicands[0].push(F::ZERO);
            for e in multiplicands.iter_mut().skip(1) {
                e.push(F::random(&mut rng));
            }
        }

        let list = multiplicands
            .into_iter()
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x).into())
            .collect();

        end_timer!(start);
        list
    }

    pub fn to_ext_field<Ext: SmallField<BaseField = F>>(&self) -> DenseMultilinearExtension<Ext> {
        DenseMultilinearExtension {
            evaluations: self.evaluations.iter().map(|f| Ext::from_base(f)).collect(),
            num_vars: self.num_vars,
        }
    }
}
