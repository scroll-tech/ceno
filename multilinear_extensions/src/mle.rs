use std::sync::Arc;

use ark_std::{end_timer, rand::RngCore, start_timer};
use goldilocks::SmallField;
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

        // TODO evaluate without clone?
        let mut to_bind_poly = self.clone();
        to_bind_poly.fix_variables(point);
        assert!(to_bind_poly.evaluations.len() == 1);
        to_bind_poly.evaluations[0]
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_variables(&mut self, partial_point: &[F]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let nv = self.num_vars;
        let poly = &mut self.evaluations;
        // evaluate single variable of partial point from left to right
        for (i, point) in partial_point.iter().enumerate() {
            Self::fix_one_variable_helper(poly, nv - i, point);
        }
        let dim = partial_point.len();
        poly.resize(1 << (nv - dim), F::ZERO);
        self.num_vars = nv - dim;
    }

    /// Helper function. Fix 1 variable.
    fn fix_one_variable_helper(data: &mut Vec<F>, max_log2_size: usize, point: &F) {
        // override buf[b1, b2,..bt, 0] = (1-point) * buf[b1, b2,..bt, 0] + point * buf[b1, b2,..bt, 1] in parallel
        data.par_iter_mut()
            .chunks(2)
            .with_min_len(64)
            .for_each(|mut buf| *buf[0] = *buf[0] + (*buf[1] - *buf[0]) * point);

        // sequentially update buf[b1, b2,..bt] = buf[b1, b2,..bt, 0]
        for index in 0..1 << (max_log2_size - 1) {
            data[index] = data[index << 1];
        }
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
