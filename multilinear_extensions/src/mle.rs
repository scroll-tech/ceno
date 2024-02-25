use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use ark_std::{end_timer, rand::RngCore, start_timer};
use goldilocks::SmallField;
use rayon::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// pub type DenseMultilinearExtensionRef<F> = Arc<Mutex<DenseMultilinearExtension<F>>>;

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, Default, Debug)]
pub struct DenseMultilinearExtension<F> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: Arc<Mutex<Vec<F>>>,
    /// Number of variables
    pub num_vars: usize,
}

impl<F: SmallField> Serialize for DenseMultilinearExtension<F> {
    fn serialize<S>(&self, _: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de, F: SmallField> Deserialize<'de> for DenseMultilinearExtension<F> {
    fn deserialize<D>(_: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

impl<F: PartialEq> PartialEq for DenseMultilinearExtension<F> {
    fn eq(&self, rhs: &DenseMultilinearExtension<F>) -> bool {
        self.num_vars == rhs.num_vars
            && self.evaluations.lock().unwrap().deref() == rhs.evaluations.lock().unwrap().deref()
    }
}

impl<F: SmallField> DenseMultilinearExtension<F> {
    /// Deep clone a DenseMultilinearExtension. Note that the normal `clone` only clones a reference to the memory.
    pub fn deep_clone(&self) -> Self {
        Self {
            evaluations: Arc::new(Mutex::new(self.evaluation_vec())),
            num_vars: self.num_vars,
        }
    }

    /// Deep clone the evaluation table
    pub fn evaluation_vec(&self) -> Vec<F> {
        self.evaluations.lock().unwrap().clone()
    }

    /// Evaluation length
    pub fn evaluation_length(&self) -> usize {
        self.evaluations.lock().unwrap().len()
    }

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
            evaluations: Arc::new(Mutex::new(evaluations)),
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

        let mut evals = self.evaluation_vec();
        let mut num_vars = self.num_vars;
        fix_low_variables_in_place(&mut evals, &mut num_vars, point);
        evals[0]
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    /// Starts from low variables by default.
    pub fn fix_variables(&self, partial_point: &[F]) -> DenseMultilinearExtension<F> {
        self.fix_low_variables(partial_point)
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_low_variables(&self, partial_point: &[F]) -> DenseMultilinearExtension<F> {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut nv = self.num_vars;
        let mut poly = self.evaluation_vec();

        // evaluate single variable of partial point from left to right
        fix_low_variables_in_place(&mut poly, &mut nv, partial_point);
        Self::from_evaluations_vec(nv, poly)
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        // evaluate single variable of partial point from left to right
        for point in partial_point {
            self.fix_one_variable_in_place_helper(point);
        }
    }

    /// Helper function. Fix 1 variable.
    fn fix_one_variable_in_place_helper(&mut self, point: &F) {
        let new_length = 1 << (self.num_vars - 1);
        let mut slice = self.evaluations.lock().unwrap();

        slice
            .par_chunks_mut(2)
            .with_min_len(64)
            .for_each(|data| data[0] = *point * (data[1] - data[0]) + data[0]);

        for i in 1..new_length {
            slice[i] = slice[i * 2]
        }

        slice.resize(new_length, F::default());
        self.num_vars -= 1;
    }

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    pub fn fix_high_variables(&self, partial_point: &[F]) -> DenseMultilinearExtension<F> {
        // TODO: return error.
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut nv = self.num_vars;
        let mut poly = self.evaluation_vec();
        // evaluate single variable of partial point from left to right
        fix_high_variables_in_place(&mut poly, &mut nv, partial_point);

        Self::from_evaluations_vec(nv, poly)
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
    ) -> (Vec<DenseMultilinearExtension<F>>, F) {
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
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x))
            .collect();

        end_timer!(start);
        (list, sum)
    }

    // Build a randomize list of mle-s whose sum is zero.
    pub fn random_zero_mle_list(
        nv: usize,
        degree: usize,
        mut rng: impl RngCore,
    ) -> Vec<DenseMultilinearExtension<F>> {
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
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x))
            .collect();

        end_timer!(start);
        list
    }

    pub fn to_ext_field<Ext: SmallField<BaseField = F>>(&self) -> DenseMultilinearExtension<Ext> {
        DenseMultilinearExtension::<Ext>::from_evaluations_vec(
            self.num_vars,
            self.evaluation_vec()
                .iter()
                .map(|f| Ext::from_base(f))
                .collect(),
        )
    }
}

pub fn fix_low_variables_in_place<F: SmallField>(
    slice: &mut Vec<F>,
    num_vars: &mut usize,
    partial_point: &[F],
) {
    // TODO: return error.
    assert!(
        partial_point.len() <= *num_vars,
        "invalid size of partial point"
    );
    // evaluate single variable of partial point from left to right
    for point in partial_point {
        fix_one_low_variable_in_place_helper(slice, num_vars, point);
    }
}

/// Helper function. Fix 1 variable.
fn fix_one_low_variable_in_place_helper<F: SmallField>(
    slice: &mut Vec<F>,
    num_vars: &mut usize,
    point: &F,
) {
    let new_length = 1 << (*num_vars - 1);
    slice
        .par_chunks_mut(2)
        .with_min_len(64)
        .for_each(|data| data[0] = *point * (data[1] - data[0]) + data[0]);

    for i in 1..new_length {
        slice[i] = slice[i * 2]
    }

    slice.resize(new_length, F::default());
    *num_vars -= 1;
}

pub fn fix_high_variables_in_place<F: SmallField>(
    slice: &mut Vec<F>,
    num_vars: &mut usize,
    partial_point: &[F],
) {
    // TODO: return error.
    assert!(
        partial_point.len() <= *num_vars,
        "invalid size of partial point"
    );
    // evaluate single variable of partial point from left to right
    for point in partial_point.iter().rev() {
        fix_one_high_variable_in_place_helper(slice, num_vars, point);
    }
}

/// Helper function. Fix 1 variable.
fn fix_one_high_variable_in_place_helper<F: SmallField>(
    slice: &mut Vec<F>,
    num_vars: &mut usize,
    point: &F,
) {
    let new_length = 1 << (*num_vars - 1);
    let buf = slice.split_off(new_length);

    slice
        .par_iter_mut()
        .zip_eq(buf.par_iter())
        .for_each(|(a, b)| *a = *point * (*b - *a) + *a);

    *num_vars -= 1;
}
