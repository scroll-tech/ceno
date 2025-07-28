use std::{
    array,
    iter::Sum,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign},
    sync::Arc,
};

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::MultilinearExtension,
    op_mle,
    util::{ceil_log2, max_usable_threads},
    virtual_poly::VirtualPolynomial,
    virtual_polys::PolyMeta,
};
use p3::field::Field;
use transcript::Transcript;

use crate::{extrapolate::ExtrapolationCache, structs::IOPProverState};

/// extrapolates values of a univariate polynomial in-place using precomputed barycentric weights.
///
/// this function fills in the remaining entries of `uni_variate[start..]` assuming the first `start`
/// values are evaluations of a univariate polynomial at `0, 1, ..., start - 1`.
/// it uses a precomputed [`ExtrapolationTable`] from [`ExtrapolationCache`] to perform
/// efficient barycentric extrapolation without requiring any inverse operations at runtime.
///
/// Note: this function is highly optimized without field inverse. see [`ExtrapolationTable`] for how to achieve it
pub fn extrapolate_from_table<E: ExtensionField>(uni_variate: &mut [E], start: usize) {
    let cur_degree = start - 1;
    let table = ExtrapolationCache::<E>::get(cur_degree, uni_variate.len() - 1);
    let target_len = uni_variate.len();
    assert!(start > 0, "start must be > 0 to define a degree");
    assert!(
        target_len > start,
        "no extrapolation needed if target_len <= start"
    );

    let (known, to_extrapolate) = uni_variate.split_at_mut(start);
    let weight_sets = &table.weights[0]; // since min_degree == cur_degree

    for (offset, target) in to_extrapolate.iter_mut().enumerate() {
        let weights = &weight_sets[offset];
        assert_eq!(weights.len(), known.len());

        let acc = weights
            .iter()
            .zip(known.iter())
            .fold(E::ZERO, |acc, (w, x)| acc + (*w * *x));

        *target = acc;
    }
}

fn extrapolate_uni_poly_deg_1<F: Field>(p_i: &[F; 2], eval_at: F) -> F {
    let x0 = F::ZERO;
    let x1 = F::ONE;

    // w0 = 1 / (0−1) = -1
    // w1 = 1 / (1−0) =  1
    let w0 = -F::ONE;
    let w1 = F::ONE;

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;

    let l = d0 * d1;
    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;

    l * (t0 + t1)
}

fn extrapolate_uni_poly_deg_2<F: Field>(p_i: &[F; 3], eval_at: F) -> F {
    let x0 = F::from_canonical_u64(0);
    let x1 = F::from_canonical_u64(1);
    let x2 = F::from_canonical_u64(2);

    // w0 = 1 / ((0−1)(0−2)) =  1/2
    // w1 = 1 / ((1−0)(1−2)) = -1
    // w2 = 1 / ((2−0)(2−1)) =  1/2
    let w0 = F::from_canonical_u64(1).div(F::from_canonical_u64(2));
    let w1 = -F::ONE;
    let w2 = F::from_canonical_u64(1).div(F::from_canonical_u64(2));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;

    let l = d0 * d1 * d2;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();
    let inv_d2 = d2.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;
    let t2 = w2 * p_i[2] * inv_d2;

    l * (t0 + t1 + t2)
}

fn extrapolate_uni_poly_deg_3<F: Field>(p_i: &[F; 4], eval_at: F) -> F {
    let x0 = F::from_canonical_u64(0);
    let x1 = F::from_canonical_u64(1);
    let x2 = F::from_canonical_u64(2);
    let x3 = F::from_canonical_u64(3);

    // w0 = 1 / ((0−1)(0−2)(0−3)) = -1/6
    // w1 = 1 / ((1−0)(1−2)(1−3)) =  1/2
    // w2 = 1 / ((2−0)(2−1)(2−3)) = -1/2
    // w3 = 1 / ((3−0)(3−1)(3−2)) =  1/6
    let w0 = -F::from_canonical_u64(1).div(F::from_canonical_u64(6));
    let w1 = F::from_canonical_u64(1).div(F::from_canonical_u64(2));
    let w2 = -F::from_canonical_u64(1).div(F::from_canonical_u64(2));
    let w3 = F::from_canonical_u64(1).div(F::from_canonical_u64(6));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;
    let d3 = eval_at - x3;

    let l = d0 * d1 * d2 * d3;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();
    let inv_d2 = d2.inverse();
    let inv_d3 = d3.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;
    let t2 = w2 * p_i[2] * inv_d2;
    let t3 = w3 * p_i[3] * inv_d3;

    l * (t0 + t1 + t2 + t3)
}

fn extrapolate_uni_poly_deg_4<F: Field>(p_i: &[F; 5], eval_at: F) -> F {
    let x0 = F::from_canonical_u64(0);
    let x1 = F::from_canonical_u64(1);
    let x2 = F::from_canonical_u64(2);
    let x3 = F::from_canonical_u64(3);
    let x4 = F::from_canonical_u64(4);

    // w0 = 1 / ((0−1)(0−2)(0−3)(0−4)) =  1/24
    // w1 = 1 / ((1−0)(1−2)(1−3)(1−4)) = -1/6
    // w2 = 1 / ((2−0)(2−1)(2−3)(2−4)) =  1/4
    // w3 = 1 / ((3−0)(3−1)(3−2)(3−4)) = -1/6
    // w4 = 1 / ((4−0)(4−1)(4−2)(4−3)) =  1/24
    let w0 = F::from_canonical_u64(1).div(F::from_canonical_u64(24));
    let w1 = -F::from_canonical_u64(1).div(F::from_canonical_u64(6));
    let w2 = F::from_canonical_u64(1).div(F::from_canonical_u64(4));
    let w3 = -F::from_canonical_u64(1).div(F::from_canonical_u64(6));
    let w4 = F::from_canonical_u64(1).div(F::from_canonical_u64(24));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;
    let d3 = eval_at - x3;
    let d4 = eval_at - x4;

    let l = d0 * d1 * d2 * d3 * d4;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();
    let inv_d2 = d2.inverse();
    let inv_d3 = d3.inverse();
    let inv_d4 = d4.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;
    let t2 = w2 * p_i[2] * inv_d2;
    let t3 = w3 * p_i[3] * inv_d3;
    let t4 = w4 * p_i[4] * inv_d4;

    l * (t0 + t1 + t2 + t3 + t4)
}

/// Evaluate a univariate polynomial defined by its values `p_i` at integer points `0..p_i.len()-1`
/// using Barycentric interpolation at the given `eval_at` point.
///
/// For overall idea, refer to https://people.maths.ox.ac.uk/trefethen/barycentric.pdf formula 3.3
/// barycentric weights `w` are for polynomial interpolation.
/// for a fixed set of interpolation points {x_0, x_1, ..., x_n}, the barycentric weight w_j is defined as:
/// w_j = 1 / ∏_{k ≠ j} (x_j - x_k)
/// these weights are used in the barycentric form of Lagrange interpolation, which allows
/// for efficient evaluation of the interpolating polynomial at any other point
/// the weights depend only on the interpolation nodes and can be treat as `constant` in loop-unroll + inline version
///
/// This is a runtime-dispatched implementation optimized for small degrees
/// with unrolled loops for performance
///
/// # Arguments
/// * `p_i` - Values of the polynomial at consecutive integer points.
/// * `eval_at` - The point at which to evaluate the interpolated polynomial.
///
/// # Returns
/// The value of the polynomial `eval_at`.
pub fn extrapolate_uni_poly<F: Field>(p: &[F], eval_at: F) -> F {
    match p.len() {
        2 => extrapolate_uni_poly_deg_1(p.try_into().unwrap(), eval_at),
        3 => extrapolate_uni_poly_deg_2(p.try_into().unwrap(), eval_at),
        4 => extrapolate_uni_poly_deg_3(p.try_into().unwrap(), eval_at),
        5 => extrapolate_uni_poly_deg_4(p.try_into().unwrap(), eval_at),
        _ => unimplemented!("Extrapolation for degree {} not implemented", p.len() - 1),
    }
}

/// merge vector of virtual poly into single virtual poly
/// NOTE this function assume polynomial in each virtual_polys are "small", due to this function need quite of clone
pub fn merge_sumcheck_polys<'a, E: ExtensionField>(
    virtual_polys: Vec<&VirtualPolynomial<'a, E>>,
    poly_meta: Option<Vec<PolyMeta>>,
) -> VirtualPolynomial<'a, E> {
    assert!(!virtual_polys.is_empty());
    assert!(virtual_polys.len().is_power_of_two());
    let log2_poly_len = ceil_log2(virtual_polys.len());
    let poly_meta = poly_meta
        .unwrap_or(std::iter::repeat_n(PolyMeta::Normal, virtual_polys.len()).collect_vec());
    let mut final_poly = virtual_polys[0].clone();
    final_poly.aux_info.max_num_variables = 0;

    // usually phase1 lefted num_var is 0, thus only constant term lefted
    // but we also support phase1 stop earlier, so each poly still got num_var > 0
    // assuming sumcheck implemented in suffix alignment to batch different num_vars

    // sanity check: all PolyMeta::Normal should have the same phase1_lefted_numvar
    debug_assert!(
        virtual_polys[0]
            .flattened_ml_extensions
            .iter()
            .zip_eq(&poly_meta)
            .filter(|(_, poly_meta)| { matches!(poly_meta, PolyMeta::Normal) })
            .map(|(poly, _)| poly.num_vars())
            .all_equal()
    );
    let merged_num_vars = poly_meta
        .iter()
        .enumerate()
        .find_map(|(index, poly_meta)| {
            if matches!(poly_meta, PolyMeta::Normal) {
                let phase1_lefted_numvar =
                    virtual_polys[0].flattened_ml_extensions[index].num_vars();
                Some(phase1_lefted_numvar + log2_poly_len)
            } else {
                None
            }
        })
        .or_else(|| {
            // all poly are phase2 only, find which the max num_var
            virtual_polys[0]
                .flattened_ml_extensions
                .iter()
                .map(|poly| poly.num_vars())
                .max()
        })
        .expect("unreachable");

    for (i, poly_meta) in (0..virtual_polys[0].flattened_ml_extensions.len()).zip_eq(&poly_meta) {
        final_poly.aux_info.max_num_variables =
            final_poly.aux_info.max_num_variables.max(merged_num_vars);
        let ml_ext = match poly_meta {
            PolyMeta::Normal => MultilinearExtension::from_evaluations_ext_vec(
                merged_num_vars,
                virtual_polys
                    .iter()
                    .flat_map(|virtual_poly| {
                        let mle = &virtual_poly.flattened_ml_extensions[i];
                        op_mle!(mle, |f| f.to_vec(), |_v| unreachable!())
                    })
                    .collect::<Vec<E>>(),
            ),
            PolyMeta::Phase2Only => {
                let poly = &virtual_polys[0].flattened_ml_extensions[i];
                assert!(poly.num_vars() <= log2_poly_len);
                let blowup_factor = 1 << (merged_num_vars - poly.num_vars());
                MultilinearExtension::from_evaluations_ext_vec(
                    merged_num_vars,
                    op_mle!(
                        poly,
                        |poly| {
                            poly.iter()
                                .flat_map(|e| std::iter::repeat_n(*e, blowup_factor))
                                .collect_vec()
                        },
                        |base_poly| base_poly.iter().map(|e| E::from(*e)).collect_vec()
                    ),
                )
            }
        };
        final_poly.flattened_ml_extensions[i] = Arc::new(ml_ext);
    }
    final_poly
}

/// retrieve virtual poly from sumcheck prover state to single virtual poly
pub fn merge_sumcheck_prover_state<'a, E: ExtensionField>(
    prover_states: &[IOPProverState<'a, E>],
) -> VirtualPolynomial<'a, E> {
    merge_sumcheck_polys(
        prover_states.iter().map(|ps| &ps.poly).collect_vec(),
        Some(prover_states[0].poly_meta.clone()),
    )
}

/// we expect each thread at least take 4 num of sumcheck variables
/// return optimal num threads to run sumcheck
pub fn optimal_sumcheck_threads(num_vars: usize) -> usize {
    let expected_max_threads = max_usable_threads();
    let min_numvar_per_thread = 4;
    if num_vars <= min_numvar_per_thread {
        1
    } else {
        (1 << (num_vars - min_numvar_per_thread)).min(expected_max_threads)
    }
}

/// Derive challenge from transcript and return all power results of the challenge.
pub fn get_challenge_pows<E: ExtensionField>(
    size: usize,
    transcript: &mut impl Transcript<E>,
) -> Vec<E> {
    let alpha = transcript
        .sample_and_append_challenge(b"combine subset evals")
        .elements;

    std::iter::successors(Some(E::ONE), move |prev| Some(*prev * alpha))
        .take(size)
        .collect()
}

#[derive(Clone, Copy, Debug)]
/// util collection to support fundamental operation
pub struct AdditiveArray<F, const N: usize>(pub [F; N]);

impl<F: Default, const N: usize> Default for AdditiveArray<F, N> {
    fn default() -> Self {
        Self(array::from_fn(|_| F::default()))
    }
}

impl<F: AddAssign, const N: usize> AddAssign for AdditiveArray<F, N> {
    fn add_assign(&mut self, rhs: Self) {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(acc, item)| *acc += item);
    }
}

impl<F: AddAssign, const N: usize> Add for AdditiveArray<F, N> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F: AddAssign + Default, const N: usize> Sum for AdditiveArray<F, N> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + item).unwrap_or_default()
    }
}

impl<F, const N: usize> Deref for AdditiveArray<F, N> {
    type Target = [F; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F, const N: usize> DerefMut for AdditiveArray<F, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug)]
pub struct AdditiveVec<F>(pub Vec<F>);

impl<F> Deref for AdditiveVec<F> {
    type Target = Vec<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> DerefMut for AdditiveVec<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: Clone + Default> AdditiveVec<F> {
    pub fn new(len: usize) -> Self {
        Self(vec![F::default(); len])
    }
}

impl<F: AddAssign> AddAssign for AdditiveVec<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(acc, item)| *acc += item);
    }
}

impl<F: AddAssign> Add for AdditiveVec<F> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F: MulAssign + Copy> MulAssign<F> for AdditiveVec<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.0.iter_mut().for_each(|lhs| *lhs *= rhs);
    }
}

impl<F: MulAssign + Copy> Mul<F> for AdditiveVec<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        self *= rhs;
        self
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ff_ext::GoldilocksExt2;
    use p3::field::FieldAlgebra;

    #[test]
    fn test_extrapolate_from_table() {
        type E = GoldilocksExt2;
        fn f(x: u64) -> E {
            E::from_canonical_u64(2u64) * E::from_canonical_u64(x) + E::from_canonical_u64(3u64)
        }
        // Test a known linear polynomial: f(x) = 2x + 3

        let degree = 1;
        let target_len = 5; // Extrapolate up to x=4

        // Known values at x=0 and x=1
        let mut values: Vec<E> = (0..=degree as u64).map(f).collect();

        // Allocate extra space for extrapolated values
        values.resize(target_len, E::ZERO);

        // Run extrapolation
        extrapolate_from_table(&mut values, degree + 1);

        // Verify values against f(x)
        for (x, val) in values.iter().enumerate() {
            let expected = f(x as u64);
            assert_eq!(*val, expected, "Mismatch at x={}", x);
        }
    }
}
