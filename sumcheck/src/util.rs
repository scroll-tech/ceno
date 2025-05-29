use std::{
    array,
    cmp::max,
    iter::Sum,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign},
    sync::Arc,
};

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::MultilinearExtension, op_mle, util::max_usable_threads, virtual_poly::VirtualPolynomial,
    virtual_polys::PolyMeta,
};
use p3::field::Field;
use rayon::{prelude::ParallelIterator, slice::ParallelSliceMut};

use crate::structs::IOPProverState;

pub fn barycentric_weights<F: Field>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter(|&(i, _)| (i != j))
                .map(|(_, point_i)| *point_j - *point_i)
                .reduce(|acc, value| acc * value)
                .unwrap_or(F::ONE)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

// Computes the inverse of each field element in a vector {v_i} using a parallelized batch inversion.
pub fn batch_inversion<F: Field>(v: &mut [F]) {
    batch_inversion_and_mul(v, &F::ONE);
}

// Computes the inverse of each field element in a vector {v_i} sequentially (serial version).
pub fn serial_batch_inversion<F: Field>(v: &mut [F]) {
    serial_batch_inversion_and_mul(v, &F::ONE)
}

// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}
pub fn batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    // Divide the vector v evenly between all available cores
    let min_elements_per_thread = 1;
    let num_cpus_available = rayon::current_num_threads();
    let num_elems = v.len();
    let num_elem_per_thread = max(num_elems / num_cpus_available, min_elements_per_thread);

    // Batch invert in parallel, without copying the vector
    v.par_chunks_mut(num_elem_per_thread).for_each(|chunk| {
        serial_batch_inversion_and_mul(chunk, coeff);
    });
}

/// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}.
/// This method is explicitly single-threaded.
fn serial_batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2
    // but with an optimization to multiply every element in the returned vector by
    // coeff

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = F::ONE;
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp.mul_assign(*f);
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.try_inverse().unwrap(); // Guaranteed to be nonzero.

    // Multiply product by coeff, so all inverses will be scaled by coeff
    tmp *= *coeff;

    // Second pass: iterate backwards to compute inverses
    for (f, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|f| !f.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(F::ONE)))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}

pub(crate) fn extrapolate<F: Field>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    inner_extrapolate::<F, true>(points, weights, evals, at)
}

pub(crate) fn serial_extrapolate<F: Field>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    inner_extrapolate::<F, false>(points, weights, evals, at)
}

fn inner_extrapolate<F: Field, const IS_PARALLEL: bool>(
    points: &[F],
    weights: &[F],
    evals: &[F],
    at: &F,
) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *at - *point).collect::<Vec<_>>();
        if IS_PARALLEL {
            batch_inversion(&mut coeffs);
        } else {
            serial_batch_inversion(&mut coeffs);
        }
        let mut sum = F::ZERO;
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= *weight;
            sum += *coeff
        });
        let sum_inv = sum.try_inverse().unwrap_or(F::ZERO);
        (coeffs, sum_inv)
    };
    coeffs
        .iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * *eval)
        .sum::<F>()
        * sum_inv
}

/// this implementation uses exactly 3 field inversions, which is optimal for barycentric
///   evaluation at degree 1:
///   - Two inverses for the distances `d0 = x - x0`, `d1 = x - x1`
///   - One inverse for the final normalization term
///
/// barycentric weights `w` are for polynomial interpolation.
/// for a fixed set of interpolation points {x_0, x_1, ..., x_n}, the barycentric weight w_j is defined as:
/// w_j = 1 / ∏_{k ≠ j} (x_j - x_k)
/// these weights are used in the barycentric form of Lagrange interpolation, which allows
/// for efficient evaluation of the interpolating polynomial at any other point
/// The weights depend only on the interpolation nodes and can be precomputed once
fn extrapolate_uni_poly_deg_1<F: Field>(p_i: &[F; 2], eval_at: F) -> F {
    let x0 = F::ZERO;
    let x1 = F::ONE;

    // w0 = 1 / (0−1) = -1
    // w1 = 1 / (1−0) =  1
    let w0 = -F::ONE;
    let w1 = F::ONE;

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;

    let b0 = w0 * inv_d0;
    let b1 = w1 * inv_d1;

    (t0 + t1) * (b0 + b1).inverse()
}

fn extrapolate_uni_poly_deg_2<F: Field>(p_i: &[F; 3], eval_at: F) -> F {
    let x0 = F::from_u64(0);
    let x1 = F::from_u64(1);
    let x2 = F::from_u64(2);

    // w0 = 1 / ((0−1)(0−2)) =  1/2
    // w1 = 1 / ((1−0)(1−2)) = -1
    // w2 = 1 / ((2−0)(2−1)) =  1/2
    let w0 = F::from_u64(1).div(F::from_u64(2));
    let w1 = -F::ONE;
    let w2 = F::from_u64(1).div(F::from_u64(2));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();
    let inv_d2 = d2.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;
    let t2 = w2 * p_i[2] * inv_d2;

    let b0 = w0 * inv_d0;
    let b1 = w1 * inv_d1;
    let b2 = w2 * inv_d2;

    (t0 + t1 + t2) * (b0 + b1 + b2).inverse()
}

fn extrapolate_uni_poly_deg_3<F: Field>(p_i: &[F; 4], eval_at: F) -> F {
    let x0 = F::from_u64(0);
    let x1 = F::from_u64(1);
    let x2 = F::from_u64(2);
    let x3 = F::from_u64(3);

    // w0 = 1 / ((0−1)(0−2)(0−3)) = -1/6
    // w1 = 1 / ((1−0)(1−2)(1−3)) =  1/2
    // w2 = 1 / ((2−0)(2−1)(2−3)) = -1/2
    // w3 = 1 / ((3−0)(3−1)(3−2)) =  1/6
    let w0 = -F::from_u64(1).div(F::from_u64(6));
    let w1 = F::from_u64(1).div(F::from_u64(2));
    let w2 = -F::from_u64(1).div(F::from_u64(2));
    let w3 = F::from_u64(1).div(F::from_u64(6));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;
    let d3 = eval_at - x3;

    let inv_d0 = d0.inverse();
    let inv_d1 = d1.inverse();
    let inv_d2 = d2.inverse();
    let inv_d3 = d3.inverse();

    let t0 = w0 * p_i[0] * inv_d0;
    let t1 = w1 * p_i[1] * inv_d1;
    let t2 = w2 * p_i[2] * inv_d2;
    let t3 = w3 * p_i[3] * inv_d3;

    let b0 = w0 * inv_d0;
    let b1 = w1 * inv_d1;
    let b2 = w2 * inv_d2;
    let b3 = w3 * inv_d3;

    (t0 + t1 + t2 + t3) * (b0 + b1 + b2 + b3).inverse()
}

fn extrapolate_uni_poly_deg_4<F: Field>(p_i: &[F; 5], eval_at: F) -> F {
    let x0 = F::from_u64(0);
    let x1 = F::from_u64(1);
    let x2 = F::from_u64(2);
    let x3 = F::from_u64(3);
    let x4 = F::from_u64(4);

    // w0 = 1 / ((0−1)(0−2)(0−3)(0−4)) =  1/24
    // w1 = 1 / ((1−0)(1−2)(1−3)(1−4)) = -1/6
    // w2 = 1 / ((2−0)(2−1)(2−3)(2−4)) =  1/4
    // w3 = 1 / ((3−0)(3−1)(3−2)(3−4)) = -1/6
    // w4 = 1 / ((4−0)(4−1)(4−2)(4−3)) =  1/24
    let w0 = F::from_u64(1).div(F::from_u64(24));
    let w1 = -F::from_u64(1).div(F::from_u64(6));
    let w2 = F::from_u64(1).div(F::from_u64(4));
    let w3 = -F::from_u64(1).div(F::from_u64(6));
    let w4 = F::from_u64(1).div(F::from_u64(24));

    let d0 = eval_at - x0;
    let d1 = eval_at - x1;
    let d2 = eval_at - x2;
    let d3 = eval_at - x3;
    let d4 = eval_at - x4;

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

    let b0 = w0 * inv_d0;
    let b1 = w1 * inv_d1;
    let b2 = w2 * inv_d2;
    let b3 = w3 * inv_d3;
    let b4 = w4 * inv_d4;

    (t0 + t1 + t2 + t3 + t4) * (b0 + b1 + b2 + b3 + b4).inverse()
}

/// Evaluate a univariate polynomial defined by its values `p_i` at integer points `0..p_i.len()-1`
/// using Barycentric interpolation at the given `eval_at` point.
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

/// log2 ceil of x
pub fn ceil_log2(x: usize) -> usize {
    assert!(x > 0, "ceil_log2: x must be positive");
    // Calculate the number of bits in usize
    let usize_bits = std::mem::size_of::<usize>() * 8;
    usize_bits - (x - 1).leading_zeros() as usize
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
