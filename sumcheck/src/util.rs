use std::{
    array,
    iter::Sum,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign},
    sync::Arc,
};

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    macros::{entered_span, exit_span},
    mle::MultilinearExtension,
    op_mle,
    util::max_usable_threads,
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

/// Interpolate a uni-variate degree-`p_i.len()-1` polynomial and evaluate this
/// polynomial at `eval_at`:
///
///   \sum_{i=0}^len p_i * (\prod_{j!=i} (eval_at - j)/(i-j) )
///
/// This implementation is linear in number of inputs in terms of field
/// operations. It also has a quadratic term in primitive operations which is
/// negligible compared to field operations.
/// TODO: The quadratic term can be removed by precomputing the lagrange
/// coefficients.
pub fn interpolate_uni_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let start = entered_span!("sum check interpolate uni poly opt");

    let len = p_i.len();
    let mut evals = vec![];
    let mut prod = eval_at;
    evals.push(eval_at);

    // `prod = \prod_{j} (eval_at - j)`
    for e in 1..len {
        let tmp = eval_at - F::from_u64(e as u64);
        evals.push(tmp);
        prod *= tmp;
    }
    let mut res = F::ZERO;
    // we want to compute \prod (j!=i) (i-j) for a given i
    //
    // we start from the last step, which is
    //  denom[len-1] = (len-1) * (len-2) *... * 2 * 1
    // the step before that is
    //  denom[len-2] = (len-2) * (len-3) * ... * 2 * 1 * -1
    // and the step before that is
    //  denom[len-3] = (len-3) * (len-4) * ... * 2 * 1 * -1 * -2
    //
    // i.e., for any i, the one before this will be derived from
    //  denom[i-1] = denom[i] * (len-i) / i
    //
    // that is, we only need to store
    // - the last denom for i = len-1, and
    // - the ratio between current step and fhe last step, which is the product of (len-i) / i from
    //   all previous steps and we store this product as a fraction number to reduce field
    //   divisions.

    let mut denom_up = field_factorial::<F>(len - 1);
    let mut denom_down = F::ONE;

    for i in (0..len).rev() {
        res += p_i[i] * prod * denom_down * (denom_up * evals[i]).inverse();

        // compute denom for the next step is current_denom * (len-i)/i
        if i != 0 {
            denom_up *= -F::from_u64((len - i) as u64);
            denom_down *= F::from_u64(i as u64);
        }
    }
    exit_span!(start);
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn field_factorial<F: Field>(a: usize) -> F {
    let mut res = F::ONE;
    for i in 2..=a {
        res *= F::from_u64(i as u64);
    }
    res
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
    use p3::field::PrimeCharacteristicRing;

    #[test]
    fn test_extrapolate_from_table() {
        type E = GoldilocksExt2;
        fn f(x: u64) -> E {
            E::from_u64(2u64) * E::from_u64(x) + E::from_u64(3u64)
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
