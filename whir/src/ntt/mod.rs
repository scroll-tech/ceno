//! NTT and related algorithms.

mod matrix;
mod ntt_impl;
mod transpose;
mod utils;
mod wavelet;

use self::matrix::MatrixMut;

use ff_ext::ExtensionField;
use p3::field::TwoAdicField;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use tracing::instrument;
use witness::{RowMajorMatrix, expand_from_coeff as expand_from_coeff_inner};

pub use self::{
    ntt_impl::{intt, intt_batch, ntt, ntt_batch},
    transpose::{transpose, transpose_bench_allocate, transpose_test},
    wavelet::wavelet_transform,
};

/// RS encode at a rate 1/`expansion`.
#[instrument(name = "expand_from_coeff", level = "trace", skip_all)]
pub fn expand_from_coeff<F: ExtensionField>(coeffs: &[F], expansion: usize) -> Vec<F> {
    let engine = ntt_impl::NttEngine::<F>::new_from_cache();
    let expanded_size = coeffs.len() * expansion;
    let mut result = Vec::with_capacity(expanded_size);
    // Note: We can also zero-extend the coefficients and do a larger NTT.
    // But this is more efficient.

    // Do coset NTT.
    let root = engine.root(expanded_size);
    result.extend_from_slice(coeffs);
    #[cfg(not(feature = "parallel"))]
    for i in 1..expansion {
        let root = root.exp_u64(i as u64);
        let mut offset = F::ONE;
        result.extend(coeffs.iter().map(|x| {
            let val = *x * offset;
            offset *= root;
            val
        }));
    }
    #[cfg(feature = "parallel")]
    result.par_extend((1..expansion).into_par_iter().flat_map(|i| {
        let root_i = root.exp_u64(i as u64);
        coeffs
            .par_iter()
            .enumerate()
            .map_with(F::ZERO, move |root_j, (j, coeff)| {
                if root_j.is_zero() {
                    *root_j = root_i.exp_u64(j as u64);
                } else {
                    *root_j *= root_i;
                }
                *coeff * *root_j
            })
    }));

    ntt_batch(&mut result, coeffs.len());
    transpose(&mut result, expansion, coeffs.len());
    result
}

pub fn expand_from_coeff_rmm<F: TwoAdicField + Ord>(
    coeffs: RowMajorMatrix<F>,
    expansion: usize,
) -> RowMajorMatrix<F> {
    expand_from_coeff_inner(coeffs, expansion)
}
