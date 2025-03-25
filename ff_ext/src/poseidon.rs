use p3::{challenger::FieldChallenger, field::PrimeField, symmetric::CryptographicPermutation};

use crate::{ExtensionField, SmallField};

pub trait FieldChallengerExt<F: PoseidonField>: FieldChallenger<F> {
    fn observe_ext_slice<E: ExtensionField<BaseField = F>>(&mut self, exts: &[E]) {
        exts.iter()
            .for_each(|ext| self.observe_slice(ext.as_basis_coefficients_slice()));
    }

    fn sample_ext_vec<E: ExtensionField<BaseField = F>>(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.sample_algebra_element()).collect()
    }
}

pub trait PoseidonField: PrimeField + SmallField {
    const PERM_WIDTH: usize;
    const RATE: usize;
    type P: Clone;
    type T: FieldChallenger<Self> + Clone;
    fn get_perm() -> Self::T;
}

pub(crate) fn new_array<const N: usize, F: PrimeField>(input: [u64; N]) -> [F; N] {
    let mut output = [F::ZERO; N];
    let mut i = 0;
    while i < N {
        output[i] = F::from_u64(input[i]);
        i += 1;
    }
    output
}
