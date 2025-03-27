use p3::{challenger::FieldChallenger, field::PrimeField};

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
    type P: Clone;
    type S: Clone + Sync;
    type C: Clone + Sync;
    type T: FieldChallenger<Self> + Clone;
    fn get_default_challenger() -> Self::T;
    fn get_default_perm() -> Self::P;
    fn get_default_sponge() -> Self::S;
    fn get_default_compression() -> Self::C;
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
