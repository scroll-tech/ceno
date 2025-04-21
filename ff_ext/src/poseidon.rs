use p3::{self, challenger::FieldChallenger, commit::Mmcs, field::PrimeField};

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
    // permutation
    type P: Clone;
    // sponge
    type S: Clone + Sync;
    // compression
    type C: Clone + Sync;
    type MMCS: Mmcs<Self> + Clone + Sync;
    type T: FieldChallenger<Self> + Clone;
    fn get_default_challenger() -> Self::T;
    fn get_default_perm() -> Self::P;
    fn get_default_sponge() -> Self::S;
    fn get_default_compression() -> Self::C;
    fn get_default_mmcs() -> Self::MMCS;
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

#[cfg(debug_assertions)]
pub mod impl_instruments {
    use std::sync::{Arc, Mutex};

    use once_cell::sync::Lazy;
    use p3::symmetric::Permutation;

    pub type PermCount = Arc<Mutex<usize>>;
    static PERM_COUNT: Lazy<PermCount> = Lazy::new(|| Arc::new(Mutex::new(0)));

    #[derive(Clone, Debug)]
    pub struct Instrumented<P> {
        pub inner_perm: P,
        pub perm_count: PermCount,
    }

    impl<P> Instrumented<P> {
        pub fn new(inner_perm: P) -> Self {
            Self {
                inner_perm,
                perm_count: PERM_COUNT.clone(),
            }
        }

        pub fn clear_metrics() {
            if let Ok(mut count) = PERM_COUNT.lock() {
                *count = 0;
            } else {
                unreachable!("Failed to acquire lock on INPUT_LENS_BY_TYPE");
            }
        }

        pub fn format_metrics() -> String {
            format!("perm_count: {}", PERM_COUNT.lock().unwrap())
        }

        fn bump_perm_count(&self) {
            let mut count = self.perm_count.lock().unwrap();
            *count += 1;
        }
    }

    impl<T: Clone, P: Permutation<T>> Permutation<T> for Instrumented<P> {
        fn permute_mut(&self, input: &mut T) {
            self.bump_perm_count();
            self.inner_perm.permute_mut(input);
        }
        fn permute(&self, input: T) -> T {
            self.bump_perm_count();
            self.inner_perm.permute(input)
        }
    }
}
