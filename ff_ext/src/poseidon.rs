use p3::{
    challenger::{FieldChallenger, GrindingChallenger},
    commit::Mmcs,
    field::PrimeField,
};

use crate::{ExtensionField, SmallField};

pub trait FieldChallengerExt<F: PoseidonField>: FieldChallenger<F> {
    fn observe_ext_slice<E: ExtensionField<BaseField = F>>(&mut self, exts: &[E]) {
        exts.iter()
            .for_each(|ext| self.observe_slice(ext.as_base_slice()));
    }

    fn sample_ext_vec<E: ExtensionField<BaseField = F>>(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.sample_ext_element()).collect()
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
    type T: FieldChallenger<Self> + Clone + GrindingChallenger<Witness = Self>;
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
        output[i] = F::from_canonical_u64(input[i]);
        i += 1;
    }
    output
}

#[cfg(debug_assertions)]
pub mod impl_instruments {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use once_cell::sync::Lazy;
    use p3::symmetric::Permutation;

    pub type PermCount = Arc<Mutex<usize>>;
    pub type LabelCounts = Arc<Mutex<HashMap<&'static str, usize>>>;

    static PERM_COUNT: Lazy<PermCount> = Lazy::new(|| Arc::new(Mutex::new(0)));
    static PERM_LABEL_COUNTS: Lazy<LabelCounts> =
        Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

    #[derive(Clone, Debug)]
    pub struct Instrumented<P> {
        pub inner_perm: P,
        pub perm_count: PermCount,
        pub label_counts: LabelCounts,
    }

    impl<P> Instrumented<P> {
        pub fn new(inner_perm: P) -> Self {
            Self {
                inner_perm,
                perm_count: PERM_COUNT.clone(),
                label_counts: PERM_LABEL_COUNTS.clone(),
            }
        }

        pub fn clear_metrics() {
            if let Ok(mut count) = PERM_COUNT.lock() {
                *count = 0;
            }
            if let Ok(mut map) = PERM_LABEL_COUNTS.lock() {
                map.clear();
            }
        }

        pub fn format_metrics() -> String {
            let count = PERM_COUNT.lock().unwrap();
            let map = PERM_LABEL_COUNTS.lock().unwrap();

            // sort ascending by value
            let mut label_vec: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            label_vec.sort_by_key(|&(_, v)| v);

            let mut lines = Vec::new();

            // start -> first_key
            if let Some((first_key, first_val)) = label_vec.first() {
                let pct = (*first_val as f64) * 100.0 / (*count as f64);
                lines.push(format!("{first_key}: {first_val} ({pct:.2}%)"));
            }

            for pair in label_vec.windows(2) {
                let (_, v1) = pair[0];
                let (k2, v2) = pair[1];
                let diff = v2 - v1;
                let pct = (diff as f64) * 100.0 / (*count as f64);
                lines.push(format!("{k2}: {diff} ({pct:.2}%)"));
            }

            lines.push(format!("overall perm_count: {count}"));

            lines.join("\n")
        }

        fn bump_perm_count(&self) {
            let mut count = self.perm_count.lock().unwrap();
            *count += 1;
        }

        pub fn log_label(label: &'static str) {
            let count = PERM_COUNT.lock().unwrap();
            let mut map = PERM_LABEL_COUNTS.lock().unwrap();
            map.insert(label, *count);
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
