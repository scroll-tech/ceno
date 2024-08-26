// use std::iter::repeat;

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use poseidon::Poseidon;
use std::ptr::hash;

use serde::{Deserialize, Serialize};

pub const DIGEST_WIDTH: usize = super::transcript::OUTPUT_WIDTH;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField + Serialize>(pub [F; DIGEST_WIDTH]);
pub type Hasher<F> = Poseidon<F, 12, 11>;

pub fn new_hasher<F: SmallField>() -> Hasher<F> {
    // FIXME: Change to the right parameter
    Hasher::<F>::new(8, 22)
}

pub fn hash_base_field<E: ExtensionField>(
    value: &E::BaseField,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    hasher.update(&[*value]);
    Digest(hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap())
}

pub fn hash_m_to_1_base_field<E: ExtensionField>(
    values: &[E::BaseField],
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    hasher.update(values);
    Digest(hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap())
}

pub fn hash_m_to_1_ext_field<E: ExtensionField>(
    values: &[E],
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    for val in values {
        hasher.update(val.as_bases());
    }
    Digest(hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap())
}

pub fn hash_ext_field<E: ExtensionField>(
    value: &E,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    hasher.update(value.as_bases());
    Digest(hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap())
}

pub fn hash_two_leaves_ext<E: ExtensionField>(
    a: &E,
    b: &E,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    hasher.update(a.as_bases());
    hasher.update(b.as_bases());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

pub fn hash_two_leaves_base<E: ExtensionField>(
    a: &E::BaseField,
    b: &E::BaseField,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    hasher.update(&[*a]);
    hasher.update(&[*b]);
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

pub fn hash_two_leaves_batch_ext<E: ExtensionField>(
    a: &Vec<E>,
    b: &Vec<E>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut left_hasher = hasher.clone();
    a.iter().for_each(|a| left_hasher.update(a.as_bases()));
    let left = Digest(
        left_hasher.squeeze_vec()[0..DIGEST_WIDTH]
            .try_into()
            .unwrap(),
    );

    let mut right_hasher = hasher.clone();
    b.iter().for_each(|b| right_hasher.update(b.as_bases()));
    let right = Digest(
        right_hasher.squeeze_vec()[0..DIGEST_WIDTH]
            .try_into()
            .unwrap(),
    );

    hash_two_digests(&left, &right, hasher)
}

pub fn hash_two_leaves_batch_base<E: ExtensionField>(
    a: &Vec<E::BaseField>,
    b: &Vec<E::BaseField>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut left_hasher = hasher.clone();
    left_hasher.update(a.as_slice());
    let left = Digest(
        left_hasher.squeeze_vec()[0..DIGEST_WIDTH]
            .try_into()
            .unwrap(),
    );

    let mut right_hasher = hasher.clone();
    right_hasher.update(b.as_slice());
    let right = Digest(
        right_hasher.squeeze_vec()[0..DIGEST_WIDTH]
            .try_into()
            .unwrap(),
    );

    hash_two_digests(&left, &right, hasher)
}

pub fn hash_two_digests<F: SmallField>(
    a: &Digest<F>,
    b: &Digest<F>,
    hasher: &Hasher<F>,
) -> Digest<F> {
    let mut hasher = hasher.clone();
    hasher.update(a.0.as_slice());
    hasher.update(b.0.as_slice());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer, test_rng};
    use bitvec::ptr::hash;
    use ff::Field;
    use goldilocks::Goldilocks;
    use itertools::Itertools;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn benchmark_hashing() {
        let rng = test_rng();
        let timer = start_timer!(|| "Timing hash initialization");
        let mut hasher = new_hasher::<Goldilocks>();
        end_timer!(timer);

        let element = Goldilocks::random(rng);

        let timer = start_timer!(|| "Timing hash update");
        for _ in 0..10000 {
            hasher.update(&[element]);
        }
        end_timer!(timer);

        let timer = start_timer!(|| "Timing hash squeeze");
        for _ in 0..10000 {
            hasher.squeeze_vec();
        }
        end_timer!(timer);

        let timer = start_timer!(|| "Timing hash update squeeze");
        for _ in 0..10000 {
            hasher.update(&[element]);
            hasher.squeeze_vec();
        }
        end_timer!(timer);
    }

    #[test]
    fn bench_n_to_1() {
        let mut rng = test_rng();
        let n_evaluations = 60;
        let n_iterations = 200;

        let values = (0..n_evaluations)
            .map(|_| Goldilocks::random(&mut rng))
            .collect_vec();

        let mut duration_sum = Duration::ZERO;
        for i in 0..n_iterations {
            let mut hasher = new_hasher::<Goldilocks>();
            let now = Instant::now();
            hasher.update(&values);
            let hash = &hasher.squeeze_vec()[0..DIGEST_WIDTH];
            duration_sum += now.elapsed();
        }
        let mean_duration = duration_sum / n_iterations;

        println!("time to hash {:?}-to-1: {:?}", n_evaluations, mean_duration);
    }

    #[test]
    fn bench_2_to_1() {
        let mut rng = test_rng();
        let n_evaluations = 60;
        let n_iterations = 20000;

        let values = (0..n_evaluations)
            .map(|_| Goldilocks::random(&mut rng))
            .collect_vec();

        let mut hasher = new_hasher::<Goldilocks>();
        hasher.update(&values);
        let hash = &hasher.squeeze_vec()[0..DIGEST_WIDTH];

        let left = Digest(hash.try_into().unwrap());
        let right = left.clone();

        let mut duration_sum = Duration::ZERO;
        for i in 0..n_iterations {
            let mut hasher = new_hasher::<Goldilocks>();
            let now = Instant::now();
            hash_two_digests(&left, &right, &mut hasher);
            duration_sum += now.elapsed();
        }
        let mean_duration = duration_sum / n_iterations;

        println!("time to hash 2-to-1: {:?}", mean_duration);
    }

    #[test]
    fn test_hasher_state_preservation() {
        let mut rng = test_rng();
        let value1 = Goldilocks::random(&mut rng);
        let value2 = Goldilocks::random(&mut rng);

        let mut hasher = new_hasher::<Goldilocks>();

        // corrupt state
        hasher.update(&[value1]);

        // hash value 2 after corrupted state
        hasher.update(&[value2]);
        let hash_after_corruption = &hasher.squeeze();

        // fresh state
        let mut hasher = new_hasher::<Goldilocks>();
        hasher.update(&[value2]);
        let hash_from_fresh_state = &hasher.squeeze();

        // verify that previous input modifies hash output
        assert_ne!(hash_after_corruption, hash_from_fresh_state);
    }
}
