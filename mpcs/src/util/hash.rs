// use std::iter::repeat;

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use multilinear_extensions::mle::FieldType;
use poseidon::Poseidon;

use serde::{Deserialize, Serialize};
use transcript::Transcript;

pub const DIGEST_WIDTH: usize = transcript::basic::OUTPUT_WIDTH;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField + Serialize>(pub [F; DIGEST_WIDTH]);
pub type Hasher<F> = Poseidon<F, 12, 11>;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E::BaseField>,
    transcript: &mut Transcript<E>,
) {
    digest
        .0
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}

pub fn new_hasher<F: SmallField>() -> Hasher<F> {
    // FIXME: Change to the right parameter
    Hasher::<F>::new(8, 22)
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

pub fn hash_field_type<E: ExtensionField>(
    field_type: &FieldType<E>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    match field_type {
        FieldType::Ext(ext) => {
            ext.iter().for_each(|x| {
                hasher.update(x.as_bases());
            });
        }
        FieldType::Base(base) => {
            hasher.update(base);
        }
        FieldType::Unreachable => panic!("Unreachable"),
    };
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

pub fn hash_field_type_subvector<E: ExtensionField>(
    field_type: &FieldType<E>,
    range: impl IntoIterator<Item = usize>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField> {
    let mut hasher = hasher.clone();
    match field_type {
        FieldType::Ext(ext) => {
            range.into_iter().for_each(|i| {
                hasher.update(&ext[i].as_bases());
            });
        }
        FieldType::Base(base) => {
            for i in range {
                hasher.update(&[base[i]]);
            }
        }
        FieldType::Unreachable => panic!("Unreachable"),
    };
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer, test_rng};
    use ff::Field;
    use goldilocks::Goldilocks;

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
}
