// use std::iter::repeat;

use ff_ext::ExtensionField;
use goldilocks::SmallField;
#[cfg(feature = "use-plonky2")]
use itertools::Itertools;
#[cfg(feature = "use-plonky2")]
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::HashOut, hashing::PlonkyPermutation, poseidon::PoseidonHash,
        poseidon::PoseidonPermutation,
    },
    plonk::config::Hasher as _,
};
#[cfg(not(feature = "use-plonky2"))]
use poseidon::Poseidon;

use serde::{Deserialize, Serialize};

pub const DIGEST_WIDTH: usize = super::transcript::OUTPUT_WIDTH;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField + Serialize>(pub [F; DIGEST_WIDTH]);
#[cfg(not(feature = "use-plonky2"))]
pub type Hasher<F> = Poseidon<F, 12, 11>;

#[cfg(feature = "use-plonky2")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hasher<F> {
    inner: PoseidonPermutation<GoldilocksField>,
    phantom: std::marker::PhantomData<F>,
}
#[cfg(feature = "use-plonky2")]
impl<F: SmallCharField> Hasher<F> {
    pub fn update(&mut self, input: &[F::BaseField]) {
        self.inner.set_from_slice(
            input
                .iter()
                .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
                .collect_vec()
                .as_slice(),
            0,
        );
        self.inner.permute();
    }

    pub fn squeeze_vec(&mut self) -> Vec<F::BaseField> {
        self.inner
            .squeeze()
            .iter()
            .map(|x| F::BaseField::from(x.to_canonical_u64()))
            .collect_vec()
    }
}
#[cfg(feature = "use-plonky2")]
pub fn new_hasher<F: SmallField>() -> Hasher<F> {
    use std::iter::repeat;

    Hasher {
        inner: PoseidonPermutation::<GoldilocksField>::new(repeat(GoldilocksField::ZERO)),
        phantom: std::marker::PhantomData,
    }
}

#[cfg(not(feature = "use-plonky2"))]
pub fn new_hasher<F: SmallField>() -> Hasher<F> {
    // FIXME: Change to the right parameter
    Hasher::<F>::new(8, 22)
}

#[cfg(not(feature = "use-plonky2"))]
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

#[cfg(not(feature = "use-plonky2"))]
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

#[cfg(feature = "use-plonky2")]
pub fn hash_two_leaves<E: ExtensionField>(
    a: &F::ChallengeField,
    b: &F::ChallengeField,
    hasher: &Hasher<PCSBaseField<F>>,
) -> Digest<F::PolynomialField> {
    let repr = a
        .to_canonical_u64_vec()
        .iter()
        .chain(b.to_canonical_u64_vec().iter())
        .map(|x| GoldilocksField::from_canonical_u64(*x))
        .collect::<Vec<GoldilocksField>>();

    let result = PoseidonHash::hash_no_pad(repr.as_slice());
    Digest(
        result
            .elements
            .iter()
            .map(|x| F::BaseField::from(x.to_canonical_u64()))
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap(),
    )
}

#[cfg(not(feature = "use-plonky2"))]
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

#[cfg(feature = "use-plonky2")]
pub fn hash_two_digests<F: SmallField>(
    a: &Digest<F>,
    b: &Digest<F>,
    _hasher: &Hasher<F>,
) -> Digest<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    let a = HashOut::<GoldilocksField>::from_vec(
        a.0.iter()
            .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
            .collect::<Vec<_>>(),
    );
    let b = HashOut::<GoldilocksField>::from_vec(
        b.0.iter()
            .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
            .collect::<Vec<_>>(),
    );

    let result = PoseidonHash::two_to_one(a, b);
    Digest(
        result
            .elements
            .iter()
            .map(|x| F::BaseField::from(x.to_canonical_u64()))
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap(),
    )
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
