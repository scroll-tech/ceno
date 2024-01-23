// use std::iter::repeat;

use goldilocks::SmallField;

use poseidon::Poseidon;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const DIGEST_WIDTH: usize = super::transcript::OUTPUT_WIDTH;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField>(pub [F::BaseField; DIGEST_WIDTH])
where
    F::BaseField: Serialize + DeserializeOwned;
pub type Hasher<F> = Poseidon<<F as SmallField>::BaseField, 12, 11>;

// Plonky 2 implementation
// #[derive(Clone, Debug, Default, PartialEq, Eq)]
// pub struct Hasher {
//     inner: PoseidonPermutation<GoldilocksField>,
// }

// impl Hasher {
//     pub fn update<F: SmallField>(&mut self, input: &[F]) {
//         self.inner.set_from_slice(
//             input
//                 .iter()
//                 .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
//                 .collect_vec()
//                 .as_slice(),
//             0,
//         );
//         self.inner.permute();
//     }

//     pub fn squeeze_vec<F: SmallField>(&mut self) -> Vec<F::BaseField> {
//         self.inner
//             .squeeze()
//             .iter()
//             .map(|x| F::BaseField::from(x.to_canonical_u64()))
//             .collect_vec()
//     }
// }

pub fn new_hasher<F: SmallField>() -> Hasher<F> {
    // FIXME: Change to the right parameter
    Hasher::<F>::new(8, 22)
}

// Plonky2
// pub fn new_hasher() -> Hasher {
//     Hasher {
//         inner: PoseidonPermutation::<GoldilocksField>::new(repeat(GoldilocksField::ZERO)),
//     }
// }

pub fn hash_two_leaves<F: SmallField>(a: &F, b: &F, hasher: &Hasher<F>) -> Digest<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    // This is the Plonky2 part
    // let repr = a
    //     .to_canonical_u64_vec()
    //     .iter()
    //     .chain(b.to_canonical_u64_vec().iter())
    //     .map(|x| GoldilocksField::from_canonical_u64(*x))
    //     .collect::<Vec<GoldilocksField>>();

    // let result = PoseidonHash::hash_no_pad(repr.as_slice());
    // Digest(
    //     result
    //         .elements
    //         .iter()
    //         .map(|x| F::BaseField::from(x.to_canonical_u64()))
    //         .collect::<Vec<_>>()
    //         .as_slice()
    //         .try_into()
    //         .unwrap(),
    // )

    let mut hasher = hasher.clone();
    hasher.update(a.to_limbs().as_slice());
    hasher.update(b.to_limbs().as_slice());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

pub fn hash_two_digests<F: SmallField>(
    a: &Digest<F>,
    b: &Digest<F>,
    hasher: &Hasher<F>,
) -> Digest<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    // Plonky2 version
    // let a = HashOut::<GoldilocksField>::from_vec(
    //     a.0.iter()
    //         .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
    //         .collect::<Vec<_>>(),
    // );
    // let b = HashOut::<GoldilocksField>::from_vec(
    //     b.0.iter()
    //         .map(|x| GoldilocksField::from_canonical_u64(x.to_canonical_u64_vec()[0]))
    //         .collect::<Vec<_>>(),
    // );

    // let result = PoseidonHash::two_to_one(a, b);
    // Digest(
    //     result
    //         .elements
    //         .iter()
    //         .map(|x| F::BaseField::from(x.to_canonical_u64()))
    //         .collect::<Vec<_>>()
    //         .as_slice()
    //         .try_into()
    //         .unwrap(),
    // )
    let mut hasher = hasher.clone();
    hasher.update(a.0.as_slice());
    hasher.update(b.0.as_slice());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}
