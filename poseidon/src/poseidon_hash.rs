use std::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample};

use crate::{
    challenger::DefaultChallenger, constants::DIGEST_WIDTH, digest::Digest, poseidon::PoseidonField,
};

pub struct PoseidonHash<F> {
    _phantom: PhantomData<F>,
}

impl<F: PoseidonField> PoseidonHash<F> {}

impl<F: PoseidonField> PoseidonHash<F> {
    pub fn two_to_one(left: &Digest<F>, right: &Digest<F>) -> Digest<F> {
        compress::<F>(left, right)
    }

    pub fn hash_or_noop(inputs: &[F]) -> Digest<F> {
        if inputs.len() <= DIGEST_WIDTH {
            Digest::from_partial(inputs)
        } else {
            hash_n_to_hash_no_pad::<F>(inputs)
        }
    }

    // pub fn hash_or_noop_iter<'a, I: Iterator<Item = &'a F>>(mut input_iter: I) -> Digest<F> {
    //     let mut initial_elements = Vec::with_capacity(DIGEST_WIDTH);

    //     for _ in 0..DIGEST_WIDTH + 1 {
    //         match input_iter.next() {
    //             Some(value) => initial_elements.push(value),
    //             None => break,
    //         }
    //     }

    //     if initial_elements.len() <= DIGEST_WIDTH {
    //         Digest::from_partial(
    //             initial_elements
    //                 .into_iter()
    //                 .copied()
    //                 .collect::<Vec<F>>()
    //                 .as_slice(),
    //         )
    //     } else {
    //         let iter = initial_elements.into_iter().chain(input_iter);
    //         hash_n_to_m_no_pad_iter::<'_, F, _>(iter, DIGEST_WIDTH)
    //             .try_into()
    //             .unwrap()
    //     }
    // }
}

pub fn hash_n_to_m_no_pad<F: PoseidonField>(inputs: &[F], num_outputs: usize) -> Vec<F> {
    let mut challenger = DefaultChallenger::<F, F::T>::new_poseidon_default();
    challenger.observe_slice(inputs);
    challenger.sample_vec(num_outputs)
    // let mut perm = PoseidonPermutation::<F>::new(core::iter::repeat(F::ZERO));

    // Absorb all input chunks.
    // for input_chunk in inputs.chunks(SPONGE_RATE) {
    //     // Overwrite the first r elements with the inputs. This differs from a standard sponge,
    //     // where we would xor or add in the inputs. This is a well-known variant, though,
    //     // sometimes called "overwrite mode".
    //     perm.set_from_slice(input_chunk, 0);
    //     perm.permute();
    // }

    // Squeeze until we have the desired number of outputs
    // let mut outputs = Vec::with_capacity(num_outputs);
    // loop {
    //     for &item in perm.squeeze() {
    //         outputs.push(item);
    //         if outputs.len() == num_outputs {
    //             return outputs;
    //         }
    //     }
    //     perm.permute();
    // }
}

// pub fn hash_n_to_m_no_pad_iter<'a, F: PrimeField, I: Iterator<Item = &'a F>>(
//     mut input_iter: I,
//     num_outputs: usize,
// ) -> Vec<F> {
//     let mut challenger = DefaultChallenger::<F, F::T>::new_poseidon_default();
//     let mut perm = PoseidonPermutation::<F, Mds>::new(core::iter::repeat(F::ZERO));

//     // Absorb all input chunks.
//     loop {
//         let chunk = input_iter.by_ref().take(SPONGE_RATE).collect::<Vec<_>>();
//         if chunk.is_empty() {
//             break;
//         }
//         // Overwrite the first r elements with the inputs. This differs from a standard sponge,
//         // where we would xor or add in the inputs. This is a well-known variant, though,
//         // sometimes called "overwrite mode".
//         perm.set_from_slice(chunk.into_iter().copied().collect::<Vec<F>>().as_slice(), 0);
//         perm.permute();
//     }

//     // Squeeze until we have the desired number of outputs
//     let mut outputs = Vec::with_capacity(num_outputs);
//     loop {
//         for &item in perm.squeeze() {
//             outputs.push(item);
//             if outputs.len() == num_outputs {
//                 return outputs;
//             }
//         }
//         perm.permute();
//     }
// }

pub fn hash_n_to_hash_no_pad<F: PoseidonField>(inputs: &[F]) -> Digest<F> {
    hash_n_to_m_no_pad(inputs, DIGEST_WIDTH).try_into().unwrap()
}

pub fn compress<F: PoseidonField>(x: &Digest<F>, y: &Digest<F>) -> Digest<F> {
    let mut challenger = DefaultChallenger::<F, F::T>::new_poseidon_default();
    challenger.observe_slice(x.elements());
    challenger.observe_slice(y.elements());
    Digest(challenger.sample_array::<DIGEST_WIDTH>())
    // let mut perm = PoseidonPermutation::<F, Mds>::new(core::iter::repeat(F::ZERO));
    // perm.set_from_slice(x.elements(), 0);
    // perm.set_from_slice(y.elements(), DIGEST_WIDTH);

    // perm.permute();

    // Digest(perm.squeeze()[..DIGEST_WIDTH].try_into().unwrap())
}
