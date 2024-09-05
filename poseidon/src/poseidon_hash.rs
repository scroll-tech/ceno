use crate::{
    constants::{DIGEST_WIDTH, SPONGE_RATE},
    digest::Digest,
    poseidon::{AdaptedField, Poseidon},
    poseidon_permutation::PoseidonPermutation,
};

pub struct PoseidonHash;

impl PoseidonHash {
    const HASH_SIZE: usize = DIGEST_WIDTH * 8;

    fn hash_no_pad<F: Poseidon + AdaptedField>(input: &[F]) -> Digest<F> {
        hash_n_to_hash_no_pad(input)
    }

    fn two_to_one<F: Poseidon + AdaptedField>(left: Digest<F>, right: Digest<F>) -> Digest<F> {
        compress(left, right)
    }

    fn hash_or_noop<F: Poseidon + AdaptedField>(inputs: Vec<F>) -> Digest<F> {
        if inputs.len() <= DIGEST_WIDTH {
            Digest::from_partial(inputs.as_slice())
        } else {
            hash_n_to_hash_no_pad(inputs.as_slice())
        }
    }
}

// Hashing
pub fn hash_n_to_m_no_pad<F: Poseidon>(inputs: &[F], num_outputs: usize) -> Vec<F> {
    let mut perm = PoseidonPermutation::new(core::iter::repeat(F::ZERO));

    // Absorb all input chunks.
    for input_chunk in inputs.chunks(SPONGE_RATE) {
        perm.set_from_slice(input_chunk, 0);
        perm.permute();
    }

    // Squeeze until we have the desired number of outputs
    let mut outputs = Vec::new();
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

pub fn hash_n_to_hash_no_pad<F: Poseidon>(inputs: &[F]) -> Digest<F> {
    // TODO: either explain why it is safe to unwrap or return error type
    hash_n_to_m_no_pad(inputs, DIGEST_WIDTH).try_into().unwrap()
}

pub fn compress<F: Poseidon>(x: Digest<F>, y: Digest<F>) -> Digest<F> {
    debug_assert!(SPONGE_RATE >= DIGEST_WIDTH);
    debug_assert_eq!(x.elements().len(), DIGEST_WIDTH);
    debug_assert_eq!(y.elements().len(), DIGEST_WIDTH);

    let mut perm = PoseidonPermutation::new(core::iter::repeat(F::ZERO));
    perm.set_from_slice(x.elements(), 0);
    perm.set_from_slice(y.elements(), DIGEST_WIDTH);

    perm.permute();

    Digest(perm.squeeze()[..DIGEST_WIDTH].try_into().unwrap())
}
