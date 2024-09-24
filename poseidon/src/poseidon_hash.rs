use crate::{
    constants::{DIGEST_WIDTH, SPONGE_RATE, SPONGE_WIDTH},
    digest::Digest,
    poseidon::{AdaptedField, Poseidon},
    poseidon_permutation::PoseidonPermutation,
};

pub struct PoseidonHash;

impl PoseidonHash {
    pub fn two_to_one<F: Poseidon + AdaptedField>(
        left: &Digest<F>,
        right: &Digest<F>,
    ) -> Digest<F> {
        compress(left, right)
    }

    pub fn hash_or_noop<F: Poseidon + AdaptedField>(inputs: &[F]) -> Digest<F> {
        if inputs.len() <= DIGEST_WIDTH {
            Digest::from_partial(inputs)
        } else {
            hash_n_to_hash_no_pad(inputs)
        }
    }
}

pub fn hash_n_to_m_no_pad<F: Poseidon>(inputs: &[F], num_outputs: usize) -> Vec<F> {
    let mut perm = PoseidonPermutation::new(core::iter::repeat(F::ZERO));

    // Absorb all input chunks.
    for input_chunk in inputs.chunks(SPONGE_RATE) {
        // Overwrite the first r elements with the inputs. This differs from a standard sponge,
        // where we would xor or add in the inputs. This is a well-known variant, though,
        // sometimes called "overwrite mode".
        perm.set_from_slice(input_chunk, 0);
        perm.permute();
    }

    // Squeeze until we have the desired number of outputs
    let mut outputs = Vec::with_capacity(num_outputs);
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
    hash_n_to_m_no_pad(inputs, DIGEST_WIDTH).try_into().unwrap()
}

pub fn compress<F: Poseidon>(x: &Digest<F>, y: &Digest<F>) -> Digest<F> {
    debug_assert!(SPONGE_RATE >= DIGEST_WIDTH);
    debug_assert!(SPONGE_WIDTH >= 2 * DIGEST_WIDTH);
    debug_assert_eq!(x.elements().len(), DIGEST_WIDTH);
    debug_assert_eq!(y.elements().len(), DIGEST_WIDTH);

    let mut perm = PoseidonPermutation::new(core::iter::repeat(F::ZERO));
    perm.set_from_slice(x.elements(), 0);
    perm.set_from_slice(y.elements(), DIGEST_WIDTH);

    perm.permute();

    Digest(perm.squeeze()[..DIGEST_WIDTH].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use crate::{digest::Digest, poseidon_hash::PoseidonHash};
    use goldilocks::Goldilocks;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{PrimeField64, Sample},
        },
        hash::{hash_types::HashOut, poseidon::PoseidonHash as PlonkyPoseidonHash},
        plonk::config::{GenericHashOut, Hasher},
    };
    use rand::{thread_rng, Rng};

    type PlonkyFieldElements = Vec<GoldilocksField>;
    type CenoFieldElements = Vec<Goldilocks>;

    const N_ITERATIONS: usize = 100;

    fn ceno_goldy_from_plonky_goldy(values: &[GoldilocksField]) -> Vec<Goldilocks> {
        values
            .iter()
            .map(|value| Goldilocks(value.to_canonical_u64()))
            .collect()
    }

    fn test_vector_pair(n: usize) -> (PlonkyFieldElements, CenoFieldElements) {
        let plonky_elems = GoldilocksField::rand_vec(n);
        let ceno_elems = ceno_goldy_from_plonky_goldy(plonky_elems.as_slice());
        (plonky_elems, ceno_elems)
    }

    fn random_hash_pair() -> (HashOut<GoldilocksField>, Digest<Goldilocks>) {
        let plonky_random_hash = HashOut::<GoldilocksField>::rand();
        let ceno_equivalent_hash = Digest(
            ceno_goldy_from_plonky_goldy(plonky_random_hash.elements.as_slice())
                .try_into()
                .unwrap(),
        );
        (plonky_random_hash, ceno_equivalent_hash)
    }

    fn compare_hash_output(
        plonky_hash: HashOut<GoldilocksField>,
        ceno_hash: Digest<Goldilocks>,
    ) -> bool {
        let plonky_elems = plonky_hash.to_vec();
        let plonky_in_ceno_field = ceno_goldy_from_plonky_goldy(plonky_elems.as_slice());
        plonky_in_ceno_field == ceno_hash.elements()
    }

    #[test]
    fn compare_hash() {
        let mut rng = thread_rng();
        for _ in 0..N_ITERATIONS {
            let n = rng.gen_range(5..=100);
            let (plonky_elems, ceno_elems) = test_vector_pair(n);
            let plonky_out = PlonkyPoseidonHash::hash_or_noop(plonky_elems.as_slice());
            let ceno_out = PoseidonHash::hash_or_noop(ceno_elems.as_slice());
            assert!(compare_hash_output(plonky_out, ceno_out));
        }
    }

    #[test]
    fn compare_noop() {
        let mut rng = thread_rng();
        for _ in 0..N_ITERATIONS {
            let n = rng.gen_range(0..=4);
            let (plonky_elems, ceno_elems) = test_vector_pair(n);
            let plonky_out = PlonkyPoseidonHash::hash_or_noop(plonky_elems.as_slice());
            let ceno_out = PoseidonHash::hash_or_noop(ceno_elems.as_slice());
            assert!(compare_hash_output(plonky_out, ceno_out));
        }
    }

    #[test]
    fn compare_two_to_one() {
        for _ in 0..N_ITERATIONS {
            let (plonky_hash_a, ceno_hash_a) = random_hash_pair();
            let (plonky_hash_b, ceno_hash_b) = random_hash_pair();
            let plonky_combined = PlonkyPoseidonHash::two_to_one(plonky_hash_a, plonky_hash_b);
            let ceno_combined = PoseidonHash::two_to_one(&ceno_hash_a, &ceno_hash_b);
            assert!(compare_hash_output(plonky_combined, ceno_combined));
        }
    }
}
