use crate::util::{
    hash::{
        hash_m_to_1_base_field, hash_m_to_1_ext_field,
        hash_two_digests, Digest, Hasher,
    },
    log2_strict,
};
use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use multilinear_extensions::mle::FieldType;
use serde::{de::DeserializeOwned, Serialize};

pub struct MerkleTree<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Vec<Digest<E::BaseField>>>,
    leaves: Vec<FieldType<E>>,
}

impl<E: ExtensionField> MerkleTree<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_leaves(leaves: FieldType<E>, hasher: &Hasher<E::BaseField>) -> Self {
        // ensure we have power of 2 leaves
        assert!(leaves.len().is_power_of_two());

        // assumes that leaves are of the same field type
        let inner = match &leaves {
            FieldType::Base(base_leaves) => merkelize_base::<E>(&[base_leaves.as_slice()], hasher),
            FieldType::Ext(ext_leaves) => merkelize_ext(&[ext_leaves.as_slice()], hasher),
            FieldType::Unreachable => unreachable!(),
        };

        Self {
            inner,
            leaves: vec![leaves],
        }
    }

    pub fn from_batch_leaves(leaves: Vec<FieldType<E>>, hasher: &Hasher<E::BaseField>) -> Self {
        // ensure we have power of 2 leaves
        assert!(leaves.len().is_power_of_two());

        // assumes that leaves are of the same field type
        let inner = match &leaves[0] {
            FieldType::Base(_) => merkelize_base::<E>(
                FieldType::get_as_base_vec(leaves.as_slice()).as_slice(),
                hasher,
            ),
            FieldType::Ext(_) => merkelize_ext(
                FieldType::get_as_ext_vec(leaves.as_slice()).as_slice(),
                hasher,
            ),
            FieldType::Unreachable => unreachable!(),
        };

        Self { inner, leaves }
    }
}

fn merkelize_base<E: ExtensionField>(
    values: &[&[E::BaseField]],
    hasher: &Hasher<E::BaseField>,
) -> Vec<Vec<Digest<E::BaseField>>> {
    let digest_first_layer = values
        .iter()
        .map(|value| hash_m_to_1_base_field::<E>(value, hasher))
        .collect::<Vec<_>>();
    build_tree::<E>(digest_first_layer, hasher)
}

// fn merkelize_base<E: ExtensionField>(
//     values: &[&[E::BaseField]],
//     hasher: &Hasher<E::BaseField>,
// ) -> Vec<Vec<Digest<E::BaseField>>> {
//     let num_threads = 10; // or a more appropriate number based on your system
//     let chunk_size = (values.len() + num_threads - 1) / num_threads;
//
//     let mut results = Vec::with_capacity(values.len());
//
//     thread::scope(|s| {
//         let mut handles = vec![];
//
//         for chunk in values.chunks(chunk_size) {
//             let handle = s.spawn(move || {
//                 let mut local_results = Vec::with_capacity(chunk.len());
//
//                 for value in chunk {
//                     let digest = hash_m_to_1_base_field::<E>(value, hasher);
//                     local_results.push(digest);
//                 }
//
//                 local_results
//             });
//
//             handles.push(handle);
//         }
//
//         for handle in handles {
//             results.extend(handle.join().unwrap());
//         }
//     });
//
//     build_tree::<E>(results, hasher)
// }

fn merkelize_ext<E: ExtensionField>(
    values: &[&[E]],
    hasher: &Hasher<E::BaseField>,
) -> Vec<Vec<Digest<E::BaseField>>> {
    let digest_first_layer = values
        .par_iter()
        .map(|value| hash_m_to_1_ext_field(value, hasher))
        .collect::<Vec<_>>();
    build_tree::<E>(digest_first_layer, hasher)
}

fn build_tree<E: ExtensionField>(
    leaf_digests: Vec<Digest<E::BaseField>>,
    hasher: &Hasher<E::BaseField>,
) -> Vec<Vec<Digest<E::BaseField>>> {
    let tree_height = log2_strict(leaf_digests.len());
    let mut digests = Vec::with_capacity(tree_height + 1);

    digests.push(leaf_digests);

    for i in 1..tree_height {
        let next_layer_digests = digests[i - 1]
            .par_chunks_exact(2)
            .map(|leaves| hash_two_digests(&leaves[0], &leaves[1], hasher))
            .collect::<Vec<_>>();

        digests.push(next_layer_digests);
    }

    digests
}

#[cfg(test)]
mod tests {
    use crate::util::{hash::new_hasher, merkle_tree::MerkleTree};
    use ark_std::test_rng;
    use ff::Field;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use multilinear_extensions::mle::FieldType;
    use std::time::{Duration, Instant};

    #[test]
    fn bench_merkle_commit_base() {
        let mut rng = test_rng();
        let n_iterations = 10;
        let n_vars = 20;
        let blowup_factor = 2;

        let n_leaves = (1 << n_vars) * blowup_factor;
        let mut duration_sum = Duration::ZERO;
        for i in 0..n_iterations {
            let hasher = new_hasher::<Goldilocks>();
            let values: FieldType<GoldilocksExt2> = FieldType::Base(
                (0..n_leaves)
                    .map(|_| Goldilocks::random(&mut rng))
                    .collect_vec(),
            );
            let now = Instant::now();
            MerkleTree::from_leaves(values, &hasher);
            duration_sum += now.elapsed();
        }
        let mean_duration = duration_sum / n_iterations;
        println!(
            "time to commit to 2^{:?} leaves: {:?}",
            n_vars, mean_duration
        );
    }

    #[test]
    fn bench_batch_merkle_commit_base() {
        let mut rng = test_rng();
        let n_iterations = 3;
        let n_evaluations = 60;
        let n_vars = 20;
        let blowup_factor = 8;

        let n_leaves = (1 << n_vars) * blowup_factor;
        let mut duration_sum = Duration::ZERO;
        for i in 0..n_iterations {
            let values: Vec<FieldType<GoldilocksExt2>> = vec![
                FieldType::Base(
                    (0..n_leaves)
                        .map(|_| Goldilocks::random(&mut rng))
                        .collect_vec()
                );
                n_evaluations
            ];
            let hasher = new_hasher::<Goldilocks>();
            let now = Instant::now();
            MerkleTree::from_batch_leaves(values, &hasher);
            duration_sum += now.elapsed();
        }
        let mean_duration = duration_sum / n_iterations;
        println!(
            "time to batch commit to 2^{:?} leaves with {:?} evaluations each: {:?}",
            n_vars, n_evaluations, mean_duration
        );
    }
}
