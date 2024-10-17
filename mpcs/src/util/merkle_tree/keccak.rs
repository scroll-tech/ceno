use std::io::{BufReader, Read};

use ff_ext::ExtensionField;

use goldilocks::SmallField;
use keccak_hash::{keccak_256, keccak_buffer};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use super::Hasher;

struct FRead<'a, E: ExtensionField, I: Iterator<Item = &'a E::BaseField>> {
    iter: I,
    _phantom: std::marker::PhantomData<E>,
}

impl<'a, E: ExtensionField, I: Iterator<Item = &'a E::BaseField>> Read for FRead<'a, E, I> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while i + 8 <= buf.len() {
            if let Some(x) = self.iter.next() {
                buf[i..i + 8].copy_from_slice(&x.to_canonical_u64().to_le_bytes());
                i += 8;
            } else {
                break;
            }
        }
        Ok(i)
    }
}

#[derive(Debug, Default, Clone)]
pub struct KeccakHasher {}

impl<E: ExtensionField> Hasher<E> for KeccakHasher
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type Digest = [u8; 32];

    fn write_digest_to_transcript(digest: &Self::Digest, transcript: &mut Transcript<E>) {
        transcript.append_message(digest);
    }

    fn hash_iter<'a, I: Iterator<Item = &'a E::BaseField>>(iter: I) -> Self::Digest {
        keccak_buffer(&mut BufReader::new(FRead {
            iter,
            _phantom: std::marker::PhantomData::<E>,
        }))
        .unwrap()
        .into()
    }

    fn hash_two_digests(a: &Self::Digest, b: &Self::Digest) -> Self::Digest {
        let input = a.iter().chain(b).map(|x| *x).collect::<Vec<_>>();
        let mut output = [0u8; 32];
        keccak_256(input.as_slice(), &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use multilinear_extensions::mle::FieldType;

    use crate::util::{
        field_type_index_base,
        merkle_tree::{
            hash_leaves_group, hash_two_leaves_batch, BatchLeavesPair, MerkleTree,
            SingleLeavesGroup,
        },
    };

    use super::*;

    #[test]
    fn test_merkelize() {
        let leaves = FieldType::Base(vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
            Goldilocks::from(4),
            Goldilocks::from(5),
            Goldilocks::from(3),
            Goldilocks::from(1),
            Goldilocks::from(0),
        ]);
        let merkle_tree =
            MerkleTree::<GoldilocksExt2, KeccakHasher>::from_leaves(leaves.clone(), 2);
        assert_eq!(merkle_tree.leaf_group_num(), 4);
        assert_eq!(merkle_tree.leaf_group_size(), 2);
        for i in 0..leaves.len() {
            assert_eq!(
                merkle_tree.get_leaf_as_base(i),
                vec![field_type_index_base(&leaves, i)]
            );
        }
        for i in 0..(leaves.len() >> 1) {
            let path = merkle_tree.merkle_path_without_leaf_sibling_or_root(i << 1);
            assert_eq!(path.len(), 2);
            assert_eq!(path.height(), 3);
            // TODO: have no idea why this cannot compile, asking to
            // implement PartialEq for KeccakHasher
            // assert_eq!(
            //     path,
            //     merkle_tree.merkle_path_without_leaf_sibling_or_root((i << 1) + 1)
            // );
            let leaves_group = SingleLeavesGroup::from_all_leaves(i, 2, &leaves);
            let leaves_pair = BatchLeavesPair::from_all_leaves(i, &[&leaves]);

            let leaves_group_hash =
                hash_leaves_group::<GoldilocksExt2, KeccakHasher>(&leaves_group);
            let leaves_pair_hash =
                hash_two_leaves_batch::<GoldilocksExt2, KeccakHasher>(&leaves_pair);

            assert_eq!(leaves_group_hash, leaves_pair_hash);

            path.authenticate_leaves_group(&leaves_group, i, &merkle_tree.root());
            path.authenticate_batch_leaves_pair(&leaves_pair, i, &merkle_tree.root());
        }

        let leaves = vec![
            FieldType::Base(vec![
                Goldilocks::from(1),
                Goldilocks::from(2),
                Goldilocks::from(3),
                Goldilocks::from(4),
                Goldilocks::from(5),
                Goldilocks::from(3),
                Goldilocks::from(1),
                Goldilocks::from(0),
            ]),
            FieldType::Base(vec![
                Goldilocks::from(4),
                Goldilocks::from(5),
                Goldilocks::from(1),
                Goldilocks::from(2),
                Goldilocks::from(3),
                Goldilocks::from(9),
                Goldilocks::from(8),
                Goldilocks::from(0),
            ]),
        ];
        let merkle_tree =
            MerkleTree::<GoldilocksExt2, KeccakHasher>::from_batch_leaves(leaves.clone(), 2);
        assert_eq!(merkle_tree.leaf_group_num(), 4);
        assert_eq!(merkle_tree.leaf_group_size(), 2);
        for i in 0..leaves.len() {
            assert_eq!(
                merkle_tree.get_leaf_as_base(i),
                vec![
                    field_type_index_base(&leaves[0], i),
                    field_type_index_base(&leaves[1], i)
                ]
            );
        }
        for i in 0..(leaves.len() >> 1) {
            let path = merkle_tree.merkle_path_without_leaf_sibling_or_root(i << 1);
            assert_eq!(path.len(), 2);
            assert_eq!(path.height(), 3);
            // TODO: have no idea why this cannot compile, asking to
            // implement PartialEq for KeccakHasher
            // assert_eq!(
            //     path,
            //     merkle_tree.merkle_path_without_leaf_sibling_or_root((i << 1) + 1)
            // );
            let leaves_pair = BatchLeavesPair::from_all_leaves(i, &leaves.iter().collect_vec());
            path.authenticate_batch_leaves_pair(&leaves_pair, i, &merkle_tree.root());
        }
    }
}
