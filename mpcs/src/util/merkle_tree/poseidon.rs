use ff_ext::ExtensionField;
use poseidon::poseidon_hash::PoseidonHash;

use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

pub use poseidon::digest::Digest;

use super::Hasher;

#[derive(Debug, Default, Clone)]
pub struct PoseidonHasher {}

impl<E: ExtensionField> Hasher<E> for PoseidonHasher
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type Digest = Digest<E::BaseField>;

    fn write_digest_to_transcript(digest: &Self::Digest, transcript: &mut Transcript<E>) {
        digest
            .0
            .iter()
            .for_each(|x| transcript.append_field_element(x));
    }

    fn hash_iter<'a, I: Iterator<Item = &'a E::BaseField>>(iter: I) -> Self::Digest {
        PoseidonHash::hash_or_noop_iter(iter)
    }

    fn hash_two_digests(a: &Self::Digest, b: &Self::Digest) -> Self::Digest {
        PoseidonHash::two_to_one(a, b)
    }
}
