use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;

use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::util::{field_type_iter_base, field_type_iter_range_base};

pub trait Hasher<E: ExtensionField>: std::fmt::Debug + Clone + Default
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type Digest: Clone
        + std::fmt::Debug
        + Default
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Eq
        + Sync
        + Send
        + TryFrom<Vec<E::BaseField>, Error: std::fmt::Debug>;

    fn write_digest_to_transcript(digest: &Self::Digest, transcript: &mut Transcript<E>);

    fn hash_iter<'a, I: Iterator<Item = &'a E::BaseField>>(input_iter: I) -> Self::Digest;

    fn hash_slice_base(vec: &[E::BaseField]) -> Self::Digest {
        Self::hash_iter(vec.iter())
    }

    fn hash_slice_ext(vec: &[E]) -> Self::Digest {
        Self::hash_iter(vec.iter().flat_map(|x| x.as_bases()))
    }

    fn hash_field_type(field_type: &FieldType<E>) -> Self::Digest {
        Self::hash_iter(field_type_iter_base(&field_type))
    }

    fn hash_field_type_subvector(
        field_type: &FieldType<E>,
        range: impl IntoIterator<Item = usize>,
    ) -> Self::Digest {
        Self::hash_iter(field_type_iter_range_base(&field_type, range))
    }

    fn hash_two_digests(a: &Self::Digest, b: &Self::Digest) -> Self::Digest;
}
