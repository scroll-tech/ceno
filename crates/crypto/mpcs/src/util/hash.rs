use ff_ext::ExtensionField;

use p3::commit::Mmcs;
use transcript::Transcript;

use crate::basefold::Digest;

use super::merkle_tree::Poseidon2ExtMerkleMmcs;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E>,
    transcript: &mut impl Transcript<E>,
) where
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    digest
        .clone()
        .into_iter()
        .for_each(|x| transcript.append_field_element(&x));
}
