use ff_ext::ExtensionField;
use goldilocks::SmallField;
use multilinear_extensions::mle::FieldType;
use poseidon::poseidon_hash::PoseidonHash;

use transcript::Transcript;

pub use poseidon::digest::Digest;
use poseidon::poseidon::Poseidon;

use super::{field_type_iter_base, field_type_iter_range_base};

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E::BaseField>,
    transcript: &mut Transcript<E>,
) {
    digest
        .0
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}

pub fn hash_field_type<E: ExtensionField>(field_type: &FieldType<E>) -> Digest<E::BaseField> {
    PoseidonHash::hash_or_noop_iter(field_type_iter_base(&field_type))
}

pub fn hash_field_type_subvector<E: ExtensionField>(
    field_type: &FieldType<E>,
    range: impl IntoIterator<Item = usize>,
) -> Digest<E::BaseField> {
    PoseidonHash::hash_or_noop_iter(field_type_iter_range_base(&field_type, range))
}

pub fn hash_two_digests<F: SmallField + Poseidon>(a: &Digest<F>, b: &Digest<F>) -> Digest<F> {
    PoseidonHash::two_to_one(a, b)
}
