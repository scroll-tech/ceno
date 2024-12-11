use ff_ext::ExtensionField;
use goldilocks::SmallField;
use poseidon::poseidon_hash::PoseidonHash;

use transcript::Transcript;

pub use poseidon::digest::Digest;
use poseidon::poseidon::Poseidon;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E::BaseField>,
    transcript: &mut impl Transcript<E>,
) {
    digest
        .0
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}

pub fn hash_two_leaves_ext<E: ExtensionField>(a: &E, b: &E) -> Digest<E::BaseField> {
    let input = [a.as_bases(), b.as_bases()].concat();
    PoseidonHash::hash_or_noop(&input)
}

pub fn hash_two_leaves_base<E: ExtensionField>(
    a: &E::BaseField,
    b: &E::BaseField,
) -> Digest<E::BaseField> {
    PoseidonHash::hash_or_noop(&[*a, *b])
}

pub fn hash_two_leaves_batch_ext<E: ExtensionField>(a: &[E], b: &[E]) -> Digest<E::BaseField> {
    let a_m_to_1_hash = PoseidonHash::hash_or_noop_iter(a.iter().flat_map(|v| v.as_bases()));
    let b_m_to_1_hash = PoseidonHash::hash_or_noop_iter(b.iter().flat_map(|v| v.as_bases()));
    hash_two_digests(&a_m_to_1_hash, &b_m_to_1_hash)
}

pub fn hash_two_leaves_batch_base<E: ExtensionField>(
    a: &[E::BaseField],
    b: &[E::BaseField],
) -> Digest<E::BaseField> {
    let a_m_to_1_hash = PoseidonHash::hash_or_noop_iter(a.iter());
    let b_m_to_1_hash = PoseidonHash::hash_or_noop_iter(b.iter());
    hash_two_digests(&a_m_to_1_hash, &b_m_to_1_hash)
}

pub fn hash_two_digests<F: SmallField + Poseidon>(a: &Digest<F>, b: &Digest<F>) -> Digest<F> {
    PoseidonHash::two_to_one(a, b)
}
