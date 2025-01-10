use ff_ext::{ExtensionField, SmallField};
use p3_field::PrimeField;
use p3_mds::MdsPermutation;
use poseidon::{SPONGE_WIDTH, poseidon_hash::PoseidonHash};

use transcript::Transcript;

pub use poseidon::digest::Digest;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E::BaseField>,
    transcript: &mut impl Transcript<E>,
) {
    digest
        .0
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}

pub fn hash_two_leaves_ext<E: ExtensionField, Mds>(a: &E, b: &E) -> Digest<E::BaseField>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    let input = [a.as_bases(), b.as_bases()].concat();
    PoseidonHash::<E::BaseField, Mds>::hash_or_noop(&input)
}

pub fn hash_two_leaves_base<E: ExtensionField, Mds>(
    a: &E::BaseField,
    b: &E::BaseField,
) -> Digest<E::BaseField>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    PoseidonHash::<E::BaseField, Mds>::hash_or_noop(&[*a, *b])
}

pub fn hash_two_leaves_batch_ext<E: ExtensionField, Mds>(a: &[E], b: &[E]) -> Digest<E::BaseField>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    let a_m_to_1_hash =
        PoseidonHash::<E::BaseField, Mds>::hash_or_noop_iter(a.iter().flat_map(|v| v.as_bases()));
    let b_m_to_1_hash =
        PoseidonHash::<E::BaseField, Mds>::hash_or_noop_iter(b.iter().flat_map(|v| v.as_bases()));
    hash_two_digests::<E::BaseField, Mds>(&a_m_to_1_hash, &b_m_to_1_hash)
}

pub fn hash_two_leaves_batch_base<E: ExtensionField, Mds>(
    a: &[E::BaseField],
    b: &[E::BaseField],
) -> Digest<E::BaseField>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    let a_m_to_1_hash = PoseidonHash::<E::BaseField, Mds>::hash_or_noop_iter(a.iter());
    let b_m_to_1_hash = PoseidonHash::<E::BaseField, Mds>::hash_or_noop_iter(b.iter());
    hash_two_digests::<E::BaseField, Mds>(&a_m_to_1_hash, &b_m_to_1_hash)
}

pub fn hash_two_digests<F: SmallField + PrimeField, Mds>(a: &Digest<F>, b: &Digest<F>) -> Digest<F>
where
    Mds: MdsPermutation<F, SPONGE_WIDTH> + Default,
{
    PoseidonHash::<F, Mds>::two_to_one(a, b)
}
