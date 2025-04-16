use crate::{crypto::DigestExt, error::Error, utils::dedup};
use ff_ext::{ExtensionField, SmallField};
use transcript::Transcript;

pub fn get_challenge_stir_queries<E: ExtensionField, T: Transcript<E>>(
    domain_size: usize,
    folding_factor: usize,
    num_queries: usize,
    transcript: &mut T,
) -> Result<Vec<usize>, Error> {
    let folded_domain_size = domain_size / (1 << folding_factor);
    // We need these many bytes to represent the query indices
    let queries = transcript.sample_and_append_vec(b"stir_queries", num_queries);
    let indices = queries
        .iter()
        .map(|query| query.as_bases()[0].to_canonical_u64() as usize % folded_domain_size);
    Ok(dedup(indices))
}

pub trait MmcsCommitmentWriter<E: ExtensionField> {
    fn add_digest(&mut self, digest: DigestExt<E>) -> Result<(), Error>;
}

pub trait MmcsCommitmentReader<E: ExtensionField> {
    fn read_digest(&mut self) -> Result<DigestExt<E>, Error>;
}
