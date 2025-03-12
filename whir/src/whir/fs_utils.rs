use crate::{crypto::MerkleConfig as Config, error::Error, utils::dedup};
use ff_ext::{ExtensionField, SmallField};
use p3_commit::Mmcs;
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

pub trait MmcsCommitmentWriter<E: ExtensionField, MerkleConfig: Config<E>> {
    fn add_digest(
        &mut self,
        digest: <MerkleConfig::Mmcs as Mmcs<E>>::Commitment,
    ) -> Result<(), Error>;
}

pub trait MmcsCommitmentReader<E: ExtensionField, MerkleConfig: Config<E>> {
    fn read_digest(&mut self) -> Result<<MerkleConfig::Mmcs as Mmcs<E>>::Commitment, Error>;
}
