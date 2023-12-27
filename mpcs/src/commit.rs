use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::{
    fri::FriConfig,
    linear_code::{LinearCode, ReedSolomonCode},
    merkle::MerkleTree,
    structs::{Commitment, CommitmentKey},
};

impl<F: SmallField + FromUniformBytes<64>> CommitmentKey<F> {
    /// Generate a commitment key for a given degree and FRI configuration.
    pub fn setup(size_bits: usize, config: FriConfig) -> Self {
        Self {
            fri_params: config.fri_params(size_bits, true),
            linear_code: ReedSolomonCode::new(size_bits, config.rate_bits),
        }
    }
}

impl Commitment {
    /// Generate the commitment for a multilinear polynomial
    pub fn commit<F: SmallField + FromUniformBytes<64>>(
        key: CommitmentKey<F>,
        poly: &DenseMultilinearExtension<F>,
    ) -> Self {
        let codeword = key.linear_code.encode(&poly.evaluations);
        Commitment {
            merkle_cap: MerkleTree::new(codeword).root,
        }
    }
}
