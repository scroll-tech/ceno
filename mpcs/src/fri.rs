/// All the codes in this module are borrowed from Plonky2
use serde::{Deserialize, Serialize};

/// Compute the approximate size of a FRI proof. Note that this
/// ignores initial evaluations, which aren't affected by arities, and some other minor
/// contributions. The result is measured in field elements.
#[allow(unused)]
fn relative_proof_size(
    degree_bits: usize,
    rate_bits: usize,
    num_queries: usize,
    rounds: usize,
) -> usize {
    const D: usize = 4;

    let mut current_layer_bits = degree_bits + rate_bits;

    let mut total_elems = 0;
    for i in 0..rounds {
        // Add neighboring evaluations, which are extension field elements.
        total_elems += D * num_queries;
        // Add siblings in the Merkle path.
        total_elems += current_layer_bits * 4 * num_queries;

        current_layer_bits -= 1;
    }

    // Add the final polynomial's coefficients.
    assert!(current_layer_bits >= rate_bits);
    let final_poly_len = 1 << (current_layer_bits - rate_bits);
    total_elems += D * final_poly_len;

    total_elems
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FriConfig {
    /// `rate = 2^{-rate_bits}`.
    pub rate_bits: usize,

    /// Height of Merkle tree caps.
    pub cap_height: usize,

    pub proof_of_work_bits: u32,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,

    /// Final polynomial degree bits.
    pub final_degree_bits: usize,
}

impl FriConfig {
    pub fn standard_fast_config() -> FriConfig {
        FriConfig {
            rate_bits: 1,
            cap_height: 4,
            proof_of_work_bits: 16,
            num_query_rounds: 84,
            final_degree_bits: 4,
        }
    }

    pub fn rate(&self) -> f64 {
        1.0 / ((1 << self.rate_bits) as f64)
    }

    pub fn fri_params(&self, degree_bits: usize, hiding: bool) -> FriParams {
        FriParams {
            config: self.clone(),
            hiding,
            degree_bits,
            rounds: degree_bits - self.final_degree_bits,
        }
    }

    pub fn num_cap_elements(&self) -> usize {
        1 << self.cap_height
    }
}

/// FRI parameters, including generated parameters which are specific to an instance size, in
/// contrast to `FriConfig` which is user-specified and independent of instance size.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FriParams {
    /// User-specified FRI configuration.
    pub config: FriConfig,

    /// Whether to use a hiding variant of Merkle trees (where random salts are added to leaves).
    pub hiding: bool,

    /// The degree of the purported codeword, measured in bits.
    pub degree_bits: usize,

    /// The number of rounds for the FRI
    pub rounds: usize,
}

impl FriParams {
    pub fn lde_bits(&self) -> usize {
        self.degree_bits + self.config.rate_bits
    }

    pub fn lde_size(&self) -> usize {
        1 << self.lde_bits()
    }

    pub fn final_poly_bits(&self) -> usize {
        self.degree_bits - self.rounds
    }

    pub fn final_poly_len(&self) -> usize {
        1 << self.final_poly_bits()
    }
}
