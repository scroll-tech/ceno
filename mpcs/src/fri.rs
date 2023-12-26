/// All the codes in this module are borrowed from Plonky2
use serde::{Deserialize, Serialize};

/// A method for deciding what arity to use at each reduction layer.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FriReductionStrategy {
    /// Specifies the exact sequence of arities (expressed in bits) to use.
    Fixed(Vec<usize>),

    /// `ConstantArityBits(arity_bits, final_poly_bits)` applies reductions of arity `2^arity_bits`
    /// until the polynomial degree is less than or equal to `2^final_poly_bits` or until any further
    /// `arity_bits`-reduction makes the last FRI tree have height less than `cap_height`.
    /// This tends to work well in the recursive setting, as it avoids needing multiple configurations
    /// of gates used in FRI verification, such as `InterpolationGate`.
    ConstantArityBits(usize, usize),

    /// `MinSize(opt_max_arity_bits)` searches for an optimal sequence of reduction arities, with an
    /// optional max `arity_bits`. If this proof will have recursive proofs on top of it, a max
    /// `arity_bits` of 3 is recommended.
    MinSize(Option<usize>),
}

impl FriReductionStrategy {
    /// The arity of each FRI reduction step, expressed as the log2 of the actual arity.
    pub fn reduction_arity_bits(
        &self,
        mut degree_bits: usize,
        rate_bits: usize,
        cap_height: usize,
        num_queries: usize,
    ) -> Vec<usize> {
        match self {
            FriReductionStrategy::Fixed(reduction_arity_bits) => reduction_arity_bits.to_vec(),
            &FriReductionStrategy::ConstantArityBits(arity_bits, final_poly_bits) => {
                let mut result = Vec::new();
                while degree_bits > final_poly_bits
                    && degree_bits + rate_bits - arity_bits >= cap_height
                {
                    result.push(arity_bits);
                    assert!(degree_bits >= arity_bits);
                    degree_bits -= arity_bits;
                }
                result.shrink_to_fit();
                result
            }
            FriReductionStrategy::MinSize(opt_max_arity_bits) => {
                min_size_arity_bits(degree_bits, rate_bits, num_queries, *opt_max_arity_bits)
            }
        }
    }
}

fn min_size_arity_bits(
    degree_bits: usize,
    rate_bits: usize,
    num_queries: usize,
    opt_max_arity_bits: Option<usize>,
) -> Vec<usize> {
    // 2^4 is the largest arity we see in optimal reduction sequences in practice. For 2^5 to occur
    // in an optimal sequence, we would need a really massive polynomial.
    let max_arity_bits = opt_max_arity_bits.unwrap_or(4);

    let (mut arity_bits, _fri_proof_size) =
        min_size_arity_bits_helper(degree_bits, rate_bits, num_queries, max_arity_bits, vec![]);
    arity_bits.shrink_to_fit();

    arity_bits
}

/// Return `(arity_bits, fri_proof_size)`.
fn min_size_arity_bits_helper(
    degree_bits: usize,
    rate_bits: usize,
    num_queries: usize,
    global_max_arity_bits: usize,
    prefix: Vec<usize>,
) -> (Vec<usize>, usize) {
    let sum_of_arities: usize = prefix.iter().sum();
    let current_layer_bits = degree_bits + rate_bits - sum_of_arities;
    assert!(current_layer_bits >= rate_bits);

    let mut best_arity_bits = prefix.clone();
    let mut best_size = relative_proof_size(degree_bits, rate_bits, num_queries, &prefix);

    // The largest next_arity_bits to search. Note that any optimal arity sequence will be
    // monotonically non-increasing, as a larger arity will shrink more Merkle proofs if it occurs
    // earlier in the sequence.
    let max_arity_bits = prefix
        .last()
        .copied()
        .unwrap_or(global_max_arity_bits)
        .min(current_layer_bits - rate_bits);

    for next_arity_bits in 1..=max_arity_bits {
        let mut extended_prefix = prefix.clone();
        extended_prefix.push(next_arity_bits);

        let (arity_bits, size) = min_size_arity_bits_helper(
            degree_bits,
            rate_bits,
            num_queries,
            max_arity_bits,
            extended_prefix,
        );
        if size < best_size {
            best_arity_bits = arity_bits;
            best_size = size;
        }
    }

    (best_arity_bits, best_size)
}

/// Compute the approximate size of a FRI proof with the given reduction arities. Note that this
/// ignores initial evaluations, which aren't affected by arities, and some other minor
/// contributions. The result is measured in field elements.
fn relative_proof_size(
    degree_bits: usize,
    rate_bits: usize,
    num_queries: usize,
    arity_bits: &[usize],
) -> usize {
    const D: usize = 4;

    let mut current_layer_bits = degree_bits + rate_bits;

    let mut total_elems = 0;
    for arity_bits in arity_bits {
        let arity = 1 << arity_bits;

        // Add neighboring evaluations, which are extension field elements.
        total_elems += (arity - 1) * D * num_queries;
        // Add siblings in the Merkle path.
        total_elems += current_layer_bits * 4 * num_queries;

        current_layer_bits -= arity_bits;
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

    pub reduction_strategy: FriReductionStrategy,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}

impl FriConfig {
    pub fn rate(&self) -> f64 {
        1.0 / ((1 << self.rate_bits) as f64)
    }

    pub fn fri_params(&self, degree_bits: usize, hiding: bool) -> FriParams {
        let reduction_arity_bits = self.reduction_strategy.reduction_arity_bits(
            degree_bits,
            self.rate_bits,
            self.cap_height,
            self.num_query_rounds,
        );
        FriParams {
            config: self.clone(),
            hiding,
            degree_bits,
            reduction_arity_bits,
        }
    }

    pub fn num_cap_elements(&self) -> usize {
        1 << self.cap_height
    }
}

/// FRI parameters, including generated parameters which are specific to an instance size, in
/// contrast to `FriConfig` which is user-specified and independent of instance size.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FriParams {
    /// User-specified FRI configuration.
    pub config: FriConfig,

    /// Whether to use a hiding variant of Merkle trees (where random salts are added to leaves).
    pub hiding: bool,

    /// The degree of the purported codeword, measured in bits.
    pub degree_bits: usize,

    /// The arity of each FRI reduction step, expressed as the log2 of the actual arity.
    /// For example, `[3, 2, 1]` would describe a FRI reduction tree with 8-to-1 reduction, then
    /// a 4-to-1 reduction, then a 2-to-1 reduction. After these reductions, the reduced polynomial
    /// is sent directly.
    pub reduction_arity_bits: Vec<usize>,
}

impl FriParams {
    pub fn total_arities(&self) -> usize {
        self.reduction_arity_bits.iter().sum()
    }

    #[allow(unused)]
    pub(crate) fn max_arity_bits(&self) -> Option<usize> {
        self.reduction_arity_bits.iter().copied().max()
    }

    pub fn lde_bits(&self) -> usize {
        self.degree_bits + self.config.rate_bits
    }

    pub fn lde_size(&self) -> usize {
        1 << self.lde_bits()
    }

    pub fn final_poly_bits(&self) -> usize {
        self.degree_bits - self.total_arities()
    }

    pub fn final_poly_len(&self) -> usize {
        1 << self.final_poly_bits()
    }
}
