use multilinear_extensions::mle::DenseMultilinearExtension;
use serde::{Deserialize, Serialize};
use transcript::Challenge;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath(Vec<Digest>);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleOpening<F> {
    pub path: MerklePath,
    pub leaf: F,
}

#[allow(unused)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) digest: Digest,
}

/// An IOP proof is a collections of
/// - Prover messages during the interactive phase
/// - The proofs for query phase
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PCSProof<F> {
    pub prover_messages: Vec<PCSProverMessage<F>>,
    pub query_proof: Vec<QueryProof<F>>,
}

#[allow(unused)]
pub(crate) const MAX_DEGREE: usize = 2;
/// A message from the prover to the verifier at a given round.
/// The protocol proceeds as follows:
/// 1. The prover sends h(X) to the verifier, corresponding to the sum-check part
///    of the protocol. It is guaranteed that the summed polynomial is of the form
///    eq(X)\sum beta_i f_i(X), where eq(X) is multilinear, and the committed f_i(X)
///    are also multilinear, so the degree of the summed polynomial is at most 2.
///    That's why MAX_DEGREE is set to 2. Note that the prover does not need to send
///    three evaluations of h(X). The prover only sends h(0) and h(2), and the verifier
///    can compute h(1) by h(1) = v - h(0), where v is the current target sum, then the
///    verifier computes the next target sum by
///    h(alpha) = h(0) * (alpha-1) * (alpha-2) / 2 -
///               h(1) * alpha * (alpha-2) +
///               h(2) * alpha * (alpha-1)
/// 2. The verifier replies with random alpha
/// 3. The prover folds the current committed linearly combined polynomial, computes
///    the commitment to the new polynomial, and sends the new commitment to the verifier.
///    However, if this is the last round, i.e., the number of variables in the new polynomial
///    reaches a threshold, the prover simply sends the polynomial in clear.
///
/// Therefore, in each round, the prover message is either
/// 1. Just the polynomial h(X) in its evaluation form
/// 2. The polynomial h(X) in its evaluation form, and the commitment to the new polynomial
/// 3. The last polynomial in clear
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PCSProverMessage<F> {
    #[default]
    None,
    Initial {
        h0: F, // h(0)
        h2: F, // h(2)
    },
    Normal {
        h0: F,              // h(0)
        h2: F,              // h(2)
        f_comm: Commitment, // Commitment to the current polynomial
    },
    Last(DenseMultilinearExtension<F>), // The polynomial sent in the last round in FRI. It won't be very large.
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryProof<F> {
    pub index: usize,
    pub merkle_openings: MerkleOpening<F>,
}

/// Prover State of the MPCS opening protocol.
#[allow(unused)]
pub struct PCSProverState<F> {
    /// sampled randomness given by the verifier
    pub(crate) challenges: Vec<Challenge<F>>,
    /// evaluation point
    pub(crate) eval_point: Vec<F>,
    /// the current round number
    pub(crate) round: usize,
    /// the prover maintains a multilinear polynomial which is repeatedly folded
    /// during the execution
    pub(crate) poly: DenseMultilinearExtension<F>,
}

/// Verifier State of the MPCS opening protocol.
#[allow(unused)]
pub struct PCSVerifierState<F> {
    pub(crate) round: usize,
    pub(crate) num_vars: usize,
    pub(crate) finished: bool,
    /// a list storing the univariate polynomial in evaluation form sent by the
    /// prover at each round
    pub(crate) polynomials_received: Vec<Vec<F>>,
    /// a list storing the randomness sampled by the verifier at each round
    pub(crate) challenges: Vec<Challenge<F>>,
}
