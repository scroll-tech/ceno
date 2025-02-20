use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly::VirtualPolynomial;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use transcript::Challenge;

/// An IOP proof is a collections of
/// - messages from prover to verifier at each round through the interactive protocol.
/// - a point that is generated by the transcript for evaluation
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct IOPProof<E: ExtensionField> {
    pub point: Vec<E>,
    pub proofs: Vec<IOPProverMessage<E>>,
}
impl<E: ExtensionField> IOPProof<E> {
    pub fn extract_sum(&self) -> E {
        self.proofs[0].evaluations[0] + self.proofs[0].evaluations[1]
    }
}

/// A message from the prover to the verifier at a given round
/// is a list of evaluations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct IOPProverMessage<E: ExtensionField> {
    pub(crate) evaluations: Vec<E>,
}

/// Prover State of a PolyIOP.
#[derive(Default)]
pub struct IOPProverState<'a, E: ExtensionField> {
    /// sampled randomness given by the verifier
    pub challenges: Vec<Challenge<E>>,
    /// the current round number
    pub(crate) round: usize,
    /// pointer to the virtual polynomial
    pub(crate) poly: VirtualPolynomial<'a, E>,
    /// points with precomputed barycentric weights for extrapolating smaller
    /// degree uni-polys to `max_degree + 1` evaluations.
    pub(crate) extrapolation_aux: Vec<(Vec<E>, Vec<E>)>,
}

/// Prover State of a PolyIOP
pub struct IOPVerifierState<E: ExtensionField> {
    pub(crate) round: usize,
    pub(crate) num_vars: usize,
    pub(crate) max_degree: usize,
    pub(crate) finished: bool,
    /// a list storing the univariate polynomial in evaluation form sent by the
    /// prover at each round
    pub(crate) polynomials_received: Vec<Vec<E>>,
    /// a list storing the randomness sampled by the verifier at each round
    pub(crate) challenges: Vec<Challenge<E>>,
}

/// A SumCheckSubClaim is a claim generated by the verifier at the end of
/// verification when it is convinced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SumCheckSubClaim<E: ExtensionField> {
    /// the multi-dimensional point that this multilinear extension is evaluated
    /// to
    pub point: Vec<Challenge<E>>,
    /// the expected evaluation
    pub expected_evaluation: E,
}
