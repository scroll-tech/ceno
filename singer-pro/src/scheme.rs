use ff_ext::ExtensionField;
use gkr::structs::GKRInputClaims;

use crate::SingerWiresOutValues;

// TODO: to be changed to a real PCS scheme.
type BatchedPCSProof<F> = Vec<Vec<F>>;
type Commitment<F> = Vec<F>;

pub mod prover;
pub mod verifier;

pub struct CommitPhaseProof<E: ExtensionField> {
    commitments: Vec<Commitment<E>>,
}

pub struct GKRPhaseProverState<E: ExtensionField> {
    proved_input_claims: Vec<GKRInputClaims<E>>,
}

pub struct GKRPhaseVerifierState<E: ExtensionField> {
    proved_input_claims: Vec<GKRInputClaims<E>>,
}

pub type GKRGraphProof<F> = gkr_graph::structs::IOPProof<F>;
pub type GKRGraphProverState<F> = gkr_graph::structs::IOPProverState<F>;
pub type GKRGraphVerifierState<F> = gkr_graph::structs::IOPVerifierState<F>;

pub struct GKRPhaseProof<E: ExtensionField> {
    gkr_proofs: Vec<GKRGraphProof<E>>,
}

pub struct OpenPhaseProof<E: ExtensionField> {
    pcs_proof: BatchedPCSProof<E>,
}

pub struct SingerProof<E: ExtensionField> {
    // commitment_phase_proof: CommitPhaseProof<F>,
    gkr_phase_proof: GKRGraphProof<E>,
    // open_phase_proof: OpenPhaseProof<F>,
    singer_out_evals: SingerWiresOutValues<E::BaseField>,
}
