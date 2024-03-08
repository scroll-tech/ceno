use gkr::structs::GKRInputClaims;
use goldilocks::SmallField;

use crate::SingerWiresOutValues;

// TODO: to be changed to a real PCS scheme.
type BatchedPCSProof<F> = Vec<Vec<F>>;
type Commitment<F> = Vec<F>;

pub mod prover;
pub mod verifier;

pub struct CommitPhaseProof<F: SmallField> {
    commitments: Vec<Commitment<F>>,
}

pub struct GKRPhaseProverState<F: SmallField> {
    proved_input_claims: Vec<GKRInputClaims<F>>,
}

pub struct GKRPhaseVerifierState<F: SmallField> {
    proved_input_claims: Vec<GKRInputClaims<F>>,
}

pub type GKRGraphProof<F> = gkr_graph::structs::IOPProof<F>;
pub type GKRGraphProverState<F> = gkr_graph::structs::IOPProverState<F>;
pub type GKRGraphVerifierState<F> = gkr_graph::structs::IOPVerifierState<F>;

pub struct GKRPhaseProof<F: SmallField> {
    gkr_proofs: Vec<GKRGraphProof<F>>,
}

pub struct OpenPhaseProof<F: SmallField> {
    pcs_proof: BatchedPCSProof<F>,
}

pub struct SingerProof<F: SmallField> {
    // commitment_phase_proof: CommitPhaseProof<F>,
    gkr_phase_proof: GKRGraphProof<F>,
    // open_phase_proof: OpenPhaseProof<F>,
    singer_out_evals: SingerWiresOutValues<F::BaseField>,
}
