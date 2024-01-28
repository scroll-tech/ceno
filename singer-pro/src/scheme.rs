use gkr::structs::GKRInputClaims;
use goldilocks::SmallField;

// TODO: to be changed to a real PCS scheme.
type BatchedPCSProof<F> = Vec<Vec<F>>;
type Commitment<F> = Vec<F>;

mod prover;
mod verifier;

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

pub struct GKRPhaseProof<F: SmallField> {
    gkr_proofs: Vec<GKRGraphProof<F>>,
}

pub struct OpenPhaseProof<F: SmallField> {
    pcs_proof: BatchedPCSProof<F>,
}

pub struct ZKVMProof<F: SmallField> {
    commitment_phase_proof: CommitPhaseProof<F>,
    gkr_phase_proof: GKRPhaseProof<F>,
    open_phase_proof: OpenPhaseProof<F>,
}
