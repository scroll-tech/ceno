use ff_ext::ExtensionField;

// TODO: to be changed to a real PCS scheme.
type BatchedPCSProof<F> = Vec<Vec<F>>;
type Commitment<F> = Vec<F>;

pub mod prover;
pub mod verifier;

pub struct CommitPhaseProof<E: ExtensionField> {
    commitments: Vec<Commitment<E>>,
}

pub type GKRGraphProof<F> = gkr_graph::structs::IOPProof<F>;
pub type GKRGraphProverState<F> = gkr_graph::structs::IOPProverState<F>;
pub type GKRGraphVerifierState<F> = gkr_graph::structs::IOPVerifierState<F>;

pub struct OpenPhaseProof<E: ExtensionField> {
    pcs_proof: BatchedPCSProof<E>,
}

pub struct SingerProof<E: ExtensionField> {
    // commitment_phase_proof: CommitPhaseProof<F>,
    gkr_phase_proof: GKRGraphProof<E>,
    // open_phase_proof: OpenPhaseProof<F>,
}
