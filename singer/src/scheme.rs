use ff_ext::ExtensionField;

// TODO: to be changed to a real PCS scheme.

pub mod prover;
pub mod verifier;

pub type GKRGraphProof<F> = gkr_graph::structs::IOPProof<F>;
pub type GKRGraphProverState<F> = gkr_graph::structs::IOPProverState<F>;
pub type GKRGraphVerifierState<F> = gkr_graph::structs::IOPVerifierState<F>;

pub struct SingerProof<E: ExtensionField> {
    // TODO: restore and implement `commitment_phase_proof` and `open_phase_proof`
    gkr_phase_proof: GKRGraphProof<E>,
}
