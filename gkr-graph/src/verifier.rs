use goldilocks::SmallField;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{CircuitGraph, CircuitGraphAuxInfo, IOPProof, IOPVerifierState, TargetEvaluations},
};

impl<F: SmallField> IOPVerifierState<F> {
    pub fn verify(
        circuit: &CircuitGraph<F>,
        challenges: &[F],
        target_evals: &TargetEvaluations<F>,
        proof: &IOPProof<F>,
        aux_info: &CircuitGraphAuxInfo,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRGraphError> {
        todo!()
    }
}
