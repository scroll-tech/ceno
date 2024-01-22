use goldilocks::SmallField;
use transcript::Transcript;

use crate::structs::{
    CircuitGraph, CircuitGraphWitness, IOPProof, IOPProverState, TargetEvaluations,
};

impl<F: SmallField> IOPProverState<F> {
    pub fn prove(
        circuit: &CircuitGraph<F>,
        circuit_witness: &CircuitGraphWitness<F>,
        target_evals: &TargetEvaluations<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProof<F> {
        todo!()
    }
}
