use ff_ext::ExtensionField;
use subprotocols::sumcheck::{
    SumcheckClaims, SumcheckProof, SumcheckProverOutput, SumcheckProverState, SumcheckVerifierState,
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    utils::{SliceVector, SliceVectorMut},
};

use super::{Layer, LayerWitness};

pub trait SumcheckLayer<E: ExtensionField> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_points: &[&[E]],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckProverOutput<E>;

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigma: &E,
        out_points: Vec<&[E]>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> SumcheckLayer<E> for Layer {
    fn prove(
        &self,
        mut wit: LayerWitness<E>,
        out_points: &[&[E]],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckProverOutput<E> {
        let prover_state = SumcheckProverState::new(
            self.exprs[0].clone(),
            out_points,
            wit.exts.slice_vector_mut(),
            wit.bases.slice_vector(),
            challenges,
            transcript,
        );

        prover_state.prove()
    }

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigma: &E,
        out_points: Vec<&[E]>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>> {
        let verifier_state = SumcheckVerifierState::new(
            *sigma,
            self.exprs[0].clone(),
            out_points,
            proof,
            challenges,
            transcript,
        );

        verifier_state
            .verify()
            .map_err(|e| BackendError::LayerVerificationFailed(self.name.clone(), e))
    }
}
