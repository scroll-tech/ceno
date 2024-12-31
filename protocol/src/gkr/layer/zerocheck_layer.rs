use ff_ext::ExtensionField;
use subprotocols::{
    sumcheck::{SumcheckClaims, SumcheckProof, SumcheckProverOutput},
    zerocheck::{ZerocheckProverState, ZerocheckVerifierState},
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    utils::{SliceVector, SliceVectorMut},
};

use super::{Layer, LayerWitness};

pub trait ZerocheckLayer<E: ExtensionField> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_points: &[&[E]],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        eqs: &mut [Vec<E>],
        eq_evals_first_part: &mut [E],
        eq_evals_second_part: &mut [E],
    ) -> SumcheckProverOutput<E>;

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigmas: Vec<E>,
        out_points: Vec<&[E]>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer {
    fn prove(
        &self,
        mut wit: LayerWitness<E>,
        out_points: &[&[E]],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        eqs: &mut [Vec<E>],
        eq_evals_first_part: &mut [E],
        eq_evals_second_part: &mut [E],
    ) -> SumcheckProverOutput<E> {
        let prover_state = ZerocheckProverState::new(
            self.exprs.clone(),
            out_points,
            wit.exts.slice_vector_mut(),
            wit.bases.slice_vector(),
            challenges,
            transcript,
            eqs,
            eq_evals_first_part,
            eq_evals_second_part,
        );

        prover_state.prove()
    }

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigmas: Vec<E>,
        out_points: Vec<&[E]>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>> {
        let verifier_state = ZerocheckVerifierState::new(
            sigmas,
            self.exprs.clone(),
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
