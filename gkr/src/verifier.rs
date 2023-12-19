use goldilocks::SmallField;
use transcript::{Challenge, Transcript};

use crate::{
    error::GKRError,
    structs::{
        Circuit, GKRInputClaims, IOPProof, IOPProverPhase1Message, IOPProverPhase2Message,
        IOPProverPhase3Message, IOPVerifierState, Point,
    },
};

impl<F: SmallField> IOPVerifierState<F> {
    pub fn verify(
        circuit: &Circuit<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
        proof: &IOPProof<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<GKRInputClaims<F>, GKRError> {
        todo!()
    }

    fn verifier_init(output_points: &[Point<F>], output_evaluations: &[F]) -> Self {
        todo!()
    }

    /// Verify the items in the i-th layer are copied to deeper layers.
    fn prove_and_update_state_phase1(
        &mut self,
        deeper_points: &[&Point<F>],
        deeper_evaluations: &[F],
        prover_msg: &IOPProverPhase1Message<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase1Message<F> {
        todo!()
    }

    /// Verify the computation in the current layer. The number of terms depends on the gate.
    fn prove_round_and_update_state_phase2(
        &mut self,
        layer_out_point: &Point<F>,
        layer_out_evaluation: F,
        prover_msg: &IOPProverPhase2Message<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase2Message<F> {
        todo!()
    }

    /// Verify the items of the input of the i-th layer are copied from previous layers.
    fn prove_round_and_update_state_phase3(
        &mut self,
        layer_in_points: &[&Point<F>],
        layer_in_evaluations: &[F],
        prover_msg: &IOPProverPhase3Message<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase3Message<F> {
        todo!()
    }
}
