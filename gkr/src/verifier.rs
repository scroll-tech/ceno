use goldilocks::SmallField;
use transcript::{Challenge, Transcript};

use crate::{
    error::GKRError,
    structs::{
        Circuit, GKRInputClaims, IOPProof, IOPProverPhase1Message, IOPProverPhase2Message,
        IOPVerifierState, Point,
    },
};

impl<F: SmallField> IOPVerifierState<F> {
    /// Verify process for data parallel circuits.
    pub fn verify_parallel(
        circuit: &Circuit<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
        proof: &IOPProof<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<GKRInputClaims<F>, GKRError> {
        todo!()
    }

    /// Initialize verifying state for data parallel circuits.
    fn verifier_init_parallel(output_points: &[Point<F>], output_evaluations: &[F]) -> Self {
        todo!()
    }

    /// Verify the items in the i-th layer are copied to deeper layers for data
    /// parallel circuits.
    fn verify_and_update_state_phase1_parallel(
        &mut self,
        deeper_points: &[&Point<F>],
        deeper_evaluations: &[F],
        prover_msg: &IOPProverPhase1Message<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase1Message<F> {
        todo!()
    }

    /// Verify the computation in the current layer for data parallel circuits.
    /// The number of terms depends on the gate.
    fn verify_round_and_update_state_phase2_parallel(
        &mut self,
        layer_out_point: &Point<F>,
        layer_out_evaluation: F,
        prover_msg: &IOPProverPhase2Message<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase2Message<F> {
        todo!()
    }
}
