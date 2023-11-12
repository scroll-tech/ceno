use ark_std::{end_timer, start_timer};
use ff::PrimeField;
use goldilocks::SmallField;
use multilinear_extensions::virtual_poly::VPAuxInfo;
use transcript::{Challenge, Transcript};

use crate::structs::{IOPProverMessage, IOPVerifierState};

impl<F: SmallField> IOPVerifierState<F> {
    /// Initialize the verifier's state.
    fn verifier_init(index_info: &VPAuxInfo<F>) -> Self {
        let start = start_timer!(|| "sum check verifier init");
        let res = Self {
            round: 1,
            num_vars: index_info.num_variables,
            max_degree: index_info.max_degree,
            finished: false,
            polynomials_received: Vec::with_capacity(index_info.num_variables),
            challenges: Vec::with_capacity(index_info.num_variables),
        };
        end_timer!(start);
        res
    }

    /// Run verifier for the current round, given a prover message.
    ///
    /// Note that `verify_round_and_update_state` only samples and stores
    /// challenges; and update the verifier's state accordingly. The actual
    /// verifications are deferred (in batch) to `check_and_generate_subclaim`
    /// at the last step.
    fn verify_round_and_update_state(
        &mut self,
        prover_msg: &IOPProverMessage<F>,
        transcript: &mut Transcript<F>,
    ) -> Challenge<F> {
        let start =
            start_timer!(|| format!("sum check verify {}-th round and update state", self.round));

        assert!(
            !self.finished,
            "Incorrect verifier state: Verifier is already finished."
        );

        // In an interactive protocol, the verifier should
        //
        // 1. check if the received 'P(0) + P(1) = expected`.
        // 2. set `expected` to P(r)`
        //
        // When we turn the protocol to a non-interactive one, it is sufficient to defer
        // such checks to `check_and_generate_subclaim` after the last round.

        let challenge = transcript.get_and_append_challenge(b"Internal round");
        self.challenges.push(challenge);
        self.polynomials_received
            .push(prover_msg.evaluations.to_vec());

        if self.round == self.num_vars {
            // accept and close
            self.finished = true;
        } else {
            // proceed to the next round
            self.round += 1;
        }

        end_timer!(start);
        challenge
    }
}
