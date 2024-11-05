use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec},
    sumcheck::{sum_check_challenge_round, sum_check_last_round},
};
use crate::{
    basefold::sumcheck::sum_check_first_round,
    util::{
        arithmetic::{interpolate_over_boolean_hypercube, interpolate2_weights},
        field_type_as_ext,
        hash::write_digest_to_transcript,
        log2_strict,
        merkle_tree::MerkleTree,
    },
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use multilinear_extensions::{mle::FieldType, virtual_poly::build_eq_x_r_vec};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::{
    iter::IntoParallelRefMutIterator,
    prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice},
};

use super::structure::BasefoldCommitmentWithData;

pub trait CommitPhaseStrategy<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_running_oracle(
        comms: &[BasefoldCommitmentWithData<E>],
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E>;

    fn initial_running_evals(
        comms: &[BasefoldCommitmentWithData<E>],
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E>;

    fn update_running_oracle(
        comms: &[BasefoldCommitmentWithData<E>],
        running_oracle_len: usize,
        index: usize,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> E;
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
pub fn commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>, CPS: CommitPhaseStrategy<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    coeffs_outer: &[E],
    coeffs_inner: &[E],
    comms: &[BasefoldCommitmentWithData<E>],
    transcript: &mut Transcript<E>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let num_vars = comms.iter().map(|c| c.num_vars).max().unwrap();
    let num_rounds = num_vars - Spec::get_basecode_msg_size_log();
    let timer = start_timer!(|| "Commit phase");
    #[cfg(feature = "sanity-check")]
    assert_eq!(point.len(), num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = &CPS::initial_running_oracle(comms, coeffs_outer, coeffs_inner);
    let mut running_evals = CPS::initial_running_evals(comms, coeffs_outer, coeffs_inner);

    #[cfg(feature = "sanity-check")]
    assert_eq!(
        running_oracle.len(),
        running_evals.len() << Spec::get_rate_log()
    );
    #[cfg(feature = "sanity-check")]
    assert_eq!(running_evals.len(), 1 << num_vars);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::open");
    let mut eq = build_eq_x_r_vec(point);
    end_timer!(build_eq_timer);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut last_sumcheck_message = sum_check_first_round(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    #[cfg(feature = "sanity-check")]
    assert_eq!(last_sumcheck_message.len(), 3);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    for i in 0..num_rounds {
        let round_timer = start_timer!(|| format!("Basefold round {}", i));
        // 1. Prover sends the sum-check message.
        //
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);
        sumcheck_messages.push(last_sumcheck_message);

        // 2. Receives the current round challenge.
        let challenge = transcript
            .get_and_append_challenge(b"commit round")
            .elements;

        // 3. Send the oracle of the folded codeword (or the original message
        //    in the last round).

        // Fold the current oracle for FRI. Note that for some strategies,
        // the oracle may be updated before the folding. The updated values
        // are provided by the `update_running_oracle` callback.
        let mut new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
            pp,
            log2_strict(running_oracle.len()) - 1,
            running_oracle,
            |i| {
                CPS::update_running_oracle(
                    comms,
                    running_oracle.len(),
                    i,
                    coeffs_outer,
                    coeffs_inner,
                )
            },
            challenge,
        );

        if i < num_rounds - 1 {
            // This (sumcheck) actually belongs to the next round (in the paper.)
            // But let's compute it here in advance, because we put the
            // first sumcheck round before the loop, so the loop starts with
            // sending the last sumcheck message.
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);

            // Now commit to the current oracle
            let tree = MerkleTree::<E>::from_leaves_ext(new_running_oracle, 2);
            write_digest_to_transcript(&tree.root(), transcript);
            roots.push(tree.root());
            trees.push(tree);
            // Now, the new running oracle still waits to be folded, but this
            // is going to be in the next round. After that, it will be moved
            // into the Merkle tree. Let's put it in the old running oracle.
            running_oracle = field_type_as_ext(&trees.last().unwrap().leaves()[0]);
        } else {
            // Clear this so the compiler knows the old value is safe to move.
            last_sumcheck_message = Vec::new();
            // Update the running oracle. Although it is not going to fold, this
            // update is needed because some polynomials may have exactly the same
            // size of the final message.
            let running_oracle_len = new_running_oracle.len();
            new_running_oracle
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, x)| {
                    *x += CPS::update_running_oracle(
                        comms,
                        running_oracle_len,
                        i,
                        coeffs_outer,
                        coeffs_inner,
                    )
                });

            // The difference of the last round is that we don't need to
            // compute the sumcheck message to send in the next round,
            // (since there is no next round at all),
            // so now we only apply the folding to the sumcheck booktable,
            // but don't interpolate the degree-two polynomials.
            // So after the last round of sum-check,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial, which is exactly the final message of FRI.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Remember that it has been bit reversed to make the left-right
            // folding into even-odd folding. So we need to reverse it back.
            reverse_index_bits_in_place(&mut running_evals);
            transcript.append_field_element_exts(&running_evals);
            final_message = running_evals;
            // To prevent the compiler from complaining that the value is moved
            running_evals = Vec::new();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = final_message.clone();
                interpolate_over_boolean_hypercube(&mut coeffs);
                if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
                    reverse_index_bits_in_place(&mut coeffs);
                }
                let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode(
                    pp,
                    &FieldType::Ext(coeffs),
                );
                let basecode = match basecode {
                    FieldType::Ext(b) => b,
                    _ => panic!("Should be ext field"),
                };

                reverse_index_bits_in_place(&mut new_running_oracle);
                assert_eq!(basecode, new_running_oracle);
            }
        }
        end_timer!(round_timer);
    }
    end_timer!(timer);

    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        roots,
        final_message,
    })
}

pub(crate) fn basefold_one_round_by_interpolation_weights<
    E: ExtensionField,
    Spec: BasefoldSpec<E>,
>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    level: usize,
    values: &[E],
    additional_values: impl Fn(usize) -> E + Sync,
    challenge: E,
) -> Vec<E> {
    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            let (x0, x1, w) =
                <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs(pp, level, i);
            interpolate2_weights(
                [
                    (x0, ys[0] + additional_values(i << 1)),
                    (x1, ys[1] + additional_values((i << 1) + 1)),
                ],
                w,
                challenge,
            )
        })
        .collect::<Vec<_>>()
}
