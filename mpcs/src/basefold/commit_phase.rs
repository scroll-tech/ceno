use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec},
    sumcheck::{sum_check_challenge_round, sum_check_last_round},
};
use crate::{
    basefold::sumcheck::sum_check_first_round,
    util::{
        arithmetic::{interpolate2_weights, interpolate_over_boolean_hypercube},
        hash::{write_digest_to_transcript, Hasher},
        log2_strict,
        merkle_tree::{MerkleTree, MerkleTreeDigests},
    },
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use multilinear_extensions::{mle::FieldType, virtual_poly::build_eq_x_r_vec};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice};

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
        running_oracle: &mut Vec<E>,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    );
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
pub fn commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>, CPS: CommitPhaseStrategy<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    coeffs_outer: &[E],
    coeffs_inner: &[E],
    comms: &[BasefoldCommitmentWithData<E>],
    transcript: &mut Transcript<E>,
    hasher: &Hasher<E::BaseField>,
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
    let mut running_oracle = CPS::initial_running_oracle(comms, coeffs_outer, coeffs_inner);
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
    let mut running_tree_inner = MerkleTreeDigests::default();
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

        // Fold the current oracle for FRI
        let mut new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
            pp,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i > 0 {
            // Consume the previous running tree digests and running oracle
            // to assemble the full Merkle tree. This actually belongs to the
            // previous round, but we postpone it to the current round because only
            // now the running oracle of the previous round is no longer used,
            // so we can move its ownership instead of cloning it.
            let running_tree =
                MerkleTree::<E>::new(running_tree_inner, FieldType::Ext(running_oracle));
            trees.push(running_tree);
        }

        if i < num_rounds - 1 {
            // This (sumcheck) actually belongs to the next round (in the paper.)
            // But let's compute it here in advance, because we put the
            // first sumcheck round before the loop, so the loop starts with
            // sending the last sumcheck message.
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);

            // To avoid cloning the running oracle, explicitly separate the
            // computation of Merkle tree inner nodes and the building of
            // entire Merkle tree. First compute the inner nodes without
            // consuming the leaves, so that we can get the challenge.
            // Then the oracle will be used to fold to the next oracle in the next
            // round. After that, this oracle is free to be moved to build the
            // complete Merkle tree.
            running_tree_inner =
                MerkleTreeDigests::<E>::from_leaves_ext(&new_running_oracle, 2, hasher);
            let running_root = running_tree_inner.root();
            // Finally, the prover sends the root (oracle) to the verifier.
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);

            // This new running oracle may not be folded alone. For some
            // strategies, it may be added by some codewords, e.g., from the
            // committed polynomials matching its size.
            CPS::update_running_oracle(comms, &mut new_running_oracle, coeffs_outer, coeffs_inner);

            // Now, the new running oracle still waits to be folded, but this
            // is going to be in the next round. After that, it will be moved
            // into the Merkle tree. Let's put it in the old running oracle.
            running_oracle = new_running_oracle;
        } else {
            // Clear this so the compiler knows the old value is safe to move.
            last_sumcheck_message = Vec::new();
            running_oracle = Vec::new();
            running_tree_inner = MerkleTreeDigests::default();
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

                let mut new_running_oracle = new_running_oracle;
                reverse_index_bits_in_place(&mut new_running_oracle);
                assert_eq!(basecode, new_running_oracle);
            }
        }
        end_timer!(round_timer);
    }
    end_timer!(timer);

    (
        trees,
        BasefoldCommitPhaseProof {
            sumcheck_messages,
            roots,
            final_message,
        },
    )
}

pub(crate) fn basefold_one_round_by_interpolation_weights<
    E: ExtensionField,
    Spec: BasefoldSpec<E>,
>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    level: usize,
    values: &Vec<E>,
    challenge: E,
) -> Vec<E> {
    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            let (x0, x1, w) =
                <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs(pp, level, i);
            interpolate2_weights([(x0, ys[0]), (x1, ys[1])], w, challenge)
        })
        .collect::<Vec<_>>()
}
