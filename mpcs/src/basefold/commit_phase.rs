use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec},
    sumcheck::{
        sum_check_challenge_round, sum_check_first_round, sum_check_first_round_field_type,
        sum_check_last_round,
    },
};
use crate::util::{
    arithmetic::{interpolate2_weights, interpolate_over_boolean_hypercube},
    field_type_index_ext, field_type_iter_ext,
    hash::{write_digest_to_transcript, Hasher},
    log2_strict,
    merkle_tree::MerkleTree,
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use multilinear_extensions::{mle::FieldType, virtual_poly::build_eq_x_r_vec};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, ParallelIterator, ParallelSlice,
};

use super::structure::BasefoldCommitmentWithData;

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
pub fn commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    comm: &BasefoldCommitmentWithData<E>,
    transcript: &mut Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Commit phase");
    #[cfg(feature = "sanity-check")]
    assert_eq!(point.len(), num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = field_type_iter_ext(&comm.get_codewords()[0]).collect_vec();
    let mut running_evals = comm.polynomials_bh_evals[0].clone();

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
    let mut last_sumcheck_message = sum_check_first_round_field_type(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    #[cfg(feature = "sanity-check")]
    assert_eq!(last_sumcheck_message.len(), 3);

    let mut running_evals = match running_evals {
        FieldType::Ext(evals) => evals,
        FieldType::Base(evals) => evals.iter().map(|x| E::from(*x)).collect_vec(),
        _ => unreachable!(),
    };

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    let mut running_tree_inner = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);
        sumcheck_messages.push(last_sumcheck_message);

        let challenge = transcript.get_and_append_challenge(b"commit round");

        // Fold the current oracle for FRI
        let new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
            pp,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge.elements,
        );

        if i > 0 {
            let running_tree = MerkleTree::<E>::from_inner_leaves(
                running_tree_inner,
                FieldType::Ext(running_oracle),
            );
            trees.push(running_tree);
        }

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge.elements);

            // To avoid cloning the running oracle, explicitly separate the
            // computation of Merkle tree inner nodes and the building of
            // entire Merkle tree. First compute the inner nodes without
            // consuming the leaves, so that we can get the challenge.
            // Then the oracle will be used to fold to the next oracle in the next
            // round. After that, this oracle is free to be moved to build the
            // complete Merkle tree.
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle, hasher);
            let running_root = MerkleTree::<E>::root_from_inner(&running_tree_inner);
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root.clone());

            running_oracle = new_running_oracle;
        } else {
            // Clear this so the compiler knows the old value is safe to move.
            last_sumcheck_message = Vec::new();
            running_oracle = Vec::new();
            running_tree_inner = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge.elements);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
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
        end_timer!(sumcheck_timer);
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

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
pub fn simple_batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    batch_coeffs: &[E],
    comm: &BasefoldCommitmentWithData<E>,
    transcript: &mut Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Simple batch commit phase");
    assert_eq!(point.len(), num_vars);
    assert_eq!(comm.num_polys, batch_coeffs.len());
    let prepare_timer = start_timer!(|| "Prepare");
    let mut trees = Vec::with_capacity(num_vars);
    let batch_codewords_timer = start_timer!(|| "Batch codewords");
    let mut running_oracle = comm.batch_codewords(batch_coeffs);
    end_timer!(batch_codewords_timer);
    let mut running_evals = (0..(1 << num_vars))
        .into_par_iter()
        .map(|i| {
            comm.polynomials_bh_evals
                .iter()
                .zip(batch_coeffs)
                .map(|(eval, coeff)| field_type_index_ext(eval, i) * *coeff)
                .sum()
        })
        .collect();
    end_timer!(prepare_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::build eq");
    let mut eq = build_eq_x_r_vec(point);
    end_timer!(build_eq_timer);

    let reverse_bits_timer = start_timer!(|| "Basefold::reverse bits");
    reverse_index_bits_in_place(&mut eq);
    end_timer!(reverse_bits_timer);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut last_sumcheck_message = sum_check_first_round(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    let mut running_tree_inner = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);
        sumcheck_messages.push(last_sumcheck_message);

        let challenge = transcript
            .get_and_append_challenge(b"commit round")
            .elements;

        // Fold the current oracle for FRI
        let new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
            pp,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i > 0 {
            let running_tree = MerkleTree::<E>::from_inner_leaves(
                running_tree_inner,
                FieldType::Ext(running_oracle),
            );
            trees.push(running_tree);
        }

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle, hasher);
            let running_root = MerkleTree::<E>::root_from_inner(&running_tree_inner);
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);
            running_oracle = new_running_oracle;
        } else {
            // Assign a new value to the old running vars so that the compiler
            // knows the old value is safe to move.
            last_sumcheck_message = Vec::new();
            running_oracle = Vec::new();
            running_tree_inner = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut running_evals);
            transcript.append_field_element_exts(&running_evals);
            final_message = running_evals;
            // To avoid the compiler complaining that running_evals is moved.
            running_evals = Vec::new();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = final_message.clone();
                if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
                    reverse_index_bits_in_place(&mut coeffs);
                }
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode(
                    pp,
                    &FieldType::Ext(coeffs),
                );
                let basecode = match basecode {
                    FieldType::Ext(basecode) => basecode,
                    _ => panic!("Should be ext field"),
                };

                let mut new_running_oracle = new_running_oracle;
                reverse_index_bits_in_place(&mut new_running_oracle);
                assert_eq!(basecode, new_running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
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
