use super::{
    basecode::encode_rs_basecode,
    sumcheck::{
        sum_check_challenge_round, sum_check_first_round, sum_check_first_round_field_type,
        sum_check_last_round,
    },
};
use crate::util::{
    arithmetic::{interpolate2_weights, interpolate_over_boolean_hypercube},
    field_type_index_ext, field_type_iter_ext,
    hash::{Digest, Hasher},
    log2_strict,
    merkle_tree::MerkleTree,
    transcript::TranscriptWrite,
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;

use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};

use multilinear_extensions::{mle::FieldType, virtual_poly::build_eq_x_r_vec};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator, ParallelSlice,
};

use super::structure::BasefoldCommitmentWithData;

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
pub fn commit_phase<E: ExtensionField>(
    point: &[E],
    comm: &BasefoldCommitmentWithData<E>,
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    log_rate: usize,
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, Vec<Vec<E>>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = field_type_iter_ext(comm.get_codeword()).collect_vec();
    let mut running_evals = comm.bh_evals.clone();

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::open");
    let mut eq = build_eq_x_r_vec(&point);
    end_timer!(build_eq_timer);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut last_sumcheck_message = sum_check_first_round_field_type(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    let mut running_evals = match running_evals {
        FieldType::Ext(evals) => evals,
        FieldType::Base(evals) => evals.iter().map(|x| E::from(*x)).collect_vec(),
        _ => unreachable!(),
    };

    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript
            .write_field_elements_ext(&last_sumcheck_message)
            .unwrap();

        let challenge = transcript.squeeze_challenge();

        // Fold the current oracle for FRI
        running_oracle = basefold_one_round_by_interpolation_weights::<E>(
            &table_w_weights,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);
            let running_tree =
                MerkleTree::<E>::from_leaves(FieldType::Ext(running_oracle.clone()), hasher);
            let running_root = running_tree.root();
            transcript.write_commitment(&running_root).unwrap();

            oracles.push(running_oracle.clone());
            trees.push(running_tree);
        } else {
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut running_evals);
            transcript.write_field_elements_ext(&running_evals).unwrap();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = running_evals.clone();
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = encode_rs_basecode(&coeffs, 1 << log_rate, coeffs.len());
                assert_eq!(basecode.len(), 1);
                let basecode = basecode[0].clone();

                reverse_index_bits_in_place(&mut running_oracle);
                assert_eq!(basecode, running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    return (trees, oracles);
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
pub fn batch_commit_phase<E: ExtensionField>(
    point: &[E],
    comms: &[&BasefoldCommitmentWithData<E>],
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    log_rate: usize,
    coeffs: &[E],
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, Vec<Vec<E>>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Batch Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = vec![E::ZERO; 1 << (num_vars + log_rate)];

    let build_oracle_timer = start_timer!(|| "Basefold build initial oracle");
    // Before the interaction, collect all the polynomials whose num variables match the
    // max num variables
    let running_oracle_len = running_oracle.len();
    comms
        .iter()
        .enumerate()
        .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
        .for_each(|(index, comm)| {
            running_oracle
                .iter_mut()
                .zip_eq(field_type_iter_ext(comm.get_codeword()))
                .for_each(|(r, a)| *r += E::from(a) * coeffs[index]);
        });
    end_timer!(build_oracle_timer);

    let build_oracle_timer = start_timer!(|| "Basefold build initial sumcheck evals");
    // Unlike the FRI part, the sum-check part still follows the original procedure,
    // and linearly combine all the polynomials once for all
    let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
    comms.iter().enumerate().for_each(|(index, comm)| {
        sum_of_all_evals_for_sumcheck
            .par_iter_mut()
            .enumerate()
            .for_each(|(pos, r)| {
                // Evaluating the multilinear polynomial outside of its interpolation hypercube
                // is equivalent to repeating each element in place.
                // Here is the tricky part: the bh_evals are stored in big endian, but we want
                // to align the polynomials to the variable with index 0 before adding them
                // together. So each element is repeated by
                // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                *r += E::from(field_type_index_ext(
                    &comm.bh_evals,
                    pos >> (num_vars - log2_strict(comm.bh_evals.len())),
                )) * coeffs[index]
            });
    });
    end_timer!(build_oracle_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec(&point);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold first round");
    let mut sumcheck_messages = Vec::with_capacity(num_rounds + 1);
    let mut last_sumcheck_message =
        sum_check_first_round(&mut eq, &mut sum_of_all_evals_for_sumcheck);
    sumcheck_messages.push(last_sumcheck_message.clone());
    end_timer!(sumcheck_timer);

    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Batch basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript
            .write_field_elements_ext(&last_sumcheck_message)
            .unwrap();

        let challenge = transcript.squeeze_challenge();

        // Fold the current oracle for FRI
        running_oracle = basefold_one_round_by_interpolation_weights::<E>(
            &table_w_weights,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            sumcheck_messages.push(last_sumcheck_message.clone());
            let running_tree =
                MerkleTree::<E>::from_leaves(FieldType::Ext(running_oracle.clone()), hasher);
            let running_root = running_tree.root();
            transcript.write_commitment(&running_root).unwrap();

            oracles.push(running_oracle.clone());
            trees.push(running_tree);

            // Then merge the rest polynomials whose sizes match the current running oracle
            let running_oracle_len = running_oracle.len();
            comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
                .for_each(|(index, comm)| {
                    running_oracle
                        .iter_mut()
                        .zip_eq(field_type_iter_ext(comm.get_codeword()))
                        .for_each(|(r, a)| *r += E::from(a) * coeffs[index]);
                });
        } else {
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // sum_of_all_evals_for_sumcheck is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut sum_of_all_evals_for_sumcheck);
            transcript
                .write_field_elements_ext(&sum_of_all_evals_for_sumcheck)
                .unwrap();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = sum_of_all_evals_for_sumcheck.clone();
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = encode_rs_basecode(&coeffs, 1 << log_rate, coeffs.len());
                assert_eq!(basecode.len(), 1);
                let basecode = basecode[0].clone();

                reverse_index_bits_in_place(&mut running_oracle);
                assert_eq!(basecode, running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    return (trees, oracles);
}

fn basefold_one_round_by_interpolation_weights<E: ExtensionField>(
    table: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    level_index: usize,
    values: &Vec<E>,
    challenge: E,
) -> Vec<E> {
    let level = &table[level_index];
    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            interpolate2_weights(
                [
                    (E::from(level[i].0), ys[0]),
                    (E::from(-(level[i].0)), ys[1]),
                ],
                E::from(level[i].1),
                challenge,
            )
        })
        .collect::<Vec<_>>()
}
