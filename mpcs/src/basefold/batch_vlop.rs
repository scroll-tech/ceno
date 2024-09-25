use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::FieldType, virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rand_chacha::rand_core::RngCore;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{
    basefold::{
        commit_phase::basefold_one_round_by_interpolation_weights,
        sumcheck::{sum_check_challenge_round, sum_check_first_round, sum_check_last_round},
    },
    util::{
        arithmetic::{inner_product, interpolate_over_boolean_hypercube},
        field_type_index_ext, field_type_iter_ext,
        hash::{new_hasher, write_digest_to_transcript, Hasher},
        log2_strict,
        merkle_tree::MerkleTree,
        plonky2_util::reverse_index_bits_in_place,
    },
    Error,
};

use super::{
    structure::{BasefoldCommitPhaseProof, BasefoldProof},
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams, EncodingScheme,
};

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug>
    Basefold<E, Spec, Rng>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn batch_open_vlop_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[&[ArcMultilinearExtension<E>]],
        comms: &[super::BasefoldCommitmentWithData<E>],
        point: &[E],
        evals: &[&[E]],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        // Make some basic checks on the inputs
        assert_eq!(polys.len(), comms.len());
        assert_eq!(polys.len(), evals.len());
        polys
            .iter()
            .zip(evals)
            .zip(comms)
            .for_each(|((polys, evals), comm)| {
                assert_eq!(polys.len(), comm.num_polys);
                assert_eq!(evals.len(), comm.num_polys);
                assert!(point.len() >= polys[0].num_vars());
                polys.iter().for_each(|poly| {
                    assert_eq!(poly.num_vars(), comm.num_vars);
                });
            });

        let hasher = new_hasher::<E::BaseField>();
        let num_vars = comms.iter().map(|c| c.num_vars).max().unwrap();
        let max_group_size = polys.iter().map(|polys| polys.len()).max().unwrap();
        let point = &point[..num_vars];

        // Since the polys are batched into two levels, we use two challenge
        // vectors to generate the coefficients for RLC, one for batching the
        // different groups, another for batching the inside polynomials in
        // each group.
        let batch_size_log_outer = polys.len().next_power_of_two().ilog2() as usize;
        let batch_size_log_inner = max_group_size.next_power_of_two().ilog2() as usize;
        let t_outer = (0..batch_size_log_outer)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs outer")
                    .elements
            })
            .collect::<Vec<_>>();
        let t_inner = (0..batch_size_log_inner)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs inner")
                    .elements
            })
            .collect::<Vec<_>>();
        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt_outer = build_eq_x_r_vec(&t_outer)[..polys.len()].to_vec();
        let eq_xt_inner = build_eq_x_r_vec(&t_inner)[..max_group_size].to_vec();
        // Now both the prover and the verifier can compute the rlc of the
        // evaluations using `eq_xt`. However, they don't need to do this
        // explicitly.
        // let evals_flatten = evals
        //     .iter()
        //     .flat_map(|e| e.iter())
        //     .cloned()
        //     .collect::<Vec<_>>();
        // let target_sum = inner_product(&evals_flatten, &eq_xt);

        let (trees, commit_phase_proof) = batch_vlop_commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            comms,
            transcript,
            num_vars - Spec::get_basecode_msg_size_log(),
            &eq_xt_outer,
            &eq_xt_inner,
            &hasher,
        );

        unimplemented!();
    }

    pub(crate) fn batch_verify_vlop_inner(
        vp: &BasefoldVerifierParams<E, Spec>,
        comms: &[BasefoldCommitment<E>],
        point: &[E],
        evals: &[&[E]],
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        // Make some basic checks on the inputs
        assert_eq!(evals.len(), comms.len());
        comms.iter().zip(evals).for_each(|(comm, evals)| {
            if let Some(num_polys) = comm.num_polys.as_ref() {
                assert_eq!(num_polys, &evals.len());
            }
            if let Some(num_vars) = comm.num_vars.as_ref() {
                assert!(&point.len() >= num_vars);
            }
        });

        let max_group_size = evals.iter().map(|evals| evals.len()).max().unwrap();
        // Since the polys are batched into two levels, we use two challenge
        // vectors to generate the coefficients for RLC, one for batching the
        // different groups, another for batching the inside polynomials in
        // each group.
        let batch_size_log_outer = evals.len().next_power_of_two().ilog2() as usize;
        let batch_size_log_inner = max_group_size.next_power_of_two().ilog2() as usize;
        let t_outer = (0..batch_size_log_outer)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs outer")
                    .elements
            })
            .collect::<Vec<_>>();
        let t_inner = (0..batch_size_log_inner)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs inner")
                    .elements
            })
            .collect::<Vec<_>>();
        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt_outer = build_eq_x_r_vec(&t_outer)[..evals.len()].to_vec();
        let eq_xt_inner = build_eq_x_r_vec(&t_inner)[..max_group_size].to_vec();
        unimplemented!();
    }
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
fn batch_vlop_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    comms: &[BasefoldCommitmentWithData<E>],
    transcript: &mut Transcript<E>,
    num_rounds: usize,
    coeffs_outer: &[E],
    coeffs_inner: &[E],
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let num_vars = comms.iter().map(|c| c.num_vars).max().unwrap();
    let timer = start_timer!(|| "Batch vlop Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = vec![E::ZERO; 1 << (num_vars + Spec::get_rate_log())];

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
                .par_iter_mut()
                .zip_eq(comm.par_iter_batch_codewords(coeffs_inner))
                .for_each(|(r, a)| *r += a * coeffs_outer[index]);
        });
    end_timer!(build_oracle_timer);

    let build_oracle_timer = start_timer!(|| "Basefold build initial sumcheck evals");
    // Unlike the FRI part, the sum-check part still follows the original procedure,
    // and linearly combine all the polynomials once for all
    let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
    comms.iter().enumerate().for_each(|(index_outer, comm)| {
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
                comm.polynomials_bh_evals
                    .iter()
                    .enumerate()
                    .for_each(|(index_inner, poly)| {
                        *r += field_type_index_ext(poly, pos >> (num_vars - comm.num_vars))
                            * coeffs_outer[index_outer]
                            * coeffs_inner[index_inner]
                    });
            });
    });
    end_timer!(build_oracle_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec(point);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold first round");
    let mut sumcheck_messages = Vec::with_capacity(num_rounds + 1);
    let mut last_sumcheck_message =
        sum_check_first_round(&mut eq, &mut sum_of_all_evals_for_sumcheck);
    sumcheck_messages.push(last_sumcheck_message.clone());
    end_timer!(sumcheck_timer);

    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    let mut running_tree_inner = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Batch basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);

        let challenge = transcript
            .get_and_append_challenge(b"commit round")
            .elements;

        // Fold the current oracle for FRI
        let mut new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
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
                sum_check_challenge_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            sumcheck_messages.push(last_sumcheck_message.clone());
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle, hasher);
            let running_root = MerkleTree::<E>::root_from_inner(&running_tree_inner);
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);

            // Then merge the rest polynomials whose sizes match the current running oracle
            let running_oracle_len = new_running_oracle.len();
            comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
                .for_each(|(index, comm)| {
                    new_running_oracle
                        .par_iter_mut()
                        .zip_eq(comm.par_iter_batch_codewords(coeffs_inner))
                        .for_each(|(r, a)| *r += a * coeffs_outer[index]);
                });
            running_oracle = new_running_oracle;
        } else {
            // Clear the value so the compiler does not think they are moved
            running_oracle = Vec::new();
            running_tree_inner = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // sum_of_all_evals_for_sumcheck is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut sum_of_all_evals_for_sumcheck);
            transcript.append_field_element_exts(&sum_of_all_evals_for_sumcheck);
            final_message = sum_of_all_evals_for_sumcheck;
            // To prevent the compiler from complaining that the value is moved
            sum_of_all_evals_for_sumcheck = Vec::new();

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
                    FieldType::Ext(x) => x,
                    _ => panic!("Expected ext field"),
                };

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
