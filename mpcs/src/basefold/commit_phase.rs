use std::sync::Arc;

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec},
    sumcheck::{
        sum_check_challenge_round, sum_check_first_round, sum_check_first_round_field_type,
        sum_check_last_round,
    },
};
use crate::{
    basefold::virtual_polys::VirtualPolynomials,
    util::{
        arithmetic::{interpolate_over_boolean_hypercube, interpolate2_weights},
        field_type_index_ext, field_type_iter_ext,
        hash::{hash_two_digests, write_digest_to_transcript},
        log2_strict,
        merkle_tree::MerkleTree,
    },
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use poseidon::digest::Digest;
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::{
    structs::IOPProverStateV2,
    util::{AdditiveVec, merge_sumcheck_polys_v3},
};
use transcript::{Challenge, Transcript};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType, IntoMLE},
    util::max_usable_threads,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::ArcMultilinearExtension,
};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice,
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
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle);
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

    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        roots,
        final_message,
    })
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
pub fn batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    comms: &[BasefoldCommitmentWithData<E>],
    transcript: &mut Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
    coeffs: &[E],
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Batch Commit phase");
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
                .iter_mut()
                .zip_eq(field_type_iter_ext(&comm.get_codewords()[0]))
                .for_each(|(r, a)| *r += a * coeffs[index]);
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
                *r += field_type_index_ext(
                    &comm.polynomials_bh_evals[0],
                    pos >> (num_vars - log2_strict(comm.polynomials_bh_evals[0].len())),
                ) * coeffs[index]
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
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle);
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
                        .iter_mut()
                        .zip_eq(field_type_iter_ext(&comm.get_codewords()[0]))
                        .for_each(|(r, a)| *r += a * coeffs[index]);
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
    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        roots,
        final_message,
    })
}

#[allow(clippy::too_many_arguments)]
fn basefold_one_round<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    prover_states: &mut Vec<IOPProverStateV2<'_, E>>,
    challenge: Option<Challenge<E>>,
    sumcheck_messages: &mut Vec<Vec<E>>,
    transcript: &mut Transcript<E>,
    running_oracle: Option<&[E]>,
    num_threads: usize,
    trees: &mut Vec<MerkleTree<E>>,
    roots: &mut Vec<Digest<E::BaseField>>,
    is_last_round: bool,
) -> Option<Challenge<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let prover_msgs = prover_states
        .par_iter_mut()
        .map(|prover_state| {
            IOPProverStateV2::prove_round_and_update_state(prover_state, &challenge)
        })
        .collect::<Vec<_>>();

    // for each round, we must collect #SIZE prover message
    let evaluations: AdditiveVec<E> =
        prover_msgs
            .into_iter()
            .fold(AdditiveVec::new(3), |mut acc, prover_msg| {
                acc += AdditiveVec(prover_msg.evaluations);
                acc
            });

    transcript.append_field_element_exts(&evaluations.0);
    sumcheck_messages.push(evaluations.0);

    let next_challenge = transcript.get_and_append_challenge(b"commit round");
    // println!(
    //     "evaluations {:?}, next_challenge {:?}",
    //     sumcheck_messages.last(),
    //     next_challenge
    // );

    let running_oracle = trees
        .last()
        .map(|last_tree| match &last_tree.leaves()[0] {
            FieldType::Ext(running_oracle) => running_oracle.as_slice(),
            _ => unimplemented!(".."),
        })
        .unwrap_or_else(|| running_oracle.expect("illegal input"));
    let running_oracle_len = running_oracle.len();
    let next_running_oracles = running_oracle
        .par_chunks_exact(running_oracle_len.div_ceil(num_threads))
        .enumerate()
        .flat_map(|(i, running_oracle)| {
            let offset = i * running_oracle.len() / 2;
            basefold_one_round_by_interpolation_weights_seq::<E, Spec>(
                pp,
                offset,
                log2_strict(running_oracle_len) - 1,
                running_oracle,
                next_challenge.elements,
            )
        })
        .collect::<Vec<_>>();

    // merkelize new leafs
    let next_running_tree_inners = next_running_oracles
        .par_chunks_exact(next_running_oracles.len().div_ceil(num_threads))
        .map(|next_running_oracle| MerkleTree::<E>::compute_inner_ext_seq(next_running_oracle))
        .collect::<Vec<_>>();

    // merge #threads running_tree_inners into one running tree inner by single thread
    // TODO optimize to be more memory efficiency
    let next_running_tree_inner = {
        let mut incompleted_running_tree_inner = next_running_tree_inners
            .into_iter()
            .reduce(|mut tree_a, tree_b| {
                tree_a
                    .iter_mut()
                    .zip(tree_b)
                    .for_each(|(layer_a, layer_b)| {
                        layer_a.extend(layer_b);
                    });
                tree_a
            })
            .unwrap();
        for i in incompleted_running_tree_inner.len()
            ..(incompleted_running_tree_inner.len() + log2_strict(num_threads))
        {
            let oracle = incompleted_running_tree_inner[i - 1]
                .chunks_exact(2)
                .map(|ys| hash_two_digests(&ys[0], &ys[1]))
                .collect::<Vec<_>>();

            incompleted_running_tree_inner.push(oracle);
        }
        incompleted_running_tree_inner
    };

    let next_running_tree = MerkleTree::<E>::from_inner_leaves(
        next_running_tree_inner,
        FieldType::Ext(next_running_oracles),
    );
    if !is_last_round {
        let running_root = next_running_tree.root();
        write_digest_to_transcript(&running_root, transcript);
        roots.push(running_root);
    }
    trees.push(next_running_tree);

    Some(next_challenge)
}

fn sumcheck_push_last_variable<E: ExtensionField>(
    prover_states: &mut Vec<IOPProverStateV2<'_, E>>,
    p: Challenge<E>,
    max_num_variables: usize,
) {
    prover_states.iter_mut().for_each(|prover_state| {
        prover_state.challenges.push(p);
        // fix last challenge to collect final evaluation
        prover_state
            .poly
            .flattened_ml_extensions
            .iter_mut()
            .for_each(|mle| {
                if max_num_variables == 1 {
                    // first time fix variable should be create new instance
                    if mle.num_vars() > 0 {
                        *mle = mle.fix_variables(&[p.elements]).into();
                    } else {
                        *mle = Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                            0,
                            mle.get_base_field_vec().to_vec(),
                        ))
                    }
                } else {
                    let mle = Arc::get_mut(mle).unwrap();
                    if mle.num_vars() > 0 {
                        mle.fix_variables_in_place(&[p.elements]);
                    }
                }
            });
    });
}

/// we expect each thread at least take 4 num of sumcheck variables
/// return optimal num threads to run sumcheck
pub fn optimal_sumcheck_threads(num_vars: usize) -> usize {
    let expected_max_threads = max_usable_threads();
    let min_numvar_per_thread = 2;
    if num_vars <= min_numvar_per_thread {
        1
    } else {
        (1 << (num_vars - min_numvar_per_thread)).min(expected_max_threads)
    }
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
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Simple batch commit phase");
    assert_eq!(point.len(), num_vars);
    assert_eq!(comm.num_polys, batch_coeffs.len());
    assert!(num_rounds <= num_vars);
    let prepare_timer = start_timer!(|| "Prepare");
    let mut trees: Vec<MerkleTree<E>> = Vec::with_capacity(num_vars);
    let batch_codewords_timer = start_timer!(|| "Batch codewords");
    let running_oracle = comm.batch_codewords(batch_coeffs);
    end_timer!(batch_codewords_timer);

    let running_evals: ArcMultilinearExtension<_> = (0..(1 << num_vars))
        .into_par_iter()
        .with_min_len(64)
        .map(|i| {
            comm.polynomials_bh_evals
                .iter()
                .zip(batch_coeffs)
                .map(|(eval, coeff)| field_type_index_ext(eval, i) * *coeff)
                .sum::<E>()
        })
        .collect::<Vec<_>>()
        .into_mle()
        .into();
    end_timer!(prepare_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::build eq");
    let mut eq = build_eq_x_r_vec(point);
    end_timer!(build_eq_timer);

    let reverse_bits_timer = start_timer!(|| "Basefold::reverse bits");
    reverse_index_bits_in_place(&mut eq);
    let eq: ArcMultilinearExtension<_> = eq.into_mle().into();
    end_timer!(reverse_bits_timer);

    //    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");

    let num_threads = optimal_sumcheck_threads(num_vars);
    // println!(
    //     "running_evals.num_vars() {}, {num_threads} ",
    //     running_evals.num_vars()
    // );
    let mut polys = VirtualPolynomials::new(num_threads, num_vars);

    polys.add_mle_list(vec![&eq, &running_evals], E::ONE);
    let batched_polys = polys.get_batched_polys();

    // let mut last_sumcheck_message = sum_check_first_round(&mut eq, &mut running_evals);
    //  end_timer!(sumcheck_timer);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);

    let mut prover_states = batched_polys
        .into_par_iter()
        .map(|poly| {
            IOPProverStateV2::prover_init_with_extrapolation_aux(poly, vec![(vec![], vec![])])
        })
        .collect::<Vec<_>>();
    let mut challenge = None;

    // eg1 num_vars = 10, thread = 8, log(thread) = 3
    // => per inner max => 10 - 3 = 7 vars
    // => need to choose min(num_round, 7)

    // eg2 num_vars = 3, thread = 16, log(thread) = 4
    // => per inner max => 10 - 3 = 7 vars
    // => need to choose min(num_round, 7)
    for i in 0..num_rounds.min(num_vars - log2_strict(num_threads)) {
        // println!("prover inner round {i}");
        challenge = basefold_one_round::<E, Spec>(
            pp,
            &mut prover_states,
            challenge,
            &mut sumcheck_messages,
            transcript,
            if i == 0 { Some(&running_oracle) } else { None },
            num_threads,
            &mut trees,
            &mut roots,
            i == num_rounds - 1,
        );
    }

    // last round: push challenge and bind last variable for all prover_states
    if let Some(p) = challenge {
        sumcheck_push_last_variable(
            &mut prover_states,
            p,
            num_rounds.min(num_vars - log2_strict(num_threads)),
        );
    }

    // deal with log(#thread) basefold rounds
    let poly = merge_sumcheck_polys_v3(&prover_states);
    let mut prover_states = vec![IOPProverStateV2::prover_init_with_extrapolation_aux(
        poly,
        vec![(vec![], vec![])],
    )];

    let mut challenge = None;

    for i in 0..num_rounds.saturating_sub(num_vars - log2_strict(num_threads)) {
        // println!("prover outer round {i}");
        challenge = basefold_one_round::<E, Spec>(
            pp,
            &mut prover_states,
            challenge,
            &mut sumcheck_messages,
            transcript,
            None,
            1,
            &mut trees,
            &mut roots,
            i == num_rounds.saturating_sub(num_vars - log2_strict(num_threads)) - 1,
        );
    }

    // last round: push challenge and bind last variable for all prover_states
    if let Some(p) = challenge {
        // num_rounds doens't matter, just need to be > 1 to assure fix variable in place
        sumcheck_push_last_variable(&mut prover_states, p, num_rounds);
    }

    let mut running_evals = prover_states[0].get_mle_final_evaluations();
    // skip first half which is eq evaluation
    let mut running_evals = running_evals.split_off(running_evals.len() / 2);

    reverse_index_bits_in_place(&mut running_evals);
    transcript.append_field_element_exts(&running_evals);
    let final_message = running_evals;

    if cfg!(feature = "sanity-check") {
        // If the prover is honest, in the last round, the running oracle
        // on the prover side should be exactly the encoding of the folded polynomial.

        let mut coeffs = final_message.clone();
        if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
            reverse_index_bits_in_place(&mut coeffs);
        }
        interpolate_over_boolean_hypercube(&mut coeffs);
        let basecode =
            <Spec::EncodingScheme as EncodingScheme<E>>::encode(pp, &FieldType::Ext(coeffs));
        let basecode = match basecode {
            FieldType::Ext(basecode) => basecode,
            _ => panic!("Should be ext field"),
        };

        match &trees.last().unwrap().leaves()[0] {
            FieldType::Ext(running_oracle) => {
                let mut running_oracle = running_oracle.to_vec();
                reverse_index_bits_in_place(&mut running_oracle);
                assert_eq!(basecode, running_oracle);
            }
            _ => unimplemented!(".."),
        }
    }

    // println!(
    //     "sumcheck_messages len() {} roots.len {}, final_message {:?}",
    //     sumcheck_messages.len(),
    //     roots.len(),
    //     final_message
    // );
    end_timer!(timer);
    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        roots,
        final_message,
    })
}

fn basefold_one_round_by_interpolation_weights<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    level: usize,
    values: &[E],
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

fn basefold_one_round_by_interpolation_weights_seq<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    offset: usize,
    level: usize,
    values: &[E],
    challenge: E,
) -> Vec<E> {
    values
        .chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            let i = offset + i;
            let (x0, x1, w) =
                <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs(pp, level, i);
            interpolate2_weights([(x0, ys[0]), (x1, ys[1])], w, challenge)
        })
        .collect::<Vec<_>>()
}
