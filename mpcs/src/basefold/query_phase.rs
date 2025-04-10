use std::{cmp::Reverse, collections::BTreeMap, slice};

use crate::{
    basefold::structure::{CircuitIndexMeta, MerkleTreeExt},
    util::merkle_tree::poseidon2_merkle_tree,
};
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    field::dot_product,
    matrix::{Dimensions, dense::RowMajorMatrix},
    util::log2_strict_usize,
};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;

use crate::basefold::structure::QueryOpeningProofs;

use super::{
    Digest,
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldSpec},
};

pub fn batch_query_phase<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    fixed_comms: &BasefoldCommitmentWithWitness<E>,
    witin_comms: &BasefoldCommitmentWithWitness<E>,
    trees: &[MerkleTreeExt<E>],
    num_verifier_queries: usize,
) -> QueryOpeningProofs<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();

    // Transform the challenge queries from field elements into integers
    let log2_witin_max_codeword_size = log2_strict_usize(witin_comms.max_codeword_size());
    let log2_fixed_max_codeword_size = log2_strict_usize(fixed_comms.max_codeword_size());
    let queries: Vec<_> = transcript.sample_bits_and_append_vec(
        b"query indices",
        num_verifier_queries,
        log2_witin_max_codeword_size,
    );

    queries
        .iter()
        .map(|idx| {
            let witin_base_opening = {
                // extract the even part of `idx`
                // ---------------------------------
                // the oracle values are committed in a row-bit-reversed format.
                // rounding `idx` to an even value is equivalent to retrieving the "left-hand" side `j` index
                // in the original (non-row-bit-reversed) format.
                //
                // however, since `p_d[j]` and `p_d[j + n_{d-1}]` are already concatenated in the same merkle leaf,
                // we can simply mask out the least significant bit (lsb) by performing a right shift by 1.
                let idx = idx >> 1;
                let (values, proof) = mmcs.open_batch(idx, &witin_comms.codeword);
                (values, proof)
            };

            let fixed_base_opening = {
                // follow same rule as `witin_base_opening`
                let idx = if log2_witin_max_codeword_size > log2_fixed_max_codeword_size {
                    idx >> (log2_witin_max_codeword_size - log2_fixed_max_codeword_size)
                } else {
                    idx << (log2_fixed_max_codeword_size - log2_witin_max_codeword_size)
                };
                let idx = idx >> 1;
                let (values, proof) = mmcs.open_batch(idx, &fixed_comms.codeword);
                (values, proof)
            };

            // this is equivalent with "idx = idx % n_{d-1}" operation in non row bit reverse format
            let idx = idx >> 1;
            let (_, opening_ext) = trees.iter().fold((idx, vec![]), |(idx, mut proofs), tree| {
                // differentiate interpolate to left or right position at next layer
                let is_interpolate_to_right_index = (idx & 1) == 1;
                // mask the least significant bit (LSB) for the same reason as above:
                // 1. we only need the even part of the index.
                // 2. since even and odd parts are concatenated in the same leaf,
                //    the overall merkle tree height is effectively halved,
                //    so we divide by 2.
                let (mut values, proof) = mmcs_ext.open_batch(idx >> 1, tree);
                let leafs = values.pop().unwrap();
                debug_assert_eq!(leafs.len(), 2);
                let sibling = leafs[(!is_interpolate_to_right_index) as usize];
                proofs.push((sibling, proof));
                (idx >> 1, proofs)
            });
            (witin_base_opening, fixed_base_opening, opening_ext)
        })
        .collect_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    max_num_var: usize,
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    final_message: &[Vec<E>],
    batch_coeffs: &[E],
    queries: &QueryOpeningProofs<E>,
    fixed_comm: &BasefoldCommitment<E>,
    witin_comm: &BasefoldCommitment<E>,
    circuit_meta_map: &BTreeMap<usize, CircuitIndexMeta>,
    commits: &[Digest<E>],
    fold_challenges: &[E],
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let encode_span = entered_span!("encode_final_codeword");
    let final_codeword = <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(
        vp,
        RowMajorMatrix::new(
            (0..final_message[0].len())
                .map(|j| final_message.iter().map(|row| row[j]).sum())
                .collect_vec(),
            1,
        ),
    );
    exit_span!(encode_span);

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();
    let check_queries_span = entered_span!("check_queries");

    // an vector with same length as circuit_meta_map, which is sorted by num_var from largest to low
    // vector keep circuit information, so we can fetch respective circuit in constant time
    let folding_sorted_order = circuit_meta_map
        .iter()
        .sorted_by_key(|(circuit_index, CircuitIndexMeta { witin_num_vars, .. })| {
            Reverse(witin_num_vars)
        })
        .map(|(circuit_index, CircuitIndexMeta { witin_num_vars, .. })| {
            (witin_num_vars, circuit_index)
        })
        .collect_vec();
    izip!(indices, queries).for_each(
        |(
            idx,
            (
                (witin_commit_leafs, witin_commit_proof),
                (fixed_commit_leafs, fixed_commit_proof),
                opening_ext,
            ),
        )| {
            // verify base oracle query proof
            // refer to prover documentation for the reason of right shift by 1
            let mut idx = idx >> 1;

            let (witin_dimentions, fixed_dimentions) =
                get_base_oracle_dimentions::<E, Spec>(circuit_meta_map);
            // verify witness
            mmcs.verify_batch(
                &witin_comm.commit,
                &witin_dimentions,
                idx,
                witin_commit_leafs,
                witin_commit_proof,
            )
            .expect("verify witin commit batch failed");
            // verify fixed
            mmcs.verify_batch(
                &fixed_comm.commit,
                &fixed_dimentions,
                idx,
                fixed_commit_leafs,
                fixed_commit_proof,
            )
            .expect("verify fixed commit batch failed");

            let mut witin_commit_leafs_iter = witin_commit_leafs.iter();
            let mut fixed_commit_leafs_iter = fixed_commit_leafs.iter();
            let mut batch_coeffs_iter = batch_coeffs.iter();

            // circuit_index -> (lo, hi)
            // TODO use pure vector for it instead of BTreeMap
            let base_oracle_lo_hi = circuit_meta_map
                .iter()
                .map(
                    |(
                        circuit_index,
                        CircuitIndexMeta {
                            witin_num_vars,
                            witin_num_polys,
                            fixed_num_vars,
                            fixed_num_polys,
                        },
                    )| {
                        let (lo, hi) = witin_commit_leafs_iter
                            .next()
                            .into_iter()
                            .map(|leafs| (leafs, *witin_num_polys))
                            .chain(
                                (*fixed_num_vars > 0)
                                    .then(|| {
                                        (fixed_commit_leafs_iter.next().unwrap(), *fixed_num_polys)
                                    })
                                    .into_iter(),
                            )
                            .map(|(leafs, num_polys)| {
                                let batch_coeffs = batch_coeffs_iter
                                    .by_ref()
                                    .take(num_polys)
                                    .copied()
                                    .collect_vec();
                                let (lo, hi): (&[E::BaseField], &[E::BaseField]) =
                                    leafs.split_at(leafs.len() / 2);
                                (
                                    dot_product::<E, _, _>(
                                        batch_coeffs.iter().copied(),
                                        lo.iter().copied(),
                                    ),
                                    dot_product::<E, _, _>(
                                        batch_coeffs.iter().copied(),
                                        hi.iter().copied(),
                                    ),
                                )
                            })
                            // fold witin/fixed lo, hi together because they share the same num_vars
                            .reduce(|(lo_wit, hi_wit), (lo_fixed, hi_fixed)| {
                                (lo_wit + lo_fixed, hi_wit + hi_fixed)
                            })
                            .expect("unreachable");
                        (*circuit_index, (lo, hi))
                    },
                )
                .collect::<BTreeMap<_, _>>();
            debug_assert_eq!(folding_sorted_order.len(), base_oracle_lo_hi.len());
            debug_assert!(witin_commit_leafs_iter.next().is_none());
            debug_assert!(fixed_commit_leafs_iter.next().is_none());
            debug_assert!(batch_coeffs_iter.next().is_none());

            // fold and query
            let mut cur_num_var = max_num_var;
            let rounds = cur_num_var
                - <Spec::EncodingScheme as EncodingScheme<E>>::get_basecode_msg_size_log()
                - 1;
            let n_d_next = 1
                << (cur_num_var + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1);
            debug_assert_eq!(rounds, fold_challenges.len() - 1);
            debug_assert_eq!(rounds, commits.len(),);
            debug_assert_eq!(rounds, opening_ext.len(),);

            // first folding challenge
            let r = fold_challenges.first().unwrap();

            let mut folding_sorted_order_iter = folding_sorted_order.iter();
            // take first batch which num_vars match max_num_var to initial fold value
            let mut folded = folding_sorted_order_iter
                .by_ref()
                .peeking_take_while(|(num_vars, _)| **num_vars == cur_num_var)
                .map(|(num_vars, circuit_index)| {
                    let (lo, hi) = &base_oracle_lo_hi[circuit_index];

                    let coeff =
                        <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
                            vp,
                            cur_num_var
                                + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log()
                                - 1,
                        )[idx];
                    let (lo, hi) = ((*lo + *hi).halve(), (*lo - *hi) * coeff);
                    lo + (hi - lo) * *r
                })
                .sum::<E>();

            let mut n_d_i = n_d_next;
            for ((pi_comm, r), (leaf, proof)) in commits
                .iter()
                .zip_eq(fold_challenges.iter().skip(1))
                .zip_eq(opening_ext)
            {
                cur_num_var -= 1;

                let is_interpolate_to_right_index = (idx & 1) == 1;
                let new_involved_oracles = folding_sorted_order_iter
                    .by_ref()
                    .peeking_take_while(|(num_vars, _)| **num_vars == cur_num_var)
                    .map(|(_, circuit_index)| {
                        let (lo, hi) = &base_oracle_lo_hi[circuit_index];
                        if is_interpolate_to_right_index {
                            *hi
                        } else {
                            *lo
                        }
                    })
                    .sum::<E>();

                let mut leafs = vec![*leaf; 2];
                leafs[is_interpolate_to_right_index as usize] = folded + new_involved_oracles;
                idx >>= 1;
                mmcs_ext
                    .verify_batch(
                        pi_comm,
                        &[Dimensions {
                            width: 2,
                            // width is 2, thus height divide by 2 via right shift
                            height: n_d_i >> 1,
                        }],
                        idx,
                        slice::from_ref(&leafs),
                        proof,
                    )
                    .expect("verify failed");
                let coeff =
                    <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
                        vp,
                        log2_strict_usize(n_d_i) - 1,
                    )[idx];
                debug_assert_eq!(
                    <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
                        vp,
                        log2_strict_usize(n_d_i) - 1,
                    )
                    .len(),
                    n_d_i >> 1
                );
                let (left, right) = (leafs[0], leafs[1]);
                let (lo, hi) = ((left + right).halve(), (left - right) * coeff);
                folded = lo + (hi - lo) * *r;
                n_d_i >>= 1;
            }
            debug_assert!(folding_sorted_order_iter.next().is_none());
            // assert!(
            //     final_codeword.values[idx] == folded,
            //     "final_codeword.values[idx] value {:?} != folded {:?}",
            //     final_codeword.values[idx],
            //     folded
            // );
        },
    );
    exit_span!(check_queries_span);
}

#[allow(clippy::too_many_arguments)]
pub fn simple_batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    _indices: &[usize],
    _vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    _queries: &QueryOpeningProofs<E>,
    _sum_check_messages: &[Vec<E>],
    _fold_challenges: &[E],
    _batch_coeffs: &[E],
    _num_rounds: usize,
    _num_vars: usize,
    _final_message: &[E],
    _roots: &[Digest<E>],
    _comm: &BasefoldCommitment<E>,
    _partial_eq: &[E],
    _evals: &[E],
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    unimplemented!()
    // let timer = start_timer!(|| "Verifier query phase");
    // let num_polys = evals.len();

    // let encode_timer = start_timer!(|| "Encode final codeword");
    // let final_codeword = <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(
    //     vp,
    //     RowMajorMatrix::new(final_message.to_vec(), 1),
    // );
    // end_timer!(encode_timer);

    // let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    // let mmcs = poseidon2_merkle_tree::<E>();

    // let span = entered_span!("check queries");
    // izip!(indices, queries).for_each(|(idx, ((commit_leafs, commit_proof), opening_ext))| {
    //     // refer to prover documentation for the reason of right shift by 1
    //     let idx = idx >> 1;
    //     mmcs.verify_batch(
    //         &comm.pi_d_digest,
    //         &[Dimensions {
    //             // width size is double num_polys due to leaf + right leafs are concat
    //             width: num_polys * 2,
    //             height: 1
    //                 << (num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1),
    //         }],
    //         idx,
    //         slice::from_ref(commit_leafs),
    //         commit_proof,
    //     )
    //     .expect("verify batch failed");
    //     let (left, right) = commit_leafs.split_at(commit_leafs.len() / 2);
    //     let (left, right): (E, E) = (
    //         dot_product(batch_coeffs.iter().copied(), left.iter().copied()),
    //         dot_product(batch_coeffs.iter().copied(), right.iter().copied()),
    //     );
    //     let r = fold_challenges.first().unwrap();
    //     let coeff = <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
    //         vp,
    //         num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1,
    //     )[idx];
    //     let (lo, hi) = ((left + right).halve(), (left - right) * coeff);
    //     let folded = lo + (hi - lo) * *r;

    //     let rounds =
    //         num_vars - <Spec::EncodingScheme as EncodingScheme<E>>::get_basecode_msg_size_log() - 1;
    //     let n_d_next =
    //         1 << (num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1);
    //     debug_assert_eq!(rounds, fold_challenges.len() - 1);
    //     debug_assert_eq!(rounds, roots.len(),);
    //     debug_assert_eq!(rounds, opening_ext.len(),);
    //     let (final_idx, final_folded, _) = roots
    //         .iter()
    //         .zip_eq(fold_challenges.iter().skip(1))
    //         .zip_eq(opening_ext)
    //         .fold(
    //             (idx, folded, n_d_next),
    //             |(idx, folded, n_d_i), ((pi_comm, r), (leaf, proof))| {
    //                 let is_interpolate_to_right_index = (idx & 1) == 1;
    //                 let mut leafs = vec![*leaf; 2];
    //                 leafs[is_interpolate_to_right_index as usize] = folded;

    //                 let idx = idx >> 1;
    //                 mmcs_ext
    //                     .verify_batch(
    //                         pi_comm,
    //                         &[Dimensions {
    //                             width: 2,
    //                             // width is 2, thus height divide by 2 via right shift
    //                             height: n_d_i >> 1,
    //                         }],
    //                         idx,
    //                         slice::from_ref(&leafs),
    //                         proof,
    //                     )
    //                     .expect("verify failed");
    //                 let coeff =
    //                     <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
    //                         vp,
    //                         log2_strict_usize(n_d_i) - 1,
    //                     )[idx];
    //                 debug_assert_eq!(
    //                     <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
    //                         vp,
    //                         log2_strict_usize(n_d_i) - 1,
    //                     )
    //                     .len(),
    //                     n_d_i >> 1
    //                 );
    //                 let (left, right) = (leafs[0], leafs[1]);
    //                 let (lo, hi) = ((left + right).halve(), (left - right) * coeff);
    //                 (idx, lo + (hi - lo) * *r, n_d_i >> 1)
    //             },
    //         );
    //     assert!(
    //         final_codeword.values[final_idx] == final_folded,
    //         "final_codeword.values[idx] value {:?} != folded {:?}",
    //         final_codeword.values[final_idx],
    //         final_folded
    //     );
    // });
    // exit_span!(span);

    // // 1. check initial claim match with first round sumcheck value
    // assert_eq!(
    //     dot_product::<E, _, _>(batch_coeffs.iter().copied(), evals.iter().copied()),
    //     { sum_check_messages[0][0] + sum_check_messages[0][1] }
    // );
    // // 2. check every round of sumcheck match with prev claims
    // for i in 0..fold_challenges.len() - 1 {
    //     assert_eq!(
    //         interpolate_uni_poly(&sum_check_messages[i], fold_challenges[i]),
    //         { sum_check_messages[i + 1][0] + sum_check_messages[i + 1][1] }
    //     );
    // }
    // // 3. check final evaluation are correct
    // assert_eq!(
    //     interpolate_uni_poly(
    //         &sum_check_messages[fold_challenges.len() - 1],
    //         fold_challenges[fold_challenges.len() - 1]
    //     ),
    //     inner_product(final_message, partial_eq)
    // );

    // end_timer!(timer);
}

fn get_base_oracle_dimentions<E: ExtensionField, Spec: BasefoldSpec<E>>(
    circuit_meta_map: &BTreeMap<usize, CircuitIndexMeta>,
) -> (Vec<Dimensions>, Vec<Dimensions>) {
    let (wit_dim, fixed_dim): (Vec<_>, Vec<_>) = circuit_meta_map
        .values()
        .map(
            |CircuitIndexMeta {
                 witin_num_vars,
                 witin_num_polys,
                 fixed_num_vars,
                 fixed_num_polys,
             }| {
                (
                    Dimensions {
                        // width size is double num_polys due to leaf + right leafs are concat
                        width: witin_num_polys * 2,
                        height: 1
                            << (witin_num_vars
                                + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log()
                                - 1),
                    },
                    if *fixed_num_vars > 0 {
                        Some(Dimensions {
                            // width size is double num_polys due to leaf + right leafs are concat
                            width: fixed_num_polys * 2,
                            height: 1
                                << (fixed_num_vars
                                    + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log()
                                    - 1),
                        })
                    } else {
                        None
                    },
                )
            },
        )
        .unzip();
    let fixed_dim = fixed_dim.into_iter().filter_map(|x| x).collect_vec();
    (wit_dim, fixed_dim)
}
