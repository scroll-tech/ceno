use std::{cmp::Reverse, slice};

use crate::{
    Point,
    basefold::structure::{CircuitIndexMeta, MerkleTreeExt, QueryOpeningProof},
    util::{codeword_fold_with_challenge, merkle_tree::poseidon2_merkle_tree},
};
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    field::{Field, PrimeCharacteristicRing, dot_product},
    fri::{BatchOpening, CommitPhaseProofStep},
    matrix::{Dimensions, dense::RowMajorMatrix},
    util::log2_strict_usize,
};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
    util::interpolate_uni_poly,
};
use transcript::Transcript;

use crate::basefold::structure::QueryOpeningProofs;

use super::{
    Digest,
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldSpec},
};

pub fn batch_query_phase<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    fixed_comms: Option<&BasefoldCommitmentWithWitness<E>>,
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
    let queries: Vec<_> = transcript.sample_bits_and_append_vec(
        b"query indices",
        num_verifier_queries,
        witin_comms.log2_max_codeword_size,
    );

    queries
        .iter()
        .map(|idx| {
            let witin_base_proof = {
                // extract the even part of `idx`
                // ---------------------------------
                // the oracle values are committed in a row-bit-reversed format.
                // rounding `idx` to an even value is equivalent to retrieving the "left-hand" side `j` index
                // in the original (non-row-bit-reversed) format.
                //
                // however, since `p_d[j]` and `p_d[j + n_{d-1}]` are already concatenated in the same merkle leaf,
                // we can simply mask out the least significant bit (lsb) by performing a right shift by 1.
                let idx = idx >> 1;
                let (opened_values, opening_proof) = mmcs.open_batch(idx, &witin_comms.codeword);
                BatchOpening {
                    opened_values,
                    opening_proof,
                }
            };

            let fixed_base_proof = if let Some(fixed_comms) = fixed_comms {
                // follow same rule as witin base proof
                let idx_shift = witin_comms.log2_max_codeword_size as i32
                    - fixed_comms.log2_max_codeword_size as i32;
                let idx = if idx_shift > 0 {
                    idx >> idx_shift
                } else {
                    idx << -idx_shift
                };
                let idx = idx >> 1;
                let (opened_values, opening_proof) = mmcs.open_batch(idx, &fixed_comms.codeword);
                Some(BatchOpening {
                    opened_values,
                    opening_proof,
                })
            } else {
                None
            };

            // this is equivalent with "idx = idx % n_{d-1}" operation in non row bit reverse format
            let idx = idx >> 1;
            let (_, commit_phase_openings) =
                trees
                    .iter()
                    .fold((idx, vec![]), |(idx, mut commit_phase_openings), tree| {
                        // differentiate interpolate to left or right position at next layer
                        let is_interpolate_to_right_index = (idx & 1) == 1;
                        // mask the least significant bit (LSB) for the same reason as above:
                        // 1. we only need the even part of the index.
                        // 2. since even and odd parts are concatenated in the same leaf,
                        //    the overall merkle tree height is effectively halved,
                        //    so we divide by 2.
                        let (mut values, opening_proof) = mmcs_ext.open_batch(idx >> 1, tree);
                        let leafs = values.pop().unwrap();
                        debug_assert_eq!(leafs.len(), 2);
                        let sibling_value = leafs[(!is_interpolate_to_right_index) as usize];
                        commit_phase_openings.push(CommitPhaseProofStep {
                            sibling_value,
                            opening_proof,
                        });
                        (idx >> 1, commit_phase_openings)
                    });
            QueryOpeningProof {
                witin_base_proof,
                fixed_base_proof,
                commit_phase_openings,
            }
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
    fixed_comm: Option<&BasefoldCommitment<E>>,
    witin_comm: &BasefoldCommitment<E>,
    circuit_meta: &[CircuitIndexMeta],
    commits: &[Digest<E>],
    fold_challenges: &[E],
    sumcheck_messages: &[IOPProverMessage<E>],
    point_evals: &[(Point<E>, Vec<E>)],
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let inv_2 = E::BaseField::from_u64(2).inverse();
    debug_assert_eq!(point_evals.len(), circuit_meta.len());
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
    // can't use witin_comm.log2_max_codeword_size since it's untrusted
    let log2_witin_max_codeword_size =
        max_num_var + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log();

    // an vector with same length as circuit_meta, which is sorted by num_var in descending order and keep its index
    // for reverse lookup when retrieving next base codeword to involve into batching
    let folding_sorted_order = circuit_meta
        .iter()
        .enumerate()
        .sorted_by_key(|(_, CircuitIndexMeta { witin_num_vars, .. })| Reverse(witin_num_vars))
        .map(|(index, CircuitIndexMeta { witin_num_vars, .. })| (witin_num_vars, index))
        .collect_vec();

    indices.iter().zip_eq(queries).for_each(
        |(
            idx,
            QueryOpeningProof {
                witin_base_proof:
                    BatchOpening {
                        opened_values: witin_opened_values,
                        opening_proof: witin_opening_proof,
                    },
                fixed_base_proof: fixed_commit_option,
                commit_phase_openings: opening_ext,
            },
        )| {
            // verify base oracle query proof
            // refer to prover documentation for the reason of right shift by 1
            let mut idx = idx >> 1;

            let (witin_dimentions, fixed_dimentions) =
                get_base_codeword_dimentions::<E, Spec>(circuit_meta);
            // verify witness
            mmcs.verify_batch(
                &witin_comm.commit,
                &witin_dimentions,
                idx,
                witin_opened_values,
                witin_opening_proof,
            )
            .expect("verify witin commit batch failed");

            // verify fixed
            let fixed_commit_leafs = if let Some(fixed_comm) = fixed_comm {
                let BatchOpening {
                    opened_values: fixed_opened_values,
                    opening_proof: fixed_opening_proof,
                } = &fixed_commit_option.as_ref().unwrap();
                mmcs.verify_batch(
                    &fixed_comm.commit,
                    &fixed_dimentions,
                    {
                        let idx_shift = log2_witin_max_codeword_size as i32
                            - fixed_comm.log2_max_codeword_size as i32;
                        if idx_shift > 0 {
                            idx >> idx_shift
                        } else {
                            idx << -idx_shift
                        }
                    },
                    fixed_opened_values,
                    fixed_opening_proof,
                )
                .expect("verify fixed commit batch failed");
                fixed_opened_values
            } else {
                &vec![]
            };

            let mut fixed_commit_leafs_iter = fixed_commit_leafs.iter();
            let mut batch_coeffs_iter = batch_coeffs.iter();

            let base_codeword_lo_hi = circuit_meta
                .iter()
                .zip_eq(witin_opened_values)
                .map(
                    |(
                        CircuitIndexMeta {
                            witin_num_polys,
                            fixed_num_vars,
                            fixed_num_polys,
                            ..
                        },
                        witin_leafs,
                    )| {
                        let (lo, hi) = std::iter::once((witin_leafs, *witin_num_polys))
                            .chain((*fixed_num_vars > 0).then(|| {
                                (fixed_commit_leafs_iter.next().unwrap(), *fixed_num_polys)
                            }))
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
                        (lo, hi)
                    },
                )
                .collect_vec();
            debug_assert_eq!(folding_sorted_order.len(), base_codeword_lo_hi.len());
            debug_assert!(fixed_commit_leafs_iter.next().is_none());
            debug_assert!(batch_coeffs_iter.next().is_none());

            // fold and query
            let mut cur_num_var = max_num_var;
            // -1 because for there are only #max_num_var-1 openings proof
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
                .map(|(_, index)| {
                    let (lo, hi) = &base_codeword_lo_hi[*index];
                    let coeff =
                        <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
                            vp,
                            cur_num_var
                                + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log()
                                - 1,
                        )[idx];
                    codeword_fold_with_challenge(&[*lo, *hi], *r, coeff, inv_2)
                })
                .sum::<E>();

            let mut n_d_i = n_d_next;
            for (
                (pi_comm, r),
                CommitPhaseProofStep {
                    sibling_value: leaf,
                    opening_proof: proof,
                },
            ) in commits
                .iter()
                .zip_eq(fold_challenges.iter().skip(1))
                .zip_eq(opening_ext)
            {
                cur_num_var -= 1;

                let is_interpolate_to_right_index = (idx & 1) == 1;
                let new_involved_codewords = folding_sorted_order_iter
                    .by_ref()
                    .peeking_take_while(|(num_vars, _)| **num_vars == cur_num_var)
                    .map(|(_, index)| {
                        let (lo, hi) = &base_codeword_lo_hi[*index];
                        if is_interpolate_to_right_index {
                            *hi
                        } else {
                            *lo
                        }
                    })
                    .sum::<E>();

                let mut leafs = vec![*leaf; 2];
                leafs[is_interpolate_to_right_index as usize] = folded + new_involved_codewords;
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
                folded = codeword_fold_with_challenge(&[leafs[0], leafs[1]], *r, coeff, inv_2);
                n_d_i >>= 1;
            }
            debug_assert!(folding_sorted_order_iter.next().is_none());
            assert!(
                final_codeword.values[idx] == folded,
                "final_codeword.values[idx] value {:?} != folded {:?}",
                final_codeword.values[idx],
                folded
            );
        },
    );
    exit_span!(check_queries_span);

    // 1. check initial claim match with first round sumcheck value
    assert_eq!(
        // we need to scale up with scalar for witin_num_vars < max_num_var
        dot_product::<E, _, _>(
            batch_coeffs.iter().copied(),
            point_evals.iter().zip_eq(circuit_meta.iter()).flat_map(
                |((_, evals), CircuitIndexMeta { witin_num_vars, .. })| {
                    evals.iter().copied().map(move |eval| {
                        eval * E::from_u64(1 << (max_num_var - witin_num_vars) as u64)
                    })
                }
            )
        ),
        { sumcheck_messages[0].evaluations[0] + sumcheck_messages[0].evaluations[1] }
    );
    // 2. check every round of sumcheck match with prev claims
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            interpolate_uni_poly(&sumcheck_messages[i].evaluations, fold_challenges[i]),
            { sumcheck_messages[i + 1].evaluations[0] + sumcheck_messages[i + 1].evaluations[1] }
        );
    }
    // 3. check final evaluation are correct
    assert_eq!(
        interpolate_uni_poly(
            &sumcheck_messages[fold_challenges.len() - 1].evaluations,
            fold_challenges[fold_challenges.len() - 1]
        ),
        izip!(final_message, point_evals.iter().map(|(point, _)| point))
            .map(|(final_message, point)| {
                // coeff is the eq polynomial evaluated at the first challenge.len() variables
                let num_vars_evaluated = point.len()
                    - <Spec::EncodingScheme as EncodingScheme<E>>::get_basecode_msg_size_log();
                let coeff = eq_eval(
                    &point[..num_vars_evaluated],
                    &fold_challenges[fold_challenges.len() - num_vars_evaluated..],
                );
                // Compute eq as the partially evaluated eq polynomial
                let eq = build_eq_x_r_vec(&point[num_vars_evaluated..]);
                dot_product(
                    final_message.iter().copied(),
                    eq.into_iter().map(|e| e * coeff),
                )
            })
            .sum()
    );
}

fn get_base_codeword_dimentions<E: ExtensionField, Spec: BasefoldSpec<E>>(
    circuit_meta_map: &[CircuitIndexMeta],
) -> (Vec<Dimensions>, Vec<Dimensions>) {
    let (wit_dim, fixed_dim): (Vec<_>, Vec<_>) = circuit_meta_map
        .iter()
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
    let fixed_dim = fixed_dim.into_iter().flatten().collect_vec();
    (wit_dim, fixed_dim)
}
