use std::slice;

use crate::{
    basefold::structure::MerkleTreeExt,
    util::{arithmetic::inner_product, ext_to_usize, merkle_tree::poseidon2_merkle_tree},
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    field::dot_product,
    matrix::{Dimensions, dense::RowMajorMatrix},
    util::log2_strict_usize,
};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::interpolate_uni_poly,
};
use transcript::Transcript;

use crate::basefold::structure::QueryOpeningProofs;

use super::{
    Digest,
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldSpec},
};

pub fn batch_prover_query_phase<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    comm: &BasefoldCommitmentWithWitness<E>,
    trees: &[MerkleTreeExt<E>],
    num_verifier_queries: usize,
) -> QueryOpeningProofs<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();

    // Transform the challenge queries from field elements into integers
    // TODO simplify with sample_bit
    let queries: Vec<_> = transcript.sample_and_append_vec(b"query indices", num_verifier_queries);
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| ext_to_usize(x_index) % comm.codeword_size())
        .collect_vec();

    queries_usize
        .iter()
        .map(|idx| {
            let opening = {
                // extract the even part of `idx`
                // ---------------------------------
                // the oracle values are committed in a row-bit-reversed format.
                // rounding `idx` to an even value is equivalent to retrieving the "left-hand" side `j` index
                // in the original (non-row-bit-reversed) format.
                //
                // however, since `p_d[j]` and `p_d[j + n_{d-1}]` are already concatenated in the same merkle leaf,
                // we can simply mask out the least significant bit (lsb) by performing a right shift by 1.
                let idx = idx >> 1;
                let (mut values, proof) = mmcs.open_batch(idx, &comm.codeword);
                let leafs = values.pop().unwrap();
                (leafs, proof)
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
            (opening, opening_ext)
        })
        .collect_vec()
}

pub fn simple_batch_prover_query_phase<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    comm: &BasefoldCommitmentWithWitness<E>,
    trees: &[MerkleTreeExt<E>],
    num_verifier_queries: usize,
) -> QueryOpeningProofs<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    unimplemented!()
    //     let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    //     let mmcs = poseidon2_merkle_tree::<E>();

    //     // Transform the challenge queries from field elements into integers
    //     // TODO simplify with sample_bit
    //     let queries: Vec<_> = transcript.sample_and_append_vec(b"query indices", num_verifier_queries);
    //     let queries_usize: Vec<usize> = queries
    //         .iter()
    //         .map(|x_index| ext_to_usize(x_index) % comm.codeword_size())
    //         .collect_vec();

    //     queries_usize
    //         .iter()
    //         .map(|idx| {
    //             let opening = {
    //                 // extract the even part of `idx`
    //                 // ---------------------------------
    //                 // the oracle values are committed in a row-bit-reversed format.
    //                 // rounding `idx` to an even value is equivalent to retrieving the "left-hand" side `j` index
    //                 // in the original (non-row-bit-reversed) format.
    //                 //
    //                 // however, since `p_d[j]` and `p_d[j + n_{d-1}]` are already concatenated in the same merkle leaf,
    //                 // we can simply mask out the least significant bit (lsb) by performing a right shift by 1.
    //                 let idx = idx >> 1;
    //                 let (mut values, proof) = mmcs.open_batch(idx, &comm.codeword);
    //                 let leafs = values.pop().unwrap();
    //                 (leafs, proof)
    //             };

    //             // this is equivalent with "idx = idx % n_{d-1}" operation in non row bit reverse format
    //             let idx = idx >> 1;
    //             let (_, opening_ext) = trees.iter().fold((idx, vec![]), |(idx, mut proofs), tree| {
    //                 // differentiate interpolate to left or right position at next layer
    //                 let is_interpolate_to_right_index = (idx & 1) == 1;
    //                 // mask the least significant bit (LSB) for the same reason as above:
    //                 // 1. we only need the even part of the index.
    //                 // 2. since even and odd parts are concatenated in the same leaf,
    //                 //    the overall merkle tree height is effectively halved,
    //                 //    so we divide by 2.
    //                 let (mut values, proof) = mmcs_ext.open_batch(idx >> 1, tree);
    //                 let leafs = values.pop().unwrap();
    //                 debug_assert_eq!(leafs.len(), 2);
    //                 let sibling = leafs[(!is_interpolate_to_right_index) as usize];
    //                 proofs.push((sibling, proof));
    //                 (idx >> 1, proofs)
    //             });
    //             (opening, opening_ext)
    //         })
    //         .collect_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn simple_batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &QueryOpeningProofs<E>,
    sum_check_messages: &[Vec<E>],
    fold_challenges: &[E],
    batch_coeffs: &[E],
    _num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E>],
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    evals: &[E],
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");
    let num_polys = evals.len();

    let encode_timer = start_timer!(|| "Encode final codeword");
    let final_codeword = <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(
        vp,
        RowMajorMatrix::new(final_message.to_vec(), 1),
    );
    end_timer!(encode_timer);

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();

    let span = entered_span!("check queries");
    izip!(indices, queries).for_each(|(idx, ((commit_leafs, commit_proof), opening_ext))| {
        // refer to prover documentation for the reason of right shift by 1
        let idx = idx >> 1;
        mmcs.verify_batch(
            &comm.pi_d_digest,
            &[Dimensions {
                // width size is double num_polys due to leaf + right leafs are concat
                width: num_polys * 2,
                height: 1
                    << (num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1),
            }],
            idx,
            slice::from_ref(commit_leafs),
            commit_proof,
        )
        .expect("verify batch failed");
        let (left, right) = commit_leafs.split_at(commit_leafs.len() / 2);
        let (left, right): (E, E) = (
            dot_product(batch_coeffs.iter().copied(), left.iter().copied()),
            dot_product(batch_coeffs.iter().copied(), right.iter().copied()),
        );
        let r = fold_challenges.first().unwrap();
        let coeff = <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs_level(
            vp,
            num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1,
        )[idx];
        let (lo, hi) = ((left + right).halve(), (left - right) * coeff);
        let folded = lo + (hi - lo) * *r;

        let rounds =
            num_vars - <Spec::EncodingScheme as EncodingScheme<E>>::get_basecode_msg_size_log() - 1;
        let n_d_next =
            1 << (num_vars + <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log() - 1);
        debug_assert_eq!(rounds, fold_challenges.len() - 1);
        debug_assert_eq!(rounds, roots.len(),);
        debug_assert_eq!(rounds, opening_ext.len(),);
        let (final_idx, final_folded, _) = roots
            .iter()
            .zip_eq(fold_challenges.iter().skip(1))
            .zip_eq(opening_ext)
            .fold(
                (idx, folded, n_d_next),
                |(idx, folded, n_d_i), ((pi_comm, r), (leaf, proof))| {
                    let is_interpolate_to_right_index = (idx & 1) == 1;
                    let mut leafs = vec![*leaf; 2];
                    leafs[is_interpolate_to_right_index as usize] = folded;

                    let idx = idx >> 1;
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
                    (idx, lo + (hi - lo) * *r, n_d_i >> 1)
                },
            );
        assert!(
            final_codeword.values[final_idx] == final_folded,
            "final_codeword.values[idx] value {:?} != folded {:?}",
            final_codeword.values[final_idx],
            final_folded
        );
    });
    exit_span!(span);

    // 1. check initial claim match with first round sumcheck value
    assert_eq!(
        dot_product::<E, _, _>(batch_coeffs.iter().copied(), evals.iter().copied()),
        { sum_check_messages[0][0] + sum_check_messages[0][1] }
    );
    // 2. check every round of sumcheck match with prev claims
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            interpolate_uni_poly(&sum_check_messages[i], fold_challenges[i]),
            { sum_check_messages[i + 1][0] + sum_check_messages[i + 1][1] }
        );
    }
    // 3. check final evaluation are correct
    assert_eq!(
        interpolate_uni_poly(
            &sum_check_messages[fold_challenges.len() - 1],
            fold_challenges[fold_challenges.len() - 1]
        ),
        inner_product(final_message, partial_eq)
    );

    end_timer!(timer);
}
