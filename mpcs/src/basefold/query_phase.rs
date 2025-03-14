use std::{iter::repeat_with, slice};

use crate::{
    basefold::structure::MerkleTreeExt,
    util::{
        arithmetic::{
            degree_2_eval, degree_2_zero_plus_one, inner_product,
            interpolate_over_boolean_hypercube,
        },
        ext_to_usize,
        merkle_tree::poseidon2_merkle_tree,
        plonky2_util::reverse_bits,
    },
};
use ark_std::{end_timer, start_timer};
use ceno_sumcheck::macros::{entered_span, exit_span};
use ff_ext::ExtensionField;
use itertools::{Itertools, izip, zip};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_field::dot_product;
use p3_matrix::{Dimensions, Matrix};
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use crate::basefold::structure::QueryOpeningProofs;
use multilinear_extensions::mle::FieldType;

use super::{
    Digest,
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldSpec},
};
use crate::util::plonky2_util::reverse_index_bits_in_place;

pub fn simple_batch_prover_query_phase<E: ExtensionField>(
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
                // mask the least significant bit (LSB) for the same reason as above:
                // 1. we only need the even part of the index.
                // 2. since even and odd parts are concatenated in the same leaf,
                //    the overall merkle tree height is effectively halved,
                //    so we divide by 2.
                let idx = idx >> 1;
                let (mut values, proof) = mmcs_ext.open_batch(idx, tree);
                let leafs = values.pop().unwrap();
                debug_assert_eq!(leafs.len(), 2);
                // TODO we can keep only one of the leafs, as the other can be interpolate from previous layer
                proofs.push((leafs, proof));
                (idx >> 1, proofs)
            });
            (opening, opening_ext)
        })
        .collect_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn simple_batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &QueryOpeningProofs<E>,
    sum_check_messages: &[Vec<E>],
    fold_challenges: &[E],
    batch_coeffs: &[E],
    num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E>],
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    evals: &[E],
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    // let timer = start_timer!(|| "Verifier query phase");

    // let encode_timer = start_timer!(|| "Encode final codeword");
    // let mut message = final_message.to_vec();
    // if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_left_and_right_folding() {
    //     reverse_index_bits_in_place(&mut message);
    // }
    // interpolate_over_boolean_hypercube(&mut message);
    // let final_codeword =
    //     <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(vp, &FieldType::Ext(message));
    // let mut final_codeword = match final_codeword {
    //     FieldType::Ext(final_codeword) => final_codeword,
    //     _ => panic!("Final codeword must be extension field"),
    // };
    // reverse_index_bits_in_place(&mut final_codeword);
    // end_timer!(encode_timer);

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();

    let span = entered_span!("check queries");
    // izip!(indices, queries).try_for_each(|(idx, (opening, opening_ext))| {
    //     mmcs.verify_batch(
    //         todo!(),
    //         &[Dimensions {
    //             width: 0,
    //             height: todo!(),
    //         }],
    //         *idx,
    //         slice::from_ref(&opening.0),
    //         &opening.1,
    //     )
    //     .expect("verify batch failed");
    //     let (left, right) = opening.0.split_at(opening.0.len() / 2);
    // let (value_0, value_1) = (
    //     dot_product(batch_coeffs.iter().copied(), left.iter().copied()),
    //     dot_product(batch_coeffs.iter().copied(), right.iter().copied()),
    // );
    //// interlopate left, right with dit_butterfly params
    // let leave = xxx

    // let folded = izip!(rev(0..self.code.d()), rev(&r), &proof.pi_comms, opening_ext).try_fold(
    //     leave,
    //     |folded, (i, r_i, comm, opening_ext)| {
    //         let sibling = ((idx / self.code.n_i(i)) & 1) ^ 1;
    //         let idx = idx % self.code.n_i(i);
    //         let mut values = vec![folded; 2];
    //         values[sibling] = opening_ext.0;
    //         self.mmcs_ext
    //             .verify_batch(
    //                 comm,
    //                 &[Dimensions {
    //                     width: 0,
    //                     height: self.code.n_i(i),
    //                 }],
    //                 idx,
    //                 slice::from_ref(&values),
    //                 &opening_ext.1,
    //             )
    //             .map_err(Self::Error::Mmcs)?;
    //         Ok(self.code.interpolate(i, idx, values[0], values[1], *r_i))
    //     },
    // )?;
    // if pi_0[idx % self.code.n_0()] != folded {
    //     return Err(Self::Error::InvalidQuery);
    // }
    // Ok(())
    // });
    exit_span!(span);

    // // For computing the weights on the fly, because the verifier is incapable of storing
    // // the weights.
    // let queries_timer = start_timer!(|| format!("Check {} queries", indices.len()));
    // // queries.check::<Spec>(
    // //     indices,
    // //     vp,
    // //     fold_challenges,
    // //     batch_coeffs,
    // //     num_rounds,
    // //     num_vars,
    // //     &final_codeword,
    // //     roots,
    // //     comm,
    // // );
    // end_timer!(queries_timer);

    // let final_timer = start_timer!(|| "Final checks");
    // assert_eq!(
    //     &inner_product(batch_coeffs, evals),
    //     &degree_2_zero_plus_one(&sum_check_messages[0])
    // );

    // // The sum-check part of the protocol
    // for i in 0..fold_challenges.len() - 1 {
    //     assert_eq!(
    //         degree_2_eval(&sum_check_messages[i], fold_challenges[i]),
    //         degree_2_zero_plus_one(&sum_check_messages[i + 1])
    //     );
    // }

    // // Finally, the last sumcheck poly evaluation should be the same as the sum of the polynomial
    // // sent from the prover
    // assert_eq!(
    //     degree_2_eval(
    //         &sum_check_messages[fold_challenges.len() - 1],
    //         fold_challenges[fold_challenges.len() - 1]
    //     ),
    //     inner_product(final_message, partial_eq)
    // );
    // end_timer!(final_timer);

    // end_timer!(timer);
    // unimplemented!()
}
