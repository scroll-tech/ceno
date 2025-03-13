use std::iter::repeat_with;

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
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_matrix::Matrix;
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
            println!("start commit proof with id {idx}");
            let opening = {
                let odd = idx | 1;
                let even = odd - 1; // get even part of idx
                // n_d_1 represent n_{d-1} oracle length
                // codeword matrix width is 2 * num_polys, because we concat them into leafs and commit
                // thus, n_d_1 match the length of next oracle p_{i-1}, which length is p_i / 2
                let n_d_1 = mmcs.get_matrices(&comm.codeword)[0].height();
                let idx = even % n_d_1;
                println!(
                    "index {idx}, tree width {}, tree leafs {}, overall len {}",
                    mmcs.get_matrices(&comm.codeword)[0].width(),
                    mmcs.get_matrices(&comm.codeword)[0].values.len(),
                    mmcs.get_matrices(&comm.codeword).len()
                );
                // Soundness: is it ok we only open on one index, and rely on next layer to provide another sibling witness?
                let (mut values, proof) = mmcs.open_batch(idx, &comm.codeword);
                let leafs = values.pop().unwrap();
                // leaf length equal to num poly * 2
                debug_assert_eq!(
                    leafs.len(),
                    mmcs.get_matrices(&comm.codeword)[0].width() * 2
                );
                (leafs, proof)
            };
            println!("end commit proof");
            let (_, opening_ext) =
                trees
                    .iter()
                    .fold((idx >> 1, vec![]), |(idx, mut proofs), tree| {
                        let odd = idx | 1;
                        let even = odd - 1;
                        println!(
                            "index {even}, tree leafs {}, overall len {}",
                            mmcs_ext.get_matrices(tree)[0].values.len(),
                            mmcs_ext.get_matrices(tree).len()
                        );
                        let (mut values, proof) = mmcs_ext.open_batch(even, tree);
                        let leafs = values.pop().unwrap();
                        debug_assert_eq!(leafs.len(), 2);
                        // TODO we can keep only one of the leafs, as the other can be interpolate from previous layer
                        proofs.push((leafs, proof));
                        (idx >> 1, proofs)
                    });
            println!("end query with id {idx}");
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
    unimplemented!()
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
}
