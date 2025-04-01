use std::sync::Arc;

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec, MerkleTreeExt},
    sumcheck::{sum_check_challenge_round, sum_check_first_round, sum_check_last_round},
};
use crate::util::{
    hash::write_digest_to_transcript,
    merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::izip;
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    field::{Field, PrimeCharacteristicRing, dot_product},
    matrix::dense::RowMajorMatrix,
    util::log2_strict_usize,
};
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{DenseMultilinearExtension, FieldType},
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
};
use rayon::{
    iter::IntoParallelRefIterator,
    prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice},
};

use super::structure::BasefoldCommitmentWithWitness;

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
pub fn simple_batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    batch_coeffs: &[E],
    comm: &BasefoldCommitmentWithWitness<E>,
    transcript: &mut impl Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
) -> (Vec<MerkleTreeExt<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    let timer = start_timer!(|| "Simple batch commit phase");
    assert_eq!(point.len(), num_vars);
    assert_eq!(comm.num_polys, batch_coeffs.len());
    let prepare_timer = start_timer!(|| "Prepare");

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();
    let mut trees: Vec<MerkleTreeExt<E>> = Vec::with_capacity(num_vars);

    let batch_codewords_timer = start_timer!(|| "Batch codewords");
    let initial_oracle = mmcs.get_matrices(&comm.codeword)[0]
        .values
        .par_chunks(comm.num_polys)
        .map(|row| dot_product(batch_coeffs.iter().copied(), row.iter().copied()))
        .collect::<Vec<_>>();
    end_timer!(batch_codewords_timer);

    let Some((running_evals, _)): Option<(ArcMultilinearExtension<E>, E)> = izip!(
        comm.polynomials_bh_evals.iter().cloned(),
        batch_coeffs.iter().cloned()
    )
    .reduce(|(poly_a, coeff_a), (poly_b, coeff_b)| {
        let next_poly = commutative_op_mle_pair!(|poly_a, poly_b| {
            // TODO we can save a bit cost if first batch_coeffs is E::ONE so we can skip the first base * ext operation
            Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                num_vars,
                poly_a
                    .par_iter()
                    .zip(poly_b.par_iter())
                    .map(|(a, b)| coeff_a * *a + coeff_b * *b)
                    .collect(),
            ))
        });
        (next_poly, E::ONE)
    }) else {
        unimplemented!()
    };
    // TODO avoid clone before sumcheck fix variable
    let mut running_evals = match running_evals.evaluations() {
        FieldType::Base(items) => items.par_iter().map(|b| E::from(*b)).collect(),
        FieldType::Ext(_) => running_evals.get_ext_field_vec().to_vec(),
        _ => unreachable!(),
    };
    end_timer!(prepare_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::build eq");
    let mut eq = build_eq_x_r_vec(point);
    end_timer!(build_eq_timer);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut running_sumcheck_message = sum_check_first_round(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_evals = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&running_sumcheck_message);
        sumcheck_messages.push(running_sumcheck_message);

        let challenge = transcript
            .sample_and_append_challenge(b"commit round")
            .elements;

        // Fold the current oracle for FRI
        let new_running_oracle = if trees.is_empty() {
            basefold_one_round_by_interpolation_weights::<E, Spec>(
                pp,
                log2_strict_usize(initial_oracle.len()) - 1,
                &initial_oracle,
                challenge,
            )
        } else {
            let values = &mmcs_ext.get_matrices(trees.last().unwrap())[0].values;
            basefold_one_round_by_interpolation_weights::<E, Spec>(
                pp,
                log2_strict_usize(values.len()) - 1,
                values,
                challenge,
            )
        };

        if i < num_rounds - 1 {
            let (commitment, merkle_tree) = mmcs_ext.commit_matrix(new_running_oracle);
            trees.push(merkle_tree);
            let running_root = commitment;
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);

            // go next round sumcheck and update sumcheck message
            running_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);
        } else {
            // Assign a new value to the old running vars so that the compiler
            // knows the old value is safe to move.
            running_sumcheck_message = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            transcript.append_field_element_exts(&running_evals);
            final_evals = running_evals;
            // To avoid the compiler complaining that running_evals is moved.
            running_evals = Vec::new();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.
                let evaluations = final_evals.clone();
                let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode_slow_ext(
                    p3::matrix::dense::DenseMatrix::new(evaluations, 1),
                );
                assert_eq!(basecode.values, new_running_oracle.values);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        roots,
        final_message: final_evals,
    })
}

// TODO define it within codeword
pub(crate) fn basefold_one_round_by_interpolation_weights<
    E: ExtensionField,
    Spec: BasefoldSpec<E>,
>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    level: usize,
    values: &[E],
    challenge: E,
) -> RowMajorMatrix<E> {
    // assume values in bit_reverse_format
    // thus chunks(2) is equivalent to left, right traverse
    let folding_coeffs =
        <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs_level(pp, level);
    debug_assert_eq!(folding_coeffs.len(), 1 << level);
    let inv_2 = E::BaseField::from_u64(2).inverse();
    RowMajorMatrix::new(
        values
            .par_chunks_exact(2)
            .zip(folding_coeffs)
            .map(|(ys, coeff)| {
                let (left, right) = (ys[0], ys[1]);
                // original (left, right) = (lo + hi*x, lo - hi*x), lo, hi are codeword, but after times x it's not codeword
                // recover left & right codeword via (lo, hi) = ((left + right) / 2, (left - right) / 2x)
                let (lo, hi) = ((left + right) * inv_2, (left - right) * *coeff); // e.g. coeff = (2 * dit_butterfly)^(-1) in rs code
                // we do fold on folded = (1-r) * left_codeword + r * right_codeword, as it match perfectly with raw message in lagrange domain fixed variable
                lo + (hi - lo) * challenge
            })
            .collect::<Vec<_>>(),
        2,
    )
}
