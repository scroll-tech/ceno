use super::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams,
};
use crate::{
    Error,
    basefold::{
        commit_phase::simple_batch_commit_phase,
        query_phase::{
            SimpleBatchQueriesResultWithMerklePath, simple_batch_prover_query_phase,
            simple_batch_verifier_query_phase,
        },
        structure::{BasefoldProof, ProofQueriesResultWithMerklePath},
    },
    sum_check::eq_xy_eval,
    util::{
        arithmetic::inner_product, ext_to_usize, hash::write_digest_to_transcript,
        merkle_tree::MerkleTree,
    },
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn simple_batch_open_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[ArcMultilinearExtension<E>],
        comm: &BasefoldCommitmentWithData<E>,
        point: &[E],
        evals: &[E],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys[0].num_vars();

        if comm.is_trivial::<Spec>() {
            return Ok(BasefoldProof::trivial(comm.polynomials_bh_evals.clone()));
        }

        polys
            .iter()
            .for_each(|poly| assert_eq!(poly.num_vars(), num_vars));
        assert!(num_vars >= Spec::get_basecode_msg_size_log());
        assert_eq!(comm.num_polys, polys.len());
        assert_eq!(comm.num_polys, evals.len());

        if cfg!(feature = "sanity-check") {
            evals
                .iter()
                .zip(polys)
                .for_each(|(eval, poly)| assert_eq!(&poly.evaluate(point), eval))
        }
        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();
        let _target_sum = inner_product(evals, &eq_xt);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let (trees, commit_phase_proof) = simple_batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            &eq_xt,
            comm,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries =
            simple_batch_prover_query_phase(transcript, comm, &trees, Spec::get_number_queries());
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::build_query_result");

        let queries_with_merkle_path =
            SimpleBatchQueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        end_timer!(timer);

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::SimpleBatched(
                queries_with_merkle_path,
            ),
            sumcheck_proof: None,
            trivial_proof: vec![],
        })
    }

    pub(crate) fn simple_batch_verify_inner(
        vp: &BasefoldVerifierParams<E, Spec>,
        comm: &BasefoldCommitment<E>,
        point: &[E],
        evals: &[E],
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::simple batch verify");
        let batch_size = evals.len();
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }

        if proof.is_trivial() {
            let trivial_proof = &proof.trivial_proof;
            let merkle_tree = MerkleTree::from_batch_leaves(trivial_proof.clone());
            if comm.root() == merkle_tree.root() {
                return Ok(());
            } else {
                return Err(Error::MerkleRootMismatch);
            }
        }

        let num_vars = point.len();
        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
            assert!(num_vars >= Spec::get_basecode_msg_size_log());
        }
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let roots = &proof.roots;
        let sumcheck_messages = &proof.sumcheck_messages;
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
            fold_challenges.push(
                transcript
                    .get_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&roots[i], transcript);
            }
        }
        let final_message = &proof.final_message;
        transcript.append_field_element_exts(final_message.as_slice());

        let queries: Vec<_> = (0..Spec::get_number_queries())
            .map(|_| {
                ext_to_usize(
                    &transcript
                        .get_and_append_challenge(b"query indices")
                        .elements,
                ) % (1 << (num_vars + Spec::get_rate_log()))
            })
            .collect();
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_simple_batched();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &point[point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&point[..point.len() - fold_challenges.len()]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        simple_batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            &eq_xt,
            num_rounds,
            num_vars,
            final_message,
            roots,
            comm,
            eq.as_slice(),
            evals,
        );
        end_timer!(timer);

        Ok(())
    }
}
