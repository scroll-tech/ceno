use super::{Basefold, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec};
use crate::{
    Error,
    basefold::{
        commit_phase::simple_batch_commit_phase,
        query_phase::{SimpleBatchQueriesResultWithMerklePath, simple_batch_prover_query_phase},
        structure::{BasefoldProof, ProofQueriesResultWithMerklePath},
    },
    util::arithmetic::inner_product,
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use multilinear_extensions::{
    virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
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
}
