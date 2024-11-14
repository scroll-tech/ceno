use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use crate::{
    Error, PolynomialCommitmentScheme,
    basefold::{
        commit_phase::commit_phase,
        query_phase::{QueriesResultWithMerklePath, prover_query_phase},
        structure::{BasefoldProof, ProofQueriesResultWithMerklePath},
    },
};

use super::{Basefold, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec};

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn basic_open(
        pp: &BasefoldProverParams<E, Spec>,
        poly: &ArcMultilinearExtension<E>,
        comm: &BasefoldCommitmentWithData<E>,
        point: &[E],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        let timer = start_timer!(|| "Basefold::open");

        // The encoded polynomial should at least have the number of
        // variables of the basecode, i.e., the size of the message
        // when the protocol stops. If the polynomial is smaller
        // the protocol won't work, and saves no verifier work anyway.
        // In this case, simply return the evaluations as trivial proof.
        if comm.is_trivial::<Spec>() {
            return Ok(<Self as PolynomialCommitmentScheme<E>>::Proof::trivial(
                vec![poly.evaluations().clone()],
            ));
        }

        assert!(comm.num_vars >= Spec::get_basecode_msg_size_log());

        assert!(comm.num_polys == 1);

        // 1. Committing phase. This phase runs the sum-check and
        //    the FRI protocols interleavingly. After this phase,
        //    the sum-check protocol is finished, so nothing is
        //    to return about the sum-check. However, for the FRI
        //    part, the prover needs to prepare the answers to the
        //    queries, so the prover needs the oracles and the Merkle
        //    trees built over them.
        let (trees, commit_phase_proof) = commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            comm,
            transcript,
            poly.num_vars(),
            poly.num_vars() - Spec::get_basecode_msg_size_log(),
        );

        // 2. Query phase. ---------------------------------------
        //    Compute the query indices by Fiat-Shamir.
        //    For each index, prepare the answers and the Merkle paths.
        //    Each entry in queried_els stores a list of triples
        //    (F, F, i) indicating the position opened at each round and
        //    the two values at that round

        // 2.1 Prepare the answers. These include two values in each oracle,
        //     in positions (i, i XOR 1), (i >> 1, (i >> 1) XOR 1), ...
        //     respectively.
        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        let queries = prover_query_phase(transcript, comm, &trees, Spec::get_number_queries());
        end_timer!(query_timer);

        // 2.2 Prepare the merkle paths for these answers.
        let query_timer = start_timer!(|| "Basefold::open::build_query_result");
        let queries_with_merkle_path =
            QueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        end_timer!(timer);

        // End of query phase.----------------------------------

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::Single(
                queries_with_merkle_path,
            ),
            sumcheck_proof: None,
            trivial_proof: vec![],
        })
    }
}
