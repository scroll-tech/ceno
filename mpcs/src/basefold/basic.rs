use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use crate::{
    Error, PolynomialCommitmentScheme,
    basefold::{
        commit_phase::commit_phase,
        query_phase::{QueriesResultWithMerklePath, prover_query_phase, verifier_query_phase},
        structure::{BasefoldProof, ProofQueriesResultWithMerklePath},
    },
    sum_check::eq_xy_eval,
    util::{ext_to_usize, hash::write_digest_to_transcript, merkle_tree::MerkleTree},
};

use super::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams,
};

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

    pub(crate) fn basic_verify(
        vp: &BasefoldVerifierParams<E, Spec>,
        comm: &BasefoldCommitment<E>,
        point: &[E],
        eval: &E,
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::verify");

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
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_single();

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

        verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            final_message,
            roots,
            comm,
            eq.as_slice(),
            eval,
        );
        end_timer!(timer);

        Ok(())
    }
}
