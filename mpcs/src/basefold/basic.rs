use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{
    basefold::CommitPhaseInput,
    util::{field_type_iter_ext, merkle_tree::MerkleTree},
    Error,
};

use super::{
    commit_phase::CommitPhaseStrategy, query_phase::QueryCheckStrategy, structure::BasefoldProof,
    BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldStrategy, BasefoldVerifierParams,
};

pub(crate) struct ProverInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) poly: &'a ArcMultilinearExtension<'a, E>,
    pub(crate) comm: &'a BasefoldCommitmentWithData<E, Spec>,
    pub(crate) point: &'a [E],
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::ProverInputs<E, Spec>
    for ProverInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitmentWithData<E, Spec>] {
        std::slice::from_ref(self.comm)
    }
}

pub(crate) struct VerifierInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) comm: &'a BasefoldCommitment<E, Spec>,
    pub(crate) point: &'a [E],
    pub(crate) num_vars: usize,
    pub(crate) eval: E,
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::VerifierInputs<E, Spec>
    for VerifierInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitment<E, Spec>] {
        std::slice::from_ref(self.comm)
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

pub(crate) struct BasicBasefoldStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldStrategy<E, Spec> for BasicBasefoldStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type CommitPhaseStrategy = BasicCommitPhaseStrategy;
    type QueryCheckStrategy = BasicQueryCheckStrategy;
    type ProverInputs<'a> = ProverInputs<'a, E, Spec> where Spec: 'a;
    type VerifierInputs<'a> = VerifierInputs<'a, E, Spec> where Spec: 'a;

    fn trivial_proof(prover_inputs: &Self::ProverInputs<'_>) -> Option<BasefoldProof<E, Spec>> {
        let comm = prover_inputs.comm;
        let poly = prover_inputs.poly;

        // The encoded polynomial should at least have the number of
        // variables of the basecode, i.e., the size of the message
        // when the protocol stops. If the polynomial is smaller
        // the protocol won't work, and saves no verifier work anyway.
        // In this case, simply return the evaluations as trivial proof.
        if comm.is_trivial() {
            return Some(BasefoldProof::trivial(vec![poly.evaluations().clone()]));
        }
        None
    }

    #[allow(unused)]
    fn prepare_commit_phase_input(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &Self::ProverInputs<'_>,
        transcript: &mut Transcript<E>,
    ) -> Result<CommitPhaseInput<E>, Error> {
        let comm = prover_inputs.comm;
        let point = prover_inputs.point;

        assert!(comm.num_vars >= Spec::get_basecode_msg_size_log());
        assert!(comm.num_polys == 1);
        Ok(CommitPhaseInput {
            point: point.to_vec(),
            coeffs_outer: vec![],
            coeffs_inner: vec![],
            sumcheck_proof: None,
        })
    }

    #[allow(unused)]
    fn check_trivial_proof(
        verifier_inputs: &Self::VerifierInputs<'_>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let trivial_proof = &proof.trivial_proof;
        let merkle_tree =
            MerkleTree::<_, Spec::Hasher>::from_batch_leaves(trivial_proof.clone(), 2);
        let comm = verifier_inputs.comm;

        if comm.root() == merkle_tree.root() {
            return Ok(());
        } else {
            return Err(Error::MerkleRootMismatch);
        }
    }

    fn check_sizes(verifier_inputs: &Self::VerifierInputs<'_>) {
        let comm = verifier_inputs.comm;
        let num_vars = verifier_inputs.num_vars;

        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
            assert!(num_vars >= Spec::get_basecode_msg_size_log());
        }
    }

    #[allow(unused)]
    fn prepare_sumcheck_target_and_point_batching_coeffs(
        vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &Self::VerifierInputs<'_>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(E, Vec<E>, Vec<E>, Vec<E>), Error> {
        // For the basic version, everything is just the same
        Ok((
            verifier_inputs.eval,
            verifier_inputs.point.to_vec(),
            vec![],
            vec![],
        ))
    }
}

pub(crate) struct BasicCommitPhaseStrategy;
impl<E: ExtensionField> CommitPhaseStrategy<E> for BasicCommitPhaseStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_running_oracle<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        assert_eq!(comms.len(), 1);
        let comm = &comms[0];
        let codewords = comm.get_codewords();
        assert_eq!(codewords.len(), 1);
        let codeword = &codewords[0];
        field_type_iter_ext(codeword).collect()
    }

    fn initial_running_evals<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        assert_eq!(comms.len(), 1);
        let comm = &comms[0];
        assert_eq!(comm.polynomials_bh_evals.len(), 1);
        let evals = &comm.polynomials_bh_evals[0];
        field_type_iter_ext(evals).collect()
    }

    fn update_running_oracle<Spec: BasefoldSpec<E>>(
        _comms: &[BasefoldCommitmentWithData<E, Spec>],
        _running_oracle_len: usize,
        _index: usize,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> E {
        // The basic version only has one polynomial. No polynomial needs to
        // be updated to the oracle during the interaction.
        E::ZERO
    }
}

pub(crate) struct BasicQueryCheckStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> QueryCheckStrategy<E, Spec>
    for BasicQueryCheckStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_values(
        query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        let (left, right) = query_result
            .get_single_commitments_query()
            .single_leave_ext();
        vec![left, right]
    }

    fn pre_update_values(
        _query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
        _codeword_size_log: usize,
    ) -> Option<Vec<E>> {
        None
    }
}
