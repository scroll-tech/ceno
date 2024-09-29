use ff_ext::ExtensionField;
use multilinear_extensions::{
    virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{
    basefold::CommitPhaseInput,
    util::{
        arithmetic::inner_product, field_type_index_ext, hash::new_hasher, merkle_tree::MerkleTree,
    },
    Error,
};

use super::{
    commit_phase::CommitPhaseStrategy, query_phase::QueryCheckStrategy, structure::BasefoldProof,
    BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldStrategy, BasefoldVerifierParams,
};

pub(crate) struct ProverInputs<'a, E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) polys: &'a [ArcMultilinearExtension<'a, E>],
    pub(crate) comm: &'a BasefoldCommitmentWithData<E>,
    pub(crate) point: &'a [E],
}

impl<'a, E: ExtensionField> super::ProverInputs<E> for ProverInputs<'a, E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitmentWithData<E>] {
        std::slice::from_ref(self.comm)
    }
}

pub(crate) struct VerifierInputs<'a, E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) comm: &'a BasefoldCommitment<E>,
    pub(crate) point: &'a [E],
    pub(crate) num_vars: usize,
    pub(crate) evals: &'a [E],
}

impl<'a, E: ExtensionField> super::VerifierInputs<E> for VerifierInputs<'a, E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitment<E>] {
        std::slice::from_ref(self.comm)
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

pub(crate) struct BatchSimpleBasefoldStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldStrategy<E, Spec>
    for BatchSimpleBasefoldStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type CommitPhaseStrategy = BatchSimpleCommitPhaseStrategy;
    type QueryCheckStrategy = BatchSimpleQueryCheckStrategy;
    type ProverInputs<'a> = ProverInputs<'a, E>;
    type VerifierInputs<'a> = VerifierInputs<'a, E>;

    #[allow(unused)]
    fn trivial_proof(prover_inputs: &ProverInputs<'_, E>) -> Option<BasefoldProof<E>> {
        let comm = prover_inputs.comm;
        // The encoded polynomial should at least have the number of
        // variables of the basecode, i.e., the size of the message
        // when the protocol stops. If the polynomial is smaller
        // the protocol won't work, and saves no verifier work anyway.
        // In this case, simply return the evaluations as trivial proof.
        if comm.is_trivial::<Spec>() {
            return Some(BasefoldProof::trivial(comm.polynomials_bh_evals.clone()));
        }
        None
    }

    #[allow(unused)]
    fn prepare_commit_phase_input(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &ProverInputs<'_, E>,
        transcript: &mut Transcript<E>,
    ) -> Result<CommitPhaseInput<E>, Error> {
        let comm = prover_inputs.comm;
        let point = prover_inputs.point;
        let polys = prover_inputs.polys;

        assert!(comm.num_vars >= Spec::get_basecode_msg_size_log());
        assert_eq!(comm.num_polys, polys.len());

        let num_vars = polys[0].num_vars();

        polys
            .iter()
            .for_each(|poly| assert_eq!(poly.num_vars(), num_vars));
        assert_eq!(point.len(), num_vars);
        assert!(num_vars >= Spec::get_basecode_msg_size_log());

        let batch_size = polys.len();
        let batch_size_log = batch_size.next_power_of_two().ilog2() as usize;
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
        let eq_xt = build_eq_x_r_vec(&t)[..batch_size].to_vec();
        // let _target_sum = inner_product(evals, &eq_xt);

        Ok(CommitPhaseInput {
            point: point.to_vec(),
            coeffs_outer: vec![],
            coeffs_inner: eq_xt,
            sumcheck_proof: None,
        })
    }

    #[allow(unused)]
    fn check_trivial_proof(
        verifier_inputs: &VerifierInputs<'_, E>,
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let comm = verifier_inputs.comm;

        let hasher = new_hasher::<E::BaseField>();
        let trivial_proof = &proof.trivial_proof;
        let merkle_tree = MerkleTree::from_batch_leaves(trivial_proof.clone(), 2, &hasher);
        if comm.root() == merkle_tree.root() {
            return Ok(());
        } else {
            return Err(Error::MerkleRootMismatch);
        }
    }

    fn check_sizes(verifier_inputs: &VerifierInputs<'_, E>) {
        let comm = verifier_inputs.comm;
        let batch_size = verifier_inputs.evals.len();
        let num_vars = verifier_inputs.num_vars;
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }
        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
            assert!(num_vars >= Spec::get_basecode_msg_size_log());
        }
    }

    #[allow(unused)]
    fn prepare_sumcheck_target_and_point_batching_coeffs(
        vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &VerifierInputs<'_, E>,
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(E, Vec<E>, Vec<E>, Vec<E>), Error> {
        let evals = verifier_inputs.evals;
        let point = verifier_inputs.point;

        let batch_size = evals.len();
        let batch_size_log = batch_size.next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();

        Ok((inner_product(evals, &eq_xt), point.to_vec(), vec![], eq_xt))
    }
}

pub(crate) struct BatchSimpleCommitPhaseStrategy;
impl<E: ExtensionField> CommitPhaseStrategy<E> for BatchSimpleCommitPhaseStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_running_oracle(
        comms: &[BasefoldCommitmentWithData<E>],
        _coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E> {
        assert_eq!(comms.len(), 1);
        let comm = &comms[0];
        comm.batch_codewords(coeffs_inner)
    }

    fn initial_running_evals(
        comms: &[BasefoldCommitmentWithData<E>],
        _coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E> {
        assert_eq!(comms.len(), 1);
        let comm = &comms[0];

        let num_vars = comm.num_vars;
        (0..(1 << num_vars))
            .into_par_iter()
            .map(|i| {
                comm.polynomials_bh_evals
                    .iter()
                    .zip(coeffs_inner)
                    .map(|(eval, coeff)| field_type_index_ext(eval, i) * *coeff)
                    .sum()
            })
            .collect()
    }

    fn update_running_oracle(
        _comms: &[BasefoldCommitmentWithData<E>],
        _running_oracle_len: usize,
        _index: usize,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> E {
        // The simple batch version only has one group of polynomials.
        // No polynomial needs to
        // be updated to the oracle during the interaction.
        E::ZERO
    }
}

pub(crate) struct BatchSimpleQueryCheckStrategy;
impl<E: ExtensionField> QueryCheckStrategy<E> for BatchSimpleQueryCheckStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_values(
        query_result: &super::query_phase::BasefoldQueryResult<E>,
        _coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E> {
        let (left, right) = query_result
            .get_single_commitments_query()
            .batch(coeffs_inner);
        vec![left, right]
    }

    fn pre_update_values(
        _query_result: &super::query_phase::BasefoldQueryResult<E>,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
        _codeword_size_log: usize,
    ) -> Option<Vec<E>> {
        None
    }
}
