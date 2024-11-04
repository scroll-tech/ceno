use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{
    util::{arithmetic::inner_product, field_type_index_ext, log2_strict},
    Error,
};

use super::{
    commit_phase::CommitPhaseStrategy, query_phase::QueryCheckStrategy, structure::BasefoldProof,
    BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldStrategy, BasefoldVerifierParams, CommitPhaseInput,
};

pub(crate) struct ProverInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) polys: &'a [&'a [ArcMultilinearExtension<'a, E>]],
    pub(crate) comms: &'a [BasefoldCommitmentWithData<E, Spec>],
    pub(crate) point: &'a [E],
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::ProverInputs<E, Spec>
    for ProverInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitmentWithData<E, Spec>] {
        self.comms
    }
}

pub(crate) struct VerifierInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) comms: &'a [BasefoldCommitment<E, Spec>],
    pub(crate) point: &'a [E],
    pub(crate) num_vars: usize,
    pub(crate) evals: &'a [&'a [E]],
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::VerifierInputs<E, Spec>
    for VerifierInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitment<E, Spec>] {
        self.comms
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

pub(crate) struct BatchVLOPBasefoldStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldStrategy<E, Spec>
    for BatchVLOPBasefoldStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type CommitPhaseStrategy = BatchVLOPCommitPhaseStrategy;
    type QueryCheckStrategy = BatchVLOPQueryCheckStrategy;
    type ProverInputs<'a> = ProverInputs<'a, E, Spec> where Spec: 'a;
    type VerifierInputs<'a> = VerifierInputs<'a, E, Spec> where Spec: 'a;

    #[allow(unused)]
    fn trivial_proof(prover_inputs: &ProverInputs<'_, E, Spec>) -> Option<BasefoldProof<E, Spec>> {
        // The encoded polynomial should at least have the number of
        // variables of the basecode, i.e., the size of the message
        // when the protocol stops. If the polynomial is smaller
        // the protocol won't work, and saves no verifier work anyway.
        // In the current implementation, the batch vlop case simply
        // ignores this case and crashes on trivial proof.
        prover_inputs.comms.iter().for_each(|comm| {
            assert!(!comm.is_trivial());
        });
        None
    }

    #[allow(unused)]
    fn prepare_commit_phase_input(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &ProverInputs<'_, E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<CommitPhaseInput<E>, Error> {
        let comms = prover_inputs.comms;
        let polys = prover_inputs.polys;
        let num_vars = comms.iter().map(|comm| comm.num_vars).max().unwrap();
        let min_num_vars = comms.iter().map(|comm| comm.num_vars).min().unwrap();
        assert!(min_num_vars >= Spec::get_basecode_msg_size_log());

        comms.iter().for_each(|comm| {
            assert!(!comm.is_trivial());
        });

        polys
            .iter()
            .zip(prover_inputs.comms.iter())
            .for_each(|(polys, comm)| {
                let num_vars = comm.num_vars;
                assert_eq!(polys.len(), comm.num_polys);
                polys
                    .iter()
                    .for_each(|poly| assert_eq!(poly.num_vars(), num_vars));
                assert!(prover_inputs.point.len() >= num_vars);
            });

        assert_eq!(prover_inputs.polys.len(), prover_inputs.comms.len());

        let batch_size_outer = polys.len();
        let batch_size_outer_log = batch_size_outer.next_power_of_two().ilog2() as usize;
        let t_outer = (0..batch_size_outer_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let batch_size_inner = polys.iter().map(|polys| polys.len()).max().unwrap();
        let batch_size_inner_log = batch_size_inner.next_power_of_two().ilog2() as usize;
        let t_inner = (0..batch_size_inner_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let eq_xt_outer = build_eq_x_r_vec(&t_outer)[..batch_size_outer].to_vec();
        let eq_xt_inner = build_eq_x_r_vec(&t_inner)[..batch_size_inner].to_vec();

        Ok(CommitPhaseInput {
            point: prover_inputs.point[..num_vars].to_vec(),
            coeffs_outer: eq_xt_outer,
            coeffs_inner: eq_xt_inner,
            sumcheck_proof: None,
        })
    }

    #[allow(unused)]
    fn check_trivial_proof(
        verifier_inputs: &VerifierInputs<'_, E, Spec>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        assert!(!proof.is_trivial());

        Ok(())
    }

    fn check_sizes(verifier_inputs: &VerifierInputs<'_, E, Spec>) {
        let num_vars = verifier_inputs.num_vars;
        assert!(verifier_inputs.point.len() >= num_vars);
        verifier_inputs
            .comms
            .iter()
            .zip_eq(verifier_inputs.evals)
            .for_each(|(comm, evals)| {
                if let Some(comm_num_vars) = comm.num_vars {
                    assert!(comm_num_vars <= num_vars);
                    assert!(comm_num_vars >= Spec::get_basecode_msg_size_log());
                }
                if let Some(num_polys) = comm.num_polys {
                    assert_eq!(num_polys, evals.len());
                }
            });
    }

    #[allow(unused)]
    fn prepare_sumcheck_target_and_point_batching_coeffs(
        vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &VerifierInputs<'_, E, Spec>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(E, Vec<E>, Vec<E>, Vec<E>), Error> {
        let batch_size_outer = verifier_inputs.evals.len();
        let batch_size_outer_log = batch_size_outer.next_power_of_two().ilog2() as usize;
        let t_outer = (0..batch_size_outer_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let batch_size_inner = verifier_inputs
            .evals
            .iter()
            .map(|eval| eval.len())
            .max()
            .unwrap();
        let batch_size_inner_log = batch_size_inner.next_power_of_two().ilog2() as usize;
        let t_inner = (0..batch_size_inner_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let eq_xt_outer = build_eq_x_r_vec(&t_outer)[..batch_size_outer].to_vec();
        let eq_xt_inner = build_eq_x_r_vec(&t_inner)[..batch_size_inner].to_vec();

        let target_sum = inner_product(
            &verifier_inputs
                .evals
                .iter()
                .map(|evals| inner_product::<E>(evals.iter(), &eq_xt_inner[..evals.len()]))
                .collect::<Vec<_>>(),
            &eq_xt_outer[..verifier_inputs.evals.len()],
        );

        Ok((
            target_sum,
            verifier_inputs.point[..verifier_inputs.num_vars].to_vec(),
            eq_xt_outer,
            eq_xt_inner,
        ))
    }
}

pub(crate) struct BatchVLOPCommitPhaseStrategy;
impl<E: ExtensionField> CommitPhaseStrategy<E> for BatchVLOPCommitPhaseStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_running_oracle<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        // Initialize to zero oracle, and before each folding. All the
        // committed polynomial values are added to the oracle in the matching
        // round.
        let codeword_size = comms.iter().map(|comm| comm.codeword_size()).max().unwrap();
        vec![E::ZERO; codeword_size]
    }

    fn initial_running_evals<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E> {
        let num_vars = comms.iter().map(|comm| comm.num_vars).max().unwrap();
        let build_evals_timer = start_timer!(|| "Basefold build initial sumcheck evals");
        // Unlike the FRI part, the sum-check part still follows the original procedure,
        // and linearly combine all the polynomials once for all
        let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
        comms.iter().enumerate().for_each(|(index, comm)| {
            sum_of_all_evals_for_sumcheck
                .par_iter_mut()
                .enumerate()
                .for_each(|(pos, r)| {
                    // Evaluating the multilinear polynomial outside of its interpolation hypercube
                    // is equivalent to repeating each element in place.
                    // Here is the tricky part: the bh_evals are stored in big endian, but we want
                    // to align the polynomials to the variable with index 0 before adding them
                    // together. So each element is repeated by
                    // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                    *r += comm
                        .polynomials_bh_evals
                        .iter()
                        .enumerate()
                        .map(|(i, bh_evals)| {
                            field_type_index_ext(
                                bh_evals,
                                pos >> (num_vars - log2_strict(comm.polynomials_bh_evals[0].len())),
                            ) * coeffs_inner[i]
                        })
                        .sum::<E>()
                        * coeffs_outer[index]
                });
        });
        end_timer!(build_evals_timer);
        sum_of_all_evals_for_sumcheck
    }

    fn update_running_oracle<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        running_oracle_len: usize,
        index: usize,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> E {
        comms
            .iter()
            .enumerate()
            .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
            .map(|(i, comm)| comm.batch_codewords_at(coeffs_inner, index) * coeffs_outer[i])
            .sum()
    }
}

pub(crate) struct BatchVLOPQueryCheckStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> QueryCheckStrategy<E, Spec>
    for BatchVLOPQueryCheckStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_values(
        _query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        // Initialize the current values to zero, and before each round
        // add the matching commitments to the current values
        vec![E::ZERO, E::ZERO]
    }

    fn pre_update_values(
        query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
        codeword_size_log: usize,
    ) -> Option<Vec<E>> {
        let matching_pairs =
            query_result.get_commitments_query_matching_size_log(codeword_size_log);
        let (left, right) = matching_pairs
            .iter()
            .map(|(index, pair)| {
                let pair = pair.batch(coeffs_inner);
                (pair.0 * coeffs_outer[*index], pair.1 * coeffs_outer[*index])
            })
            .fold((E::ZERO, E::ZERO), |(s, t), (a, b)| (s + a, t + b));
        Some(vec![left, right])
    }
}
