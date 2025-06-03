use ff_ext::ExtensionField;
use std::{collections::BTreeMap, sync::Arc};

use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    util::ceil_log2,
};
use p3::field::PrimeCharacteristicRing;
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use transcript::Transcript;
use witness::{RowMajorMatrix, next_pow2_instance_padding};

use crate::{
    error::ZKVMError,
    scheme::{constants::NUM_FANIN_LOGUP, hal::ProofInput},
    structs::{ProvingKey, TowerProofs, ZKVMProvingKey, ZKVMWitnesses},
};

use super::{
    PublicValues, ZKVMChipProof, ZKVMProof,
    hal::{ProverBackend, ProverDevice},
};

type CreateTableProof<E> = (ZKVMChipProof<E>, Point<E>);

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, PB, PD> {
    pub pk: Arc<ZKVMProvingKey<E, PCS>>,
    device: PD,
    _marker: std::marker::PhantomData<PB>,
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS>,
    PD: ProverDevice<PB>,
> ZKVMProver<E, PCS, PB, PD>
{
    pub fn new(pk: ZKVMProvingKey<E, PCS>, device: PD) -> Self {
        let pk = Arc::new(pk);
        ZKVMProver {
            pk,
            device,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB>,
> ZKVMProver<E, PCS, PB, PD>
{
    /// create proof for zkvm execution
    #[tracing::instrument(
        skip_all,
        name = "ZKVM_create_proof",
        fields(profiling_1),
        level = "trace"
    )]
    pub fn create_proof(
        &self,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues,
        mut transcript: impl Transcript<E>,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let raw_pi = pi.to_vec::<E>();
        let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
        let mut opcode_proofs: BTreeMap<usize, ZKVMChipProof<E>> = BTreeMap::new();
        let mut table_proofs: BTreeMap<usize, ZKVMChipProof<E>> = BTreeMap::new();

        let span = entered_span!("commit_to_pi", profiling_1 = true);
        // including raw public input to transcript
        for v in raw_pi.iter().flatten() {
            transcript.append_field_element(v);
        }
        exit_span!(span);

        let pi: Vec<MultilinearExtension<E>> =
            raw_pi.iter().map(|p| p.to_vec().into_mle()).collect();

        // commit to fixed commitment
        let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
        if let Some(fixed_commit) = &self.pk.fixed_commit {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }
        exit_span!(span);

        // commit to main traces
        let circuit_name_index_mapping = self
            .pk
            .circuit_pks
            .keys()
            .enumerate()
            .map(|(k, v)| (v, k))
            .collect::<BTreeMap<_, _>>();
        let mut wits_instances = BTreeMap::new();
        let mut wits_rmms = BTreeMap::new();
        let mut structural_wits = BTreeMap::new();

        let mut num_instances = Vec::with_capacity(self.pk.circuit_pks.len());
        for (index, (circuit_name, _)) in self.pk.circuit_pks.iter().enumerate() {
            if let Some(num_instance) = witnesses
                .get_opcode_witness(circuit_name)
                .or_else(|| {
                    witnesses
                        .get_table_witness(circuit_name)
                        .map(|rmms| &rmms[0])
                })
                .map(|rmm| rmm.num_instances())
                .and_then(|num_instance| {
                    if num_instance > 0 {
                        Some(num_instance)
                    } else {
                        None
                    }
                })
            {
                num_instances.push((index, num_instance));
            }
        }

        // write (circuit_size, num_var) to transcript
        for (circuit_size, num_var) in &num_instances {
            transcript.append_message(&circuit_size.to_le_bytes());
            transcript.append_message(&num_var.to_le_bytes());
        }

        let commit_to_traces_span = entered_span!("commit_to_traces", profiling_1 = true);
        // commit to opcode circuits first and then commit to table circuits, sorted by name
        for (circuit_name, mut rmm) in witnesses.into_iter_sorted() {
            let witness_rmm = rmm.remove(0);
            // only table got structural witness
            let structural_witness_rmm = if !rmm.is_empty() {
                rmm.remove(0)
            } else {
                RowMajorMatrix::empty()
            };
            let num_instances = witness_rmm.num_instances();
            wits_instances.insert(circuit_name.clone(), num_instances);
            if num_instances == 0 {
                continue;
            }

            let structural_witness = structural_witness_rmm.to_mles();
            wits_rmms.insert(circuit_name_index_mapping[&circuit_name], witness_rmm);
            structural_wits.insert(circuit_name, (structural_witness, num_instances));
        }

        debug_assert_eq!(num_instances.len(), wits_rmms.len());

        // batch commit witness
        let span = entered_span!("batch commit to witness", profiling_2 = true);
        let (mut witness_mles, witness_data, witin_commit) = self.device.commit_traces(wits_rmms);
        exit_span!(span);
        exit_span!(commit_to_traces_span);

        // transfer pk to device
        let device_pk = self.device.transport_proving_key(self.pk.clone());
        let mut fixed_mles = device_pk.fixed_mles;

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::trace!("challenges in prover: {:?}", challenges);

        let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);
        let (points, evaluations) = self.pk.circuit_pks.iter().enumerate().try_fold(
            (vec![], vec![]),
            |(mut points, mut evaluations), (index, (circuit_name, pk))| {
                let num_instances = *wits_instances
                    .get(circuit_name)
                    .ok_or(ZKVMError::WitnessNotFound(circuit_name.to_string()))?;
                if num_instances == 0 {
                    // do nothing without point and evaluation insertion
                    return Ok::<(Vec<_>, Vec<Vec<_>>), ZKVMError>((points, evaluations));
                }
                transcript.append_field_element(&E::BaseField::from_u64(index as u64));
                // TODO: add an enum for circuit type either in constraint_system or vk
                let cs = pk.get_cs();
                let witness_mle = witness_mles.drain(..cs.num_witin as usize).collect_vec();
                let is_opcode_circuit = cs.lk_table_expressions.is_empty()
                    && cs.r_table_expressions.is_empty()
                    && cs.w_table_expressions.is_empty();

                let public_inputs = self.device.transport_mles(pi.clone());
                if is_opcode_circuit {
                    tracing::trace!(
                        "opcode circuit {} has {} witnesses, {} reads, {} writes, {} lookups",
                        circuit_name,
                        cs.num_witin,
                        cs.r_expressions.len(),
                        cs.w_expressions.len(),
                        cs.lk_expressions.len(),
                    );
                    let (opcode_proof, input_opening_point) = self.create_chip_proof(
                        circuit_name,
                        pk,
                        vec![],
                        witness_mle,
                        vec![],
                        public_inputs,
                        num_instances,
                        &mut transcript,
                        &challenges,
                    )?;
                    tracing::trace!(
                        "generated proof for opcode {} with num_instances={}",
                        circuit_name,
                        num_instances
                    );
                    points.push(input_opening_point);
                    evaluations.push(opcode_proof.wits_in_evals.clone());
                    opcode_proofs.insert(index, opcode_proof);
                } else {
                    let fixed_mle = fixed_mles.remove(circuit_name).unwrap_or(vec![]);
                    let structural_witness = self.device.transport_mles(
                        structural_wits
                            .remove(circuit_name)
                            .ok_or(ZKVMError::WitnessNotFound(circuit_name.clone()))?
                            .0,
                    );
                    assert!(!witness_mle.is_empty());
                    assert!(num_instances.is_power_of_two());
                    let (table_proof, input_opening_point) = self.create_chip_proof(
                        circuit_name,
                        pk,
                        fixed_mle,
                        witness_mle,
                        structural_witness,
                        public_inputs,
                        num_instances,
                        &mut transcript,
                        &challenges,
                    )?;
                    points.push(input_opening_point);
                    evaluations.push(table_proof.wits_in_evals.clone());
                    if cs.num_fixed > 0 {
                        evaluations.push(table_proof.fixed_in_evals.clone());
                    }
                    table_proofs.insert(index, table_proof);
                    // for (idx, eval) in pi_in_evals {
                    //     pi_evals[idx] = eval;
                    // }
                };
                Ok((points, evaluations))
            },
        )?;

        // batch opening pcs
        // generate static info from prover key for expected num variable
        let circuit_num_polys = self
            .pk
            .circuit_pks
            .values()
            .map(|pk| (pk.get_cs().num_witin as usize, pk.get_cs().num_fixed))
            .collect_vec();
        let pcs_opening = entered_span!("pcs_opening");
        let (evaluations, mpcs_opening_proof) = self.device.open(
            witness_data,
            Some(device_pk.pcs_data),
            points,
            &circuit_num_polys,
            &num_instances,
            &mut transcript,
        );

        exit_span!(pcs_opening);

        let vm_proof = ZKVMProof::new(
            raw_pi,
            pi_evals,
            opcode_proofs,
            table_proofs,
            witin_commit,
            mpcs_opening_proof,
            // verifier need this information from prover to achieve non-uniform design.
            num_instances,
        );
        exit_span!(main_proofs_span);

        Ok(vm_proof)
    }

    #[allow(clippy::too_many_arguments)]
    /// create proof for opcode and table circuits
    ///
    /// for each read/write/logup expression, we pack all records of that type
    /// into a single tower tree, and then feed these trees into tower prover.
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=name, profiling_2), level="trace")]
    pub fn create_chip_proof<'a>(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        fixed: Vec<PB::MultilinearPoly<'a>>,
        witness: Vec<PB::MultilinearPoly<'a>>,
        structural_witness: Vec<PB::MultilinearPoly<'a>>,
        public_input: Vec<PB::MultilinearPoly<'a>>,
        num_instances: usize,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<CreateTableProof<E>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let chip_record_alpha = challenges[0];
        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();

        // opcode must have at least one read/write/lookup
        let is_opcode_circuit = !cs.lk_expressions.is_empty()
            || !cs.r_expressions.is_empty()
            || !cs.w_expressions.is_empty();
        // table must have at least one read/write/lookup
        let is_table_circuit = !cs.lk_table_expressions.is_empty()
            || !cs.r_table_expressions.is_empty()
            || !cs.w_table_expressions.is_empty();

        let input = ProofInput {
            witness,
            fixed,
            structural_witness,
            public_input,
            num_instances,
        };
        let (mut out_evals, records, prod_specs, lookup_specs) =
            self.device.build_tower_witness(cs, &input, challenges);

        let lk_out_evals = out_evals.pop().unwrap();
        let w_out_evals = out_evals.pop().unwrap();
        let r_out_evals = out_evals.pop().unwrap();

        let (rt_tower, tower_proof) =
            self.device
                .prove_tower_relation(prod_specs, lookup_specs, NUM_FANIN_LOGUP, transcript);

        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            log2_num_instances,
        );

        let (input_opening_point, main_sumcheck_proofs) = self.device.prove_main_constraints(
            rt_tower,
            &tower_proof,
            records,
            &input,
            cs,
            challenges,
            transcript,
        );

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                tower_proof,
                fixed_in_evals: vec![],
                wits_in_evals: vec![],
            },
            input_opening_point,
        ))
    }
}

/// TowerProofs
impl<E: ExtensionField> TowerProofs<E> {
    pub fn new(prod_spec_size: usize, logup_spec_size: usize) -> Self {
        TowerProofs {
            proofs: vec![],
            prod_specs_eval: vec![vec![]; prod_spec_size],
            logup_specs_eval: vec![vec![]; logup_spec_size],
            prod_specs_points: vec![vec![]; prod_spec_size],
            logup_specs_points: vec![vec![]; logup_spec_size],
        }
    }
    pub fn push_sumcheck_proofs(&mut self, proofs: Vec<IOPProverMessage<E>>) {
        self.proofs.push(proofs);
    }

    pub fn push_prod_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.prod_specs_eval[spec_index].push(evals);
        self.prod_specs_points[spec_index].push(point);
    }

    pub fn push_logup_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.logup_specs_eval[spec_index].push(evals);
        self.logup_specs_points[spec_index].push(point);
    }

    pub fn prod_spec_size(&self) -> usize {
        self.prod_specs_eval.len()
    }

    pub fn logup_spec_size(&self) -> usize {
        self.logup_specs_eval.len()
    }
}
