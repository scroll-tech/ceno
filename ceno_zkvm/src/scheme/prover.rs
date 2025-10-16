use ff_ext::ExtensionField;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    hal::ProverBackend,
};
use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    sync::Arc,
};

use crate::scheme::hal::MainSumcheckEvals;
use gkr_iop::hal::MultilinearPolynomial;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Instance,
    mle::{IntoMLE, MultilinearExtension},
};
use p3::field::FieldAlgebra;
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use transcript::Transcript;
use witness::RowMajorMatrix;

use super::{PublicValues, ZKVMChipProof, ZKVMProof, hal::ProverDevice};
use crate::{
    error::ZKVMError,
    scheme::{hal::ProofInput, utils::build_main_witness},
    structs::{ProvingKey, TowerProofs, ZKVMProvingKey, ZKVMWitnesses},
};

type CreateTableProof<E> = (ZKVMChipProof<E>, HashMap<usize, E>, Point<E>);

pub type ZkVMCpuProver<E, PCS> =
    ZKVMProver<E, PCS, CpuBackend<E, PCS>, CpuProver<CpuBackend<E, PCS>>>;

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, PB, PD> {
    pub pk: Arc<ZKVMProvingKey<E, PCS>>,
    device: PD,
    _marker: PhantomData<PB>,
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
            _marker: PhantomData,
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
        &mut self,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues,
        mut transcript: impl Transcript<E> + 'static,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let raw_pi = pi.to_vec::<E>();
        let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
        let mut chip_proofs: BTreeMap<usize, ZKVMChipProof<E>> = BTreeMap::new();

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

        // keep track of circuit name to index mapping
        let circuit_name_index_mapping = self
            .pk
            .circuit_pks
            .keys()
            .enumerate()
            .map(|(k, v)| (v, k))
            .collect::<BTreeMap<_, _>>();
        // only keep track of circuits that have non-zero instances
        let mut num_instances = Vec::with_capacity(self.pk.circuit_pks.len());
        let mut num_instances_with_rotation = Vec::with_capacity(self.pk.circuit_pks.len());
        let mut circuit_name_num_instances_mapping = BTreeMap::new();
        for (index, (circuit_name, ProvingKey { vk, .. })) in self.pk.circuit_pks.iter().enumerate()
        {
            // num_instance from witness might include rotation
            if let Some(num_instance) = witnesses
                .get_opcode_witness(circuit_name)
                .or_else(|| witnesses.get_table_witness(circuit_name))
                .map(|rmms| {
                    if rmms[0].num_instances() == 0 {
                        rmms[1].num_instances()
                    } else {
                        rmms[0].num_instances()
                    }
                })
                .and_then(|num_instance| {
                    if num_instance > 0 {
                        Some(num_instance)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    vk.get_cs().is_static_circuit().then(|| {
                        self.pk
                            .circuit_index_fixed_num_instances
                            .get(&index)
                            .copied()
                            .unwrap_or(0)
                    })
                })
            {
                num_instances.push((
                    index,
                    num_instance >> vk.get_cs().rotation_vars().unwrap_or(0),
                ));
                num_instances_with_rotation.push((index, num_instance));
                circuit_name_num_instances_mapping.insert(
                    circuit_name,
                    num_instance >> vk.get_cs().rotation_vars().unwrap_or(0),
                );
            }
        }

        // write (circuit_idx, num_var) to transcript
        for (circuit_idx, num_instance) in &num_instances {
            transcript.append_message(&circuit_idx.to_le_bytes());
            transcript.append_message(&num_instance.to_le_bytes());
        }

        let commit_to_traces_span = entered_span!("batch commit to traces", profiling_1 = true);
        let mut wits_rmms = BTreeMap::new();
        let mut structural_wits = BTreeMap::new();

        // commit to opcode circuits first and then commit to table circuits, sorted by name
        for (circuit_name, mut rmm) in witnesses.into_iter_sorted() {
            let witness_rmm = rmm.remove(0);
            // only table got structural witness
            let structural_witness_rmm = if !rmm.is_empty() {
                rmm.remove(0)
            } else {
                RowMajorMatrix::empty()
            };

            if witness_rmm.num_instances() > 0 {
                wits_rmms.insert(circuit_name_index_mapping[&circuit_name], witness_rmm);
            }
            if structural_witness_rmm.num_instances() > 0 {
                let num_instances = circuit_name_num_instances_mapping
                    .get(&circuit_name)
                    .unwrap();
                let structural_witness = structural_witness_rmm.to_mles();
                structural_wits.insert(circuit_name, (structural_witness, num_instances));
            }
        }

        // commit to witness traces in batch
        let (mut witness_mles, witness_data, witin_commit) = self.device.commit_traces(wits_rmms);
        PCS::write_commitment(&witin_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        exit_span!(commit_to_traces_span);

        // transfer pk to device
        let transfer_pk_span = entered_span!("transfer pk to device", profiling_1 = true);
        let device_pk = self.device.transport_proving_key(self.pk.clone());
        let mut fixed_mles = device_pk.fixed_mles;
        exit_span!(transfer_pk_span);

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("global challenges in prover: {:?}", challenges);

        let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);
        let (points, evaluations) = self.pk.circuit_pks.iter().enumerate().try_fold(
            (vec![], vec![]),
            |(mut points, mut evaluations), (index, (circuit_name, pk))| {
                let num_instances = circuit_name_num_instances_mapping
                    .get(&circuit_name)
                    .copied()
                    .unwrap_or(0);
                let cs = pk.get_cs();
                if num_instances == 0 {
                    // we need to drain respective fixed when num_instances is 0
                    if cs.num_fixed() > 0 {
                        let _ = fixed_mles.drain(..cs.num_fixed()).collect_vec();
                    }
                    return Ok::<(Vec<_>, Vec<Vec<_>>), ZKVMError>((points, evaluations));
                }
                transcript.append_field_element(&E::BaseField::from_canonical_u64(index as u64));
                // TODO: add an enum for circuit type either in constraint_system or vk
                let witness_mle = witness_mles
                    .drain(..cs.num_witin())
                    .map(|mle| mle.into())
                    .collect_vec();
                let structural_witness = self.device.transport_mles(
                    structural_wits
                        .remove(circuit_name)
                        .map(|(sw, _)| sw)
                        .unwrap_or(vec![]),
                );
                let fixed = fixed_mles.drain(..cs.num_fixed()).collect_vec();
                let public_input = self.device.transport_mles(pi.clone());
                let mut input = ProofInput {
                    witness: witness_mle,
                    fixed,
                    structural_witness,
                    public_input,
                    num_instances,
                };

                if cs.is_opcode_circuit() {
                    let (opcode_proof, _, input_opening_point) = self.create_chip_proof(
                        circuit_name,
                        pk,
                        input,
                        &mut transcript,
                        &challenges,
                    )?;
                    tracing::trace!(
                        "generated proof for opcode {} with num_instances={}",
                        circuit_name,
                        num_instances
                    );
                    points.push(input_opening_point);
                    evaluations.push(vec![opcode_proof.wits_in_evals.clone()]);
                    chip_proofs.insert(index, opcode_proof);
                } else {
                    // FIXME: PROGRAM table circuit is not guaranteed to have 2^n instances
                    input.num_instances = 1 << input.log2_num_instances();
                    let (mut table_proof, pi_in_evals, input_opening_point) = self
                        .create_chip_proof(circuit_name, pk, input, &mut transcript, &challenges)?;
                    if cs.num_witin() > 0 || cs.num_fixed() > 0 {
                        points.push(input_opening_point);
                        evaluations.push(vec![
                            table_proof.wits_in_evals.clone(),
                            table_proof.fixed_in_evals.clone(),
                        ]);
                    } else {
                        assert!(table_proof.wits_in_evals.is_empty());
                        assert!(table_proof.fixed_in_evals.is_empty());
                    }
                    // FIXME: PROGRAM table circuit is not guaranteed to have 2^n instances
                    table_proof.num_instances = num_instances;
                    chip_proofs.insert(index, table_proof);
                    for (idx, eval) in pi_in_evals {
                        pi_evals[idx] = eval;
                    }
                };
                Ok((points, evaluations))
            },
        )?;
        exit_span!(main_proofs_span);

        // batch opening pcs
        // generate static info from prover key for expected num variable
        let pcs_opening = entered_span!("pcs_opening", profiling_1 = true);
        let mpcs_opening_proof = self.device.open(
            witness_data,
            Some(device_pk.pcs_data),
            points,
            evaluations,
            &mut transcript,
        );
        exit_span!(pcs_opening);

        let vm_proof = ZKVMProof::new(
            raw_pi,
            pi_evals,
            chip_proofs,
            witin_commit,
            mpcs_opening_proof,
        );

        Ok(vm_proof)
    }

    /// create proof for opcode and table circuits
    ///
    /// for each read/write/logup expression, we pack all records of that type
    /// into a single tower tree, and then feed these trees into tower prover.
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=name, profiling_2
    ), level = "trace")]
    pub fn create_chip_proof<'a>(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        input: ProofInput<'a, PB>,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<CreateTableProof<E>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let log2_num_instances = input.log2_num_instances();
        let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);

        // build main witness
        let (records, is_padded) =
            build_main_witness::<E, PCS, PB, PD>(&self.device, cs, &input, challenges);

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        // prove the product and logup sum relation between layers in tower
        // (internally calls build_tower_witness)
        let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) = self
            .device
            .prove_tower_relation(cs, &input, &records, is_padded, challenges, transcript);
        exit_span!(span);

        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            num_var_with_rotation,
        );

        // 1. prove the main constraints among witness polynomials
        // 2. prove the relation between last layer in the tower and read/write/logup records
        let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) = self
            .device
            .prove_main_constraints(rt_tower, &input, cs, challenges, transcript)?;
        let MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        } = evals;

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_name_map().is_empty() {
            let span = entered_span!("pi::evals");
            for &Instance(idx) in cs.instance_name_map().keys() {
                let poly = &input.public_input[idx];
                pi_in_evals.insert(
                    idx,
                    poly.eval(input_opening_point[..poly.num_vars()].to_vec()),
                );
            }
            exit_span!(span);
        }

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                gkr_iop_proof,
                tower_proof,
                fixed_in_evals,
                wits_in_evals,
                num_instances: input.num_instances,
            },
            pi_in_evals,
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
