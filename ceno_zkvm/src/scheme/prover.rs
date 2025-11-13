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

use crate::scheme::{constants::SEPTIC_EXTENSION_DEGREE, hal::MainSumcheckEvals};
use either::Either;
use gkr_iop::hal::MultilinearPolynomial;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, Instance,
    mle::{IntoMLE, MultilinearExtension},
};
use p3::field::FieldAlgebra;
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use transcript::Transcript;

use super::{PublicValues, ZKVMChipProof, ZKVMProof, hal::ProverDevice};
use crate::{
    e2e::ShardContext,
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
        &self,
        shard_ctx: &ShardContext,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues,
        mut transcript: impl Transcript<E> + 'static,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let raw_pi = pi.to_vec::<E>();
        let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
        let mut chip_proofs = BTreeMap::new();

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
        if let Some(fixed_commit) = &self.pk.fixed_commit
            && shard_ctx.is_first_shard()
        {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        } else if let Some(fixed_commit) = &self.pk.fixed_no_omc_init_commit
            && !shard_ctx.is_first_shard()
        {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }
        exit_span!(span);

        // only keep track of circuits that have non-zero instances
        for (name, chip_inputs) in &witnesses.witnesses {
            let pk = self.pk.circuit_pks.get(name).ok_or(ZKVMError::VKNotFound(
                format!("proving key for circuit {} not found", name).into(),
            ))?;

            // include omc init tables iff it's in first shard
            if !shard_ctx.is_first_shard() && pk.get_cs().with_omc_init_only() {
                continue;
            }

            // num_instance from witness might include rotation
            let num_instances = chip_inputs
                .iter()
                .flat_map(|chip_input| &chip_input.num_instances)
                .map(|num_instance| num_instance >> pk.get_cs().rotation_vars().unwrap_or(0))
                .collect_vec();

            if num_instances.is_empty() {
                continue;
            }

            let circuit_idx = self.pk.circuit_name_to_index.get(name).unwrap();
            // write (circuit_idx, num_var) to transcript
            transcript.append_message(&circuit_idx.to_le_bytes());
            for num_instance in num_instances {
                transcript.append_message(&num_instance.to_le_bytes());
            }
        }

        // extract chip meta info before consuming witnesses
        // (circuit_name, num_instances)
        let name_and_instances = witnesses.get_witnesses_name_instance();

        let commit_to_traces_span = entered_span!("batch commit to traces", profiling_1 = true);
        let mut wits_rmms = BTreeMap::new();

        let mut structural_rmms = Vec::with_capacity(name_and_instances.len());
        // commit to opcode circuits first and then commit to table circuits, sorted by name
        for (i, chip_input) in witnesses.into_iter_sorted().enumerate() {
            let [witness_rmm, structural_witness_rmm] = chip_input.witness_rmms;

            if witness_rmm.num_instances() > 0 {
                wits_rmms.insert(i, witness_rmm);
            }
            structural_rmms.push(structural_witness_rmm);
        }

        // commit to witness traces in batch
        let (mut witness_mles, witness_data, witin_commit) = self.device.commit_traces(wits_rmms);
        PCS::write_commitment(&witin_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        exit_span!(commit_to_traces_span);

        // transfer pk to device
        let transfer_pk_span = entered_span!("transfer pk to device", profiling_1 = true);
        let device_pk = self
            .device
            .transport_proving_key(shard_ctx, self.pk.clone());
        let mut fixed_mles = device_pk.fixed_mles;
        exit_span!(transfer_pk_span);

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("global challenges in prover: {:?}", challenges);

        let public_input_span = entered_span!("public_input", profiling_1 = true);
        let public_input = self.device.transport_mles(&pi);
        exit_span!(public_input_span);

        let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);

        let mut points = Vec::new();
        let mut evaluations = Vec::new();
        for ((circuit_name, num_instances), structural_rmm) in name_and_instances
            .into_iter()
            .zip_eq(structural_rmms.into_iter())
        {
            let circuit_idx = self
                .pk
                .circuit_name_to_index
                .get(&circuit_name)
                .cloned()
                .expect("invalid circuit {} not exist in ceno zkvm");
            let pk = self.pk.circuit_pks.get(&circuit_name).unwrap();
            let cs = pk.get_cs();
            if !shard_ctx.is_first_shard() && cs.with_omc_init_only() {
                assert!(num_instances.is_empty());
                // skip drain respective fixed because we use different set of fixed commitment
                continue;
            }
            if num_instances.is_empty() {
                // we need to drain respective fixed when num_instances is 0
                if cs.num_fixed() > 0 {
                    let _ = fixed_mles.drain(..cs.num_fixed()).collect_vec();
                }
                continue;
            }
            transcript.append_field_element(&E::BaseField::from_canonical_u64(circuit_idx as u64));

            // TODO: add an enum for circuit type either in constraint_system or vk
            let witness_mle = witness_mles
                .drain(..cs.num_witin())
                .map(|mle| mle.into())
                .collect_vec();

            let structural_witness_span = entered_span!("structural_witness", profiling_2 = true);
            let structural_mles = structural_rmm.to_mles();
            let structural_witness = self.device.transport_mles(&structural_mles);
            exit_span!(structural_witness_span);

            let fixed = fixed_mles.drain(..cs.num_fixed()).collect_vec();
            let input = ProofInput {
                witness: witness_mle,
                fixed,
                structural_witness,
                public_input: public_input.clone(),
                pub_io_evals: pi_evals.iter().map(|p| Either::Right(*p)).collect(),
                num_instances: num_instances.clone(),
                has_ecc_ops: cs.has_ecc_ops(),
            };

            let (opcode_proof, pi_in_evals, input_opening_point) = self.create_chip_proof(
                circuit_name.as_str(),
                pk,
                input,
                &mut transcript,
                &challenges,
            )?;
            tracing::trace!(
                "generated proof for opcode {} with num_instances={:?}",
                circuit_name,
                num_instances
            );
            if cs.num_witin() > 0 || cs.num_fixed() > 0 {
                points.push(input_opening_point);
                evaluations.push(vec![
                    opcode_proof.wits_in_evals.clone(),
                    opcode_proof.fixed_in_evals.clone(),
                ]);
            } else {
                assert!(opcode_proof.wits_in_evals.is_empty());
                assert!(opcode_proof.fixed_in_evals.is_empty());
            }
            chip_proofs
                .entry(circuit_idx)
                .or_insert(vec![])
                .push(opcode_proof);
            for (idx, eval) in pi_in_evals {
                pi_evals[idx] = eval;
            }
        }
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

        // run ecc quark prover
        let ecc_proof = if !cs.zkvm_v1_css.ec_final_sum.is_empty() {
            let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
            let ec_point_exprs = &cs.zkvm_v1_css.ec_point_exprs;
            assert_eq!(ec_point_exprs.len(), SEPTIC_EXTENSION_DEGREE * 2);
            let mut xs_ys = ec_point_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("ec point's expression must be WitIn"),
                })
                .collect_vec();
            let ys = xs_ys.split_off(SEPTIC_EXTENSION_DEGREE);
            let xs = xs_ys;
            let slopes = cs
                .zkvm_v1_css
                .ec_slope_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("slope's expression must be WitIn"),
                })
                .collect_vec();
            let ecc_proof = Some(self.device.prove_ec_sum_quark(
                input.num_instances(),
                xs,
                ys,
                slopes,
                transcript,
            )?);
            exit_span!(span);
            ecc_proof
        } else {
            None
        };

        // build main witness
        let records = build_main_witness::<E, PCS, PB, PD>(cs, &input, challenges);

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        // prove the product and logup sum relation between layers in tower
        // (internally calls build_tower_witness)
        let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) = self
            .device
            .prove_tower_relation(cs, &input, &records, challenges, transcript);
        exit_span!(span);

        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            num_var_with_rotation,
        );

        // TODO: batch reduction into main sumcheck
        // x[rt,0] = \sum_b eq([rt,0], b) * x[b]
        // x[rt,1] = \sum_b eq([rt,1], b) * x[b]
        // x[1,rt] = \sum_b eq([1,rt], b) * x[b]
        // y[rt,0] = \sum_b eq([rt,0], b) * y[b]
        // y[rt,1] = \sum_b eq([rt,1], b) * y[b]
        // y[1,rt] = \sum_b eq([1,rt], b) * y[b]
        // s[0,rt] = \sum_b eq([0,rt], b) * s[b]

        // 1. prove the main constraints among witness polynomials
        // 2. prove the relation between last layer in the tower and read/write/logup records
        let span = entered_span!("prove_main_constraints", profiling_2 = true);
        let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) = self
            .device
            .prove_main_constraints(rt_tower, &input, cs, challenges, transcript)?;
        let MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        } = evals;
        exit_span!(span);

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_openings().is_empty() {
            let span = entered_span!("pi::evals");
            for &Instance(idx) in cs.instance_openings() {
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
                ecc_proof,
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
