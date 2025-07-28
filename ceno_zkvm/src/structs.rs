use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    instructions::Instruction,
    state::StateCircuit,
    tables::{RMMCollections, TableCircuit},
    witness::LkMultiplicity,
};
use ceno_emul::{CENO_PLATFORM, Platform, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{gkr::GKRCircuit, tables::LookupTable};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{Expression, Instance};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use sumcheck::structs::IOPProverMessage;
use witness::RowMajorMatrix;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct TowerProofs<E: ExtensionField> {
    pub proofs: Vec<Vec<IOPProverMessage<E>>>,
    // specs -> layers -> evals
    pub prod_specs_eval: Vec<Vec<Vec<E>>>,
    // specs -> layers -> point
    #[serde(skip)] // verifier can derive points itself
    pub prod_specs_points: Vec<Vec<Point<E>>>,
    // specs -> layers -> evals
    pub logup_specs_eval: Vec<Vec<Vec<E>>>,
    // specs -> layers -> point
    #[serde(skip)] // verifier can derive points itself
    pub logup_specs_points: Vec<Vec<Point<E>>>,
}

pub type WitnessId = u16;
pub type ChallengeId = u16;

pub type ROMType = LookupTable;

pub type RAMType = gkr_iop::RAMType;

pub type PointAndEval<F> = multilinear_extensions::mle::PointAndEval<F>;

#[derive(Clone)]
pub struct ProvingKey<E: ExtensionField> {
    pub vk: VerifyingKey<E>,
}

impl<E: ExtensionField> ProvingKey<E> {
    pub fn get_cs(&self) -> &ComposedConstrainSystem<E> {
        self.vk.get_cs()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct VerifyingKey<E: ExtensionField> {
    pub cs: ComposedConstrainSystem<E>,
}

impl<E: ExtensionField> VerifyingKey<E> {
    pub fn get_cs(&self) -> &ComposedConstrainSystem<E> {
        &self.cs
    }
}

#[derive(Clone, Debug)]
pub struct ProgramParams {
    pub platform: Platform,
    pub program_size: usize,
    pub pubio_len: usize,
    pub static_memory_len: usize,
}

impl Default for ProgramParams {
    fn default() -> Self {
        ProgramParams {
            platform: CENO_PLATFORM,
            program_size: (1 << 14),
            pubio_len: (1 << 2),
            static_memory_len: (1 << 16),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct ComposedConstrainSystem<E: ExtensionField> {
    // TODO combine zkvm_v1_css to `GKRCircuit<E>`
    // right now both co-exist because gkr_circuit couldn't cope with dynamic layers features which required by tower argument
    pub zkvm_v1_css: ConstraintSystem<E>,
    pub gkr_circuit: Option<GKRCircuit<E>>,
}

impl<E: ExtensionField> ComposedConstrainSystem<E> {
    pub fn key_gen(self) -> ProvingKey<E> {
        ProvingKey {
            vk: VerifyingKey { cs: self },
        }
    }
    pub fn num_witin(&self) -> usize {
        self.zkvm_v1_css.num_witin.into()
    }

    pub fn num_fixed(&self) -> usize {
        self.zkvm_v1_css.num_fixed
    }

    pub fn num_reads(&self) -> usize {
        self.zkvm_v1_css.r_expressions.len() + self.zkvm_v1_css.r_table_expressions.len()
    }

    pub fn num_writes(&self) -> usize {
        self.zkvm_v1_css.w_expressions.len() + self.zkvm_v1_css.w_table_expressions.len()
    }

    pub fn instance_name_map(&self) -> &HashMap<Instance, String> {
        &self.zkvm_v1_css.instance_name_map
    }

    pub fn is_opcode_circuit(&self) -> bool {
        self.zkvm_v1_css.lk_table_expressions.is_empty()
            && self.zkvm_v1_css.r_table_expressions.is_empty()
            && self.zkvm_v1_css.w_table_expressions.is_empty()
    }

    /// return number of lookup operation
    pub fn num_lks(&self) -> usize {
        self.zkvm_v1_css.lk_expressions.len() + self.zkvm_v1_css.lk_table_expressions.len()
    }

    /// return num_vars belongs to rotation
    pub fn rotation_vars(&self) -> Option<usize> {
        self.zkvm_v1_css
            .rotation_params
            .as_ref()
            .map(|param| param.rotation_cyclic_group_log2)
    }
}

#[derive(Clone)]
pub struct ZKVMConstraintSystem<E: ExtensionField> {
    pub(crate) circuit_css: BTreeMap<String, ComposedConstrainSystem<E>>,
    pub(crate) initial_global_state_expr: Expression<E>,
    pub(crate) finalize_global_state_expr: Expression<E>,
    // pub keccak_gkr_iop: Option<KeccakGKRIOP<E>>,
    pub params: ProgramParams,
}

impl<E: ExtensionField> Default for ZKVMConstraintSystem<E> {
    fn default() -> Self {
        ZKVMConstraintSystem {
            circuit_css: BTreeMap::new(),
            initial_global_state_expr: Expression::ZERO,
            finalize_global_state_expr: Expression::ZERO,
            params: ProgramParams::default(),
            // keccak_gkr_iop: None,
        }
    }
}

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn new_with_platform(params: ProgramParams) -> Self {
        ZKVMConstraintSystem {
            params,
            ..Default::default()
        }
    }

    pub fn register_opcode_circuit<OC: Instruction<E>>(&mut self) -> OC::InstructionConfig {
        let mut cs = ConstraintSystem::new(|| format!("riscv_opcode/{}", OC::name()));
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        let (config, gkr_iop_circuit) =
            OC::build_gkr_iop_circuit(&mut circuit_builder, &self.params).unwrap();
        let cs = ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit: Some(gkr_iop_circuit),
        };
        tracing::trace!(
            "opcode circuit {} has {} witnesses, {} reads, {} writes, {} lookups",
            OC::name(),
            cs.num_witin(),
            cs.zkvm_v1_css.r_expressions.len(),
            cs.zkvm_v1_css.w_expressions.len(),
            cs.zkvm_v1_css.lk_expressions.len(),
        );
        assert!(self.circuit_css.insert(OC::name(), cs).is_none());
        config
    }

    pub fn register_table_circuit<TC: TableCircuit<E>>(&mut self) -> TC::TableConfig {
        let mut cs = ConstraintSystem::new(|| format!("riscv_table/{}", TC::name()));
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        let config = TC::construct_circuit(&mut circuit_builder, &self.params).unwrap();
        assert!(
            self.circuit_css
                .insert(
                    TC::name(),
                    ComposedConstrainSystem {
                        zkvm_v1_css: cs,
                        gkr_circuit: None
                    }
                )
                .is_none()
        );
        config
    }

    pub fn register_global_state<SC: StateCircuit<E>>(&mut self) {
        let mut cs = ConstraintSystem::new(|| "riscv_state");
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        self.initial_global_state_expr =
            SC::initial_global_state(&mut circuit_builder).expect("global_state_in failed");
        self.finalize_global_state_expr =
            SC::finalize_global_state(&mut circuit_builder).expect("global_state_out failed");
    }

    pub fn get_css(&self) -> &BTreeMap<String, ComposedConstrainSystem<E>> {
        &self.circuit_css
    }

    pub fn get_cs(&self, name: &String) -> Option<&ComposedConstrainSystem<E>> {
        self.circuit_css.get(name)
    }
}

#[derive(Default, Clone)]
pub struct ZKVMFixedTraces<E: ExtensionField> {
    pub circuit_fixed_traces: BTreeMap<String, Option<RowMajorMatrix<E::BaseField>>>,
}

impl<E: ExtensionField> ZKVMFixedTraces<E> {
    pub fn register_opcode_circuit<OC: Instruction<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        config: &OC::InstructionConfig,
    ) {
        let cs = cs.get_cs(&OC::name()).expect("cs not found");
        assert!(
            self.circuit_fixed_traces
                .insert(
                    OC::name(),
                    OC::generate_fixed_traces(config, cs.zkvm_v1_css.num_fixed,)
                )
                .is_none()
        );
    }

    pub fn register_table_circuit<TC: TableCircuit<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        config: &TC::TableConfig,
        input: &TC::FixedInput,
    ) {
        let cs = cs.get_cs(&TC::name()).expect("cs not found");
        assert!(
            self.circuit_fixed_traces
                .insert(
                    TC::name(),
                    Some(TC::generate_fixed_traces(
                        config,
                        cs.zkvm_v1_css.num_fixed,
                        input
                    )),
                )
                .is_none()
        );
    }
}

#[derive(Default, Clone)]
pub struct ZKVMWitnesses<E: ExtensionField> {
    witnesses_opcodes: BTreeMap<String, RMMCollections<E::BaseField>>,
    witnesses_tables: BTreeMap<String, RMMCollections<E::BaseField>>,
    lk_mlts: BTreeMap<String, LkMultiplicity>,
    combined_lk_mlt: Option<Vec<HashMap<u64, usize>>>,
}

impl<E: ExtensionField> ZKVMWitnesses<E> {
    pub fn get_opcode_witness(&self, name: &String) -> Option<&RMMCollections<E::BaseField>> {
        self.witnesses_opcodes.get(name)
    }

    pub fn get_table_witness(&self, name: &String) -> Option<&RMMCollections<E::BaseField>> {
        self.witnesses_tables.get(name)
    }

    pub fn get_lk_mlt(&self, name: &String) -> Option<&LkMultiplicity> {
        self.lk_mlts.get(name)
    }

    pub fn assign_opcode_circuit<OC: Instruction<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        config: &OC::InstructionConfig,
        records: Vec<StepRecord>,
    ) -> Result<(), ZKVMError> {
        assert!(self.combined_lk_mlt.is_none());

        let cs = cs.get_cs(&OC::name()).unwrap();
        let (witness, logup_multiplicity) = OC::assign_instances(
            config,
            cs.zkvm_v1_css.num_witin as usize,
            cs.zkvm_v1_css.num_structural_witin as usize,
            records,
        )?;
        assert!(self.witnesses_opcodes.insert(OC::name(), witness).is_none());
        assert!(!self.witnesses_tables.contains_key(&OC::name()));
        assert!(
            self.lk_mlts
                .insert(OC::name(), logup_multiplicity)
                .is_none()
        );

        Ok(())
    }

    // merge the multiplicities in each opcode circuit into one
    pub fn finalize_lk_multiplicities(&mut self, is_keep_raw_lk_mlts: bool) {
        assert!(self.combined_lk_mlt.is_none());
        assert!(!self.lk_mlts.is_empty());

        let mut combined_lk_mlt = vec![];
        let keys = self.lk_mlts.keys().cloned().collect_vec();
        for name in keys {
            let lk_mlt = if is_keep_raw_lk_mlts {
                // mock prover needs the lk_mlt for processing, so we do not remove it
                self.lk_mlts
                    .get(&name)
                    .unwrap()
                    .deep_clone()
                    .into_finalize_result()
            } else {
                self.lk_mlts.remove(&name).unwrap().into_finalize_result()
            };

            if combined_lk_mlt.is_empty() {
                combined_lk_mlt = lk_mlt.to_vec();
            } else {
                combined_lk_mlt
                    .iter_mut()
                    .zip_eq(lk_mlt.iter())
                    .for_each(|(m1, m2)| {
                        for (key, value) in m2 {
                            *m1.entry(*key).or_insert(0) += value;
                        }
                    });
            }
        }

        self.combined_lk_mlt = Some(combined_lk_mlt);
    }

    pub fn assign_table_circuit<TC: TableCircuit<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        config: &TC::TableConfig,
        input: &TC::WitnessInput,
    ) -> Result<(), ZKVMError> {
        assert!(self.combined_lk_mlt.is_some());
        let cs = cs.get_cs(&TC::name()).unwrap();
        let witness = TC::assign_instances(
            config,
            cs.zkvm_v1_css.num_witin as usize,
            cs.zkvm_v1_css.num_structural_witin as usize,
            self.combined_lk_mlt.as_ref().unwrap(),
            input,
        )?;
        assert!(self.witnesses_tables.insert(TC::name(), witness).is_none());
        assert!(!self.witnesses_opcodes.contains_key(&TC::name()));

        Ok(())
    }

    /// Iterate opcode/table circuits, sorted by alphabetical order.
    pub fn into_iter_sorted(
        self,
    ) -> impl Iterator<Item = (String, Vec<RowMajorMatrix<E::BaseField>>)> {
        self.witnesses_opcodes
            .into_iter()
            .map(|(name, witnesses)| (name, witnesses.into()))
            .chain(
                self.witnesses_tables
                    .into_iter()
                    .map(|(name, witnesses)| (name, witnesses.into())),
            )
            .collect::<BTreeMap<_, _>>()
            .into_iter()
    }
}
pub struct ZKVMProvingKey<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: PCS::ProverParam,
    pub vp: PCS::VerifierParam,
    // pk for opcode and table circuits
    pub circuit_pks: BTreeMap<String, ProvingKey<E>>,
    pub fixed_commit_wd: Option<Arc<<PCS as PolynomialCommitmentScheme<E>>::CommitmentWithWitness>>,
    pub fixed_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,

    // expression for global state in/out
    pub initial_global_state_expr: Expression<E>,
    pub finalize_global_state_expr: Expression<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProvingKey<E, PCS> {
    pub(crate) fn new(pp: PCS::ProverParam, vp: PCS::VerifierParam) -> Self {
        Self {
            pp,
            vp,
            circuit_pks: BTreeMap::new(),
            initial_global_state_expr: Expression::ZERO,
            finalize_global_state_expr: Expression::ZERO,
            fixed_commit_wd: None,
            fixed_commit: None,
        }
    }

    pub(crate) fn commit_fixed(
        &mut self,
        fixed_traces: BTreeMap<usize, RowMajorMatrix<<E as ExtensionField>::BaseField>>,
    ) -> Result<(), ZKVMError> {
        if !fixed_traces.is_empty() {
            let fixed_commit_wd =
                PCS::batch_commit(&self.pp, fixed_traces.into_values().collect_vec())
                    .map_err(ZKVMError::PCSError)?;
            let fixed_commit = PCS::get_pure_commitment(&fixed_commit_wd);
            self.fixed_commit_wd = Some(Arc::new(fixed_commit_wd));
            self.fixed_commit = Some(fixed_commit);
        } else {
            self.fixed_commit_wd = None;
            self.fixed_commit = None;
        }
        Ok(())
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProvingKey<E, PCS> {
    pub fn get_vk_slow(&self) -> ZKVMVerifyingKey<E, PCS> {
        ZKVMVerifyingKey {
            vp: self.vp.clone(),
            circuit_vks: self
                .circuit_pks
                .iter()
                .map(|(name, pk)| (name.clone(), pk.vk.clone()))
                .collect(),
            fixed_commit: self.fixed_commit.clone(),
            // expression for global state in/out
            initial_global_state_expr: self.initial_global_state_expr.clone(),
            finalize_global_state_expr: self.finalize_global_state_expr.clone(),
            circuit_index_to_name: self
                .circuit_pks
                .keys()
                .enumerate()
                .map(|(index, name)| (index, name.clone()))
                .collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned",
))]
pub struct ZKVMVerifyingKey<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub vp: PCS::VerifierParam,
    // vk for opcode and table circuits
    pub circuit_vks: BTreeMap<String, VerifyingKey<E>>,
    pub fixed_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    // expression for global state in/out
    pub initial_global_state_expr: Expression<E>,
    pub finalize_global_state_expr: Expression<E>,
    // circuit index -> circuit name
    // mainly used for debugging
    pub circuit_index_to_name: BTreeMap<usize, String>,
}
