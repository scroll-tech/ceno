use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::{E2EProgramCtx, ShardContext},
    error::ZKVMError,
    instructions::Instruction,
    scheme::{septic_curve::SepticPoint, verifier::MemStatePubValuesVerifier},
    state::StateCircuit,
    tables::{
        ECPoint, MemFinalRecord, RMMCollections, ShardRamCircuit, ShardRamInput, ShardRamRecord,
        TableCircuit,
    },
};
use ceno_emul::{Addr, CENO_PLATFORM, Platform, RegIdx, StepRecord, WordAddr};
use ff_ext::{ExtensionField, PoseidonField};
use gkr_iop::{gkr::GKRCircuit, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{Expression, Instance};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    sync::Arc,
};
use sumcheck::structs::{IOPProof, IOPProverMessage};
use tracing::Level;
use witness::RowMajorMatrix;

/// proof that the sum of N=2^n EC points is equal to `sum`
/// in one layer instead of GKR layered circuit approach
/// note that this one layer IOP borrowed ideas from
/// [Quark paper](https://eprint.iacr.org/2020/1275.pdf)
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct EccQuarkProof<E: ExtensionField> {
    pub zerocheck_proof: IOPProof<E>,
    pub num_instances: usize,
    pub evals: Vec<E>, // x[rt,0], x[rt,1], y[rt,0], y[rt,1], x[0,rt], y[0,rt], s[0,rt]
    pub rt: Point<E>,
    pub sum: SepticPoint<E::BaseField>,
}

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
            platform: CENO_PLATFORM.clone(),
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

    pub fn num_structural_witin(&self) -> usize {
        self.zkvm_v1_css.num_structural_witin.into()
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

    pub fn instance_openings(&self) -> &[Instance] {
        &self.zkvm_v1_css.instance_openings
    }
    pub fn has_ecc_ops(&self) -> bool {
        !self.zkvm_v1_css.ec_final_sum.is_empty()
    }

    pub fn is_with_lk_table(&self) -> bool {
        !self.zkvm_v1_css.lk_table_expressions.is_empty()
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

    /// return rotation sub_group size
    pub fn rotation_subgroup_size(&self) -> Option<usize> {
        self.zkvm_v1_css
            .rotation_params
            .as_ref()
            .map(|param| param.rotation_cyclic_subgroup_size)
    }

    pub fn with_omc_init_only(&self) -> bool {
        self.zkvm_v1_css.with_omc_init_only
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
        assert!(
            self.circuit_css.insert(OC::name(), cs).is_none(),
            "opcode circuit {} already registered",
            OC::name()
        );
        config
    }

    pub fn register_table_circuit<TC: TableCircuit<E>>(&mut self) -> TC::TableConfig {
        let mut cs = ConstraintSystem::new(|| format!("riscv_table/{}", TC::name()));
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        let (config, gkr_iop_circuit) =
            TC::build_gkr_iop_circuit(&mut circuit_builder, &self.params).unwrap();
        let cs = ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit: gkr_iop_circuit,
        };
        assert!(self.circuit_css.insert(TC::name(), cs).is_none());
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

#[derive(Clone)]
pub struct ChipInput<E: ExtensionField> {
    pub name: String,
    pub witness_rmms: RMMCollections<E::BaseField>,
    // in shard ram chip, num_instances length would be > 1
    pub num_instances: Vec<usize>,
}

impl<E: ExtensionField> ChipInput<E> {
    pub fn new(
        name: String,
        witness_rmms: RMMCollections<E::BaseField>,
        num_instances: Vec<usize>,
    ) -> Self {
        Self {
            name,
            witness_rmms,
            num_instances,
        }
    }

    pub fn num_instances(&self) -> usize {
        self.num_instances.iter().sum()
    }
}

#[derive(Default, Clone)]
pub struct ZKVMWitnesses<E: ExtensionField> {
    pub witnesses: BTreeMap<String, Vec<ChipInput<E>>>,
    lk_mlts: BTreeMap<String, Multiplicity<u64>>,
    combined_lk_mlt: Option<Vec<HashMap<u64, usize>>>,
}

impl<E: ExtensionField> ZKVMWitnesses<E> {
    pub fn get_witness(&self, name: &String) -> Option<&Vec<ChipInput<E>>> {
        self.witnesses.get(name)
    }

    pub fn get_lk_mlt(&self, name: &String) -> Option<&Multiplicity<u64>> {
        self.lk_mlts.get(name)
    }

    pub fn assign_opcode_circuit<OC: Instruction<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        config: &OC::InstructionConfig,
        records: Vec<&StepRecord>,
    ) -> Result<(), ZKVMError> {
        assert!(self.combined_lk_mlt.is_none());

        let cs = cs.get_cs(&OC::name()).unwrap();
        let (witness, logup_multiplicity) = OC::assign_instances(
            config,
            shard_ctx,
            cs.zkvm_v1_css.num_witin as usize,
            cs.zkvm_v1_css.num_structural_witin as usize,
            records,
        )?;
        let num_instances = vec![witness[0].num_instances()];
        let input = ChipInput::new(
            OC::name(),
            witness,
            if num_instances[0] > 0 {
                num_instances
            } else {
                vec![]
            },
        );
        assert!(self.witnesses.insert(OC::name(), vec![input]).is_none());
        assert!(
            self.lk_mlts
                .insert(OC::name(), logup_multiplicity)
                .is_none()
        );

        Ok(())
    }

    // merge the multiplicities in each opcode circuit into one
    pub fn finalize_lk_multiplicities(&mut self) {
        assert!(self.combined_lk_mlt.is_none());
        assert!(!self.lk_mlts.is_empty());

        let mut combined_lk_mlt = vec![];
        let keys = self.lk_mlts.keys().cloned().collect_vec();
        for name in keys {
            let lk_mlt = self.lk_mlts.get(&name).unwrap();

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
        input: &TC::WitnessInput<'_>,
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
        let num_instances = std::cmp::max(witness[0].num_instances(), witness[1].num_instances());
        let input = ChipInput::new(
            TC::name(),
            witness,
            if num_instances > 0 {
                vec![num_instances]
            } else {
                vec![]
            },
        );
        assert!(self.witnesses.insert(TC::name(), vec![input]).is_none());

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_shared_circuit(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        (shard_ctx, final_mem): &(
            &ShardContext,
            &[(&'static str, Option<Range<Addr>>, &[MemFinalRecord])],
        ),
        config: &<ShardRamCircuit<E> as TableCircuit<E>>::TableConfig,
    ) -> Result<(), ZKVMError> {
        let perm = <E::BaseField as PoseidonField>::get_default_perm();
        let addr_accessed = shard_ctx.get_addr_accessed();

        // future shard needed records := shard_ctx.write_records ∪  //
        // (shard_ctx.after_current_shard_cycle(mem_record.cycle) && !addr_accessed.contains(&waddr))

        // 1. process final mem which
        // 1.1 init in first shard
        // 1.2 not accessed in first shard
        // 1.3 accessed in future shard
        let first_shard_access_later_records = if shard_ctx.is_first_shard() {
            final_mem
                .par_iter()
                // only process no range restriction memory record
                // for range specified it means dynamic init across different shard
                .filter(|(_, range, _)| range.is_none())
                .flat_map(|(mem_name, _, final_mem)| {
                    final_mem.par_iter().filter_map(|mem_record| {
                        let (waddr, addr) = Self::mem_addresses(mem_record);
                        Self::make_cross_shard_input(
                            mem_name,
                            mem_record,
                            waddr,
                            addr,
                            shard_ctx,
                            &addr_accessed,
                            &perm,
                        )
                    })
                })
                .collect()
        } else {
            vec![]
        };

        // 2. process records which
        // 2.1 init within current shard
        // 2.2 not accessed in current shard
        // 2.3 access by later shards.
        let current_shard_access_later = final_mem
            .par_iter()
            // only process range-restricted memory record
            // for range specified it means dynamic init across different shard
            .filter(|(_, range, _)| range.is_some())
            .flat_map(|(mem_name, range, final_mem)| {
                let range = range.as_ref().unwrap();
                final_mem.par_iter().filter_map(|mem_record| {
                    let (waddr, addr) = Self::mem_addresses(mem_record);
                    if !range.contains(&addr) {
                        return None;
                    }
                    Self::make_cross_shard_input(
                        mem_name,
                        mem_record,
                        waddr,
                        addr,
                        shard_ctx,
                        &addr_accessed,
                        &perm,
                    )
                })
            })
            .collect::<Vec<_>>();

        let global_input = shard_ctx
            .write_records()
            .par_iter()
            .flat_map(|records| {
                // global write -> local reads
                records.par_iter().map(|(vma, record)| {
                    let global_write: ShardRamRecord = (vma, record, true).into();
                    let ec_point: ECPoint<E> = global_write.to_ec_point(&perm);
                    ShardRamInput {
                        name: "current_shard_external_write",
                        record: global_write,
                        ec_point,
                    }
                })
            })
            .chain(first_shard_access_later_records.into_par_iter())
            .chain(current_shard_access_later.into_par_iter())
            .chain(shard_ctx.read_records().par_iter().flat_map(|records| {
                // global read -> local write
                records.par_iter().map(|(vma, record)| {
                    let global_read: ShardRamRecord = (vma, record, false).into();
                    let ec_point: ECPoint<E> = global_read.to_ec_point(&perm);
                    ShardRamInput {
                        name: "current_shard_external_read",
                        record: global_read,
                        ec_point,
                    }
                })
            }))
            .collect::<Vec<_>>();

        if tracing::enabled!(Level::DEBUG) {
            let total = global_input.len() as f64;
            // log global input stats
            let record_stats = global_input
                .par_iter()
                .fold(HashMap::new, |mut local, d| {
                    *local.entry(d.name).or_insert(0) += 1;
                    local
                })
                .reduce(HashMap::new, |mut a, b| {
                    for (k, v) in b {
                        *a.entry(k).or_insert(0) += v;
                    }
                    a
                });

            for (mem_name, count) in record_stats {
                let pct = (count as f64 / total) * 100.0;
                tracing::debug!(
                    "{}th-shard shard ram circuit records: mem_name={} count={} ({:.2}%)",
                    shard_ctx.shard_id,
                    mem_name,
                    count,
                    pct
                );
            }
        }

        assert!(self.combined_lk_mlt.is_some());
        let cs = cs.get_cs(&ShardRamCircuit::<E>::name()).unwrap();
        let circuit_inputs = global_input
            .par_chunks(shard_ctx.max_num_cross_shard_accesses)
            .map(|shard_accesses| {
                let witness = ShardRamCircuit::assign_instances(
                    config,
                    cs.zkvm_v1_css.num_witin as usize,
                    cs.zkvm_v1_css.num_structural_witin as usize,
                    self.combined_lk_mlt.as_ref().unwrap(),
                    shard_accesses,
                )?;
                let num_reads = shard_accesses
                    .par_iter()
                    .filter(|access| access.record.is_to_write_set)
                    .count();
                let num_writes = shard_accesses.len() - num_reads;

                Ok(ChipInput::new(
                    ShardRamCircuit::<E>::name(),
                    witness,
                    vec![num_reads, num_writes],
                ))
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        // set num_read, num_write as separate instance
        assert!(
            self.witnesses
                .insert(ShardRamCircuit::<E>::name(), circuit_inputs)
                .is_none()
        );

        Ok(())
    }

    pub fn get_witnesses_name_instance(&self) -> Vec<(String, Vec<usize>)> {
        self.witnesses
            .iter()
            .flat_map(|(_, chip_inputs)| {
                chip_inputs
                    .iter()
                    .map(|chip_input| (chip_input.name.clone(), chip_input.num_instances.clone()))
            })
            .collect_vec()
    }

    /// Iterate opcode/table circuits, sorted by alphabetical order.
    pub fn into_iter_sorted(self) -> impl Iterator<Item = ChipInput<E>> {
        self.witnesses
            .into_iter()
            .flat_map(|(_, chip_inputs)| chip_inputs.into_iter())
    }

    #[inline(always)]
    fn mem_addresses(mem_record: &MemFinalRecord) -> (WordAddr, Addr) {
        match mem_record.ram_type {
            RAMType::Register => (
                Platform::register_vma(mem_record.addr as RegIdx).into(),
                mem_record.addr,
            ),
            RAMType::Memory => (mem_record.addr.into(), mem_record.addr),
            _ => unimplemented!(),
        }
    }

    #[inline(always)]
    fn make_cross_shard_input(
        mem_name: &'static str,
        mem_record: &MemFinalRecord,
        waddr: WordAddr,
        addr: u32,
        shard_ctx: &ShardContext,
        addr_accessed: &FxHashSet<WordAddr>,
        perm: &<<E as ExtensionField>::BaseField as PoseidonField>::P,
    ) -> Option<ShardRamInput<E>> {
        if addr_accessed.contains(&waddr) || !shard_ctx.after_current_shard_cycle(mem_record.cycle)
        {
            return None;
        }

        let global_write = ShardRamRecord {
            addr: match mem_record.ram_type {
                RAMType::Register => addr,
                RAMType::Memory => waddr.into(),
                _ => unimplemented!(),
            },
            ram_type: mem_record.ram_type,
            value: mem_record.init_value,
            shard: shard_ctx.shard_id as u64,
            local_clk: 0,
            global_clk: 0,
            is_to_write_set: true,
        };
        let ec_point: ECPoint<E> = global_write.to_ec_point(perm);
        Some(ShardRamInput {
            name: mem_name,
            record: global_write,
            ec_point,
        })
    }
}

pub struct ZKVMProvingKey<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: PCS::ProverParam,
    pub vp: PCS::VerifierParam,
    pub program_ctx: Option<E2EProgramCtx<E>>,

    // entry program counter
    pub entry_pc: u32,
    // pk for opcode and table circuits
    pub circuit_pks: BTreeMap<String, ProvingKey<E>>,
    pub circuit_name_to_index: BTreeMap<String, usize>,

    // Fixed commitments are separated into two groups:
    //
    // 1. `fixed_commit_*`
    //    - Used by the *main circuit* for offline memory check (OMC) table initialization.
    //    - This initialization occurs **only in the first shard** (`shard_id = 0`).
    //
    // 2. `fixed_no_omc_init_commit_*`
    //    - Used by subsequent shards (`shard_id > 0`), which **omit** OMC table initialization.
    //    - All circuit components related to OMC init are skipped in these shards.
    pub fixed_commit_wd: Option<Arc<<PCS as PolynomialCommitmentScheme<E>>::CommitmentWithWitness>>,
    pub fixed_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    pub fixed_no_omc_init_commit_wd:
        Option<Arc<<PCS as PolynomialCommitmentScheme<E>>::CommitmentWithWitness>>,
    pub fixed_no_omc_init_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,

    pub circuit_index_fixed_num_instances: BTreeMap<usize, usize>,

    // expression for global state in/out
    pub initial_global_state_expr: Expression<E>,
    pub finalize_global_state_expr: Expression<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProvingKey<E, PCS> {
    pub(crate) fn new(pp: PCS::ProverParam, vp: PCS::VerifierParam) -> Self {
        Self {
            pp,
            vp,
            program_ctx: None,
            entry_pc: 0,
            circuit_pks: BTreeMap::new(),
            initial_global_state_expr: Expression::ZERO,
            finalize_global_state_expr: Expression::ZERO,
            circuit_index_fixed_num_instances: BTreeMap::new(),
            circuit_name_to_index: BTreeMap::new(),
            fixed_commit_wd: None,
            fixed_commit: None,
            fixed_no_omc_init_commit_wd: None,
            fixed_no_omc_init_commit: None,
        }
    }

    pub(crate) fn commit_fixed(
        &mut self,
        fixed_traces: BTreeMap<usize, RowMajorMatrix<<E as ExtensionField>::BaseField>>,
        fixed_traces_no_omc_init: BTreeMap<usize, RowMajorMatrix<<E as ExtensionField>::BaseField>>,
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

        if !fixed_traces_no_omc_init.is_empty() {
            let fixed_commit_wd = PCS::batch_commit(
                &self.pp,
                fixed_traces_no_omc_init.into_values().collect_vec(),
            )
            .map_err(ZKVMError::PCSError)?;
            let fixed_commit = PCS::get_pure_commitment(&fixed_commit_wd);
            self.fixed_no_omc_init_commit_wd = Some(Arc::new(fixed_commit_wd));
            self.fixed_no_omc_init_commit = Some(fixed_commit);
        } else {
            self.fixed_no_omc_init_commit_wd = None;
            self.fixed_no_omc_init_commit = None;
        }
        Ok(())
    }

    pub(crate) fn set_program_entry_pc(&mut self, entry_pc: u32) {
        self.entry_pc = entry_pc;
    }

    pub fn has_fixed_commitment(&self) -> bool {
        self.fixed_commit_wd.is_some() || self.fixed_no_omc_init_commit_wd.is_some()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProvingKey<E, PCS> {
    pub fn get_vk_slow<M>(&self) -> ZKVMVerifyingKey<E, PCS, M>
    where
        M: MemStatePubValuesVerifier<E, PCS> + From<Platform>,
    {
        ZKVMVerifyingKey {
            vp: self.vp.clone(),
            entry_pc: self.entry_pc,
            circuit_vks: self
                .circuit_pks
                .iter()
                .map(|(name, pk)| (name.clone(), pk.vk.clone()))
                .collect(),
            fixed_commit: self.fixed_commit.clone(),
            fixed_no_omc_init_commit: self.fixed_no_omc_init_commit.clone(),
            // expression for global state in/out
            initial_global_state_expr: self.initial_global_state_expr.clone(),
            finalize_global_state_expr: self.finalize_global_state_expr.clone(),
            circuit_index_to_name: self
                .circuit_pks
                .keys()
                .enumerate()
                .map(|(index, name)| (index, name.clone()))
                .collect(),
            mem_state_verifier: self
                .program_ctx
                .as_ref()
                .map(|ctx| M::from(ctx.platform.clone()))
                .unwrap_or_default(),
        }
    }

    pub fn set_program_ctx(&mut self, ctx: E2EProgramCtx<E>) {
        self.program_ctx = Some(ctx)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize, M: Serialize",
    deserialize = "E::BaseField: DeserializeOwned, M: DeserializeOwned",
))]
pub struct ZKVMVerifyingKey<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    M: MemStatePubValuesVerifier<E, PCS>,
> where
    PCS::VerifierParam: Sized,
{
    pub vp: PCS::VerifierParam,
    // entry program counter
    pub entry_pc: u32,
    // vk for opcode and table circuits
    pub circuit_vks: BTreeMap<String, VerifyingKey<E>>,
    pub fixed_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    pub fixed_no_omc_init_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    // expression for global state in/out
    pub initial_global_state_expr: Expression<E>,
    pub finalize_global_state_expr: Expression<E>,
    // circuit index -> circuit name
    // mainly used for debugging
    pub circuit_index_to_name: BTreeMap<usize, String>,
    pub mem_state_verifier: M,
}
