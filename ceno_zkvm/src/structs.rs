use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::{E2EProgramCtx, ShardContext},
    error::ZKVMError,
    instructions::Instruction,
    scheme::septic_curve::SepticPoint,
    tables::{
        ECPoint, MemFinalRecord, RMMCollections, ShardRamCircuit, ShardRamInput, ShardRamRecord,
        TableCircuit,
    },
};
use ceno_emul::{Addr, CENO_PLATFORM, Platform, RegIdx, StepIndex, StepRecord, WordAddr};
#[cfg(feature = "gpu")]
use ceno_gpu::common::witgen::types::GpuKeccakInstance;
use ff_ext::{ExtensionField, PoseidonField};
use gkr_iop::{gkr::GKRCircuit, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::Instance;
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    sync::Arc,
};
use sumcheck::structs::{IOPProof, IOPProverMessage};
use tracing::Level;
use witness::RowMajorMatrix;

/// Proof that the sum of N (not necessarily a power of two) EC points
/// is equal to `sum` in one layer instead of multiple layers in a
/// GKR layered circuit approach that we used for offline memory checking.
/// Note that this one layer IOP borrowed ideas from
/// [Quark paper](https://eprint.iacr.org/2020/1275.pdf)
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct EccQuarkProof<E: ExtensionField> {
    pub zerocheck_proof: IOPProof<E>,
    /// Number of EC points being summed
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

    pub fn instance(&self) -> &[Instance] {
        &self.zkvm_v1_css.instance
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
    // pub keccak_gkr_iop: Option<KeccakGKRIOP<E>>,
    pub params: ProgramParams,
}

impl<E: ExtensionField> Default for ZKVMConstraintSystem<E> {
    fn default() -> Self {
        ZKVMConstraintSystem {
            circuit_css: BTreeMap::new(),
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
    pub num_instances: [usize; 2],
    // Built after the initial chip witness assignment succeeds. It is not used
    // by assign_opcode_circuit itself; later prove/open stages use it to
    // regenerate transient witness buffers from shard-resident raw data.
    pub gpu_replay_plan: Option<GpuReplayPlan<E>>,
}

#[cfg(feature = "gpu")]
#[derive(Clone)]
pub struct GpuReplayPlan<E: ExtensionField> {
    pub shard_id: usize,
    pub trace_idx: Option<usize>,
    pub kind: crate::instructions::gpu::dispatch::GpuWitgenKind,
    // Per-chip payload: each replay plan owns only its step-index slice plus
    // small shape/config metadata. Shared shard state stays resident in the
    // shard-global GPU caches and is rehydrated on worker threads on demand.
    pub step_indices: Arc<[StepIndex]>,
    // Actual committed/opened witness row height after per-chip padding. This
    // is not always equal to `step_indices.len()`: rotation-heavy chips like
    // Keccak expand each logical instance into multiple witness rows.
    pub trace_height: usize,
    pub num_witin: usize,
    pub num_structural_witin: usize,
    pub shard_offset: u64,
    pub fetch_base_pc: u32,
    pub fetch_num_slots: usize,
    // Keccak replay needs a compact packed-input slice because its kernel does
    // not consume plain step indices directly. Standard opcode chips leave this
    // empty and rebuild from resident StepRecord + shard metadata on device.
    pub keccak_instances: Option<Arc<[GpuKeccakInstance]>>,
    config_ptr: usize,
    replay_fn: fn(usize, &GpuReplayPlan<E>) -> Result<RMMCollections<E::BaseField>, ZKVMError>,
}

#[cfg(not(feature = "gpu"))]
#[derive(Clone)]
pub struct GpuReplayPlan<E: ExtensionField>(std::marker::PhantomData<E>);

#[cfg(feature = "gpu")]
impl<E: ExtensionField> GpuReplayPlan<E> {
    pub fn new(
        shard_id: usize,
        kind: crate::instructions::gpu::dispatch::GpuWitgenKind,
        step_indices: Arc<[StepIndex]>,
        trace_height: usize,
        num_witin: usize,
        num_structural_witin: usize,
        shard_offset: u64,
        fetch_base_pc: u32,
        fetch_num_slots: usize,
        keccak_instances: Option<Arc<[GpuKeccakInstance]>>,
        config_ptr: usize,
        replay_fn: fn(usize, &GpuReplayPlan<E>) -> Result<RMMCollections<E::BaseField>, ZKVMError>,
    ) -> Self {
        Self {
            shard_id,
            trace_idx: None,
            kind,
            step_indices,
            trace_height,
            num_witin,
            num_structural_witin,
            shard_offset,
            fetch_base_pc,
            fetch_num_slots,
            keccak_instances,
            config_ptr,
            replay_fn,
        }
    }

    pub fn replay(&self) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        (self.replay_fn)(self.config_ptr, self)
    }
}

impl<E: ExtensionField> ChipInput<E> {
    pub fn new(
        name: String,
        witness_rmms: RMMCollections<E::BaseField>,
        num_instances: [usize; 2],
    ) -> Self {
        Self {
            name,
            witness_rmms,
            num_instances,
            gpu_replay_plan: None,
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
    combined_lk_mlt: Option<Vec<FxHashMap<u64, usize>>>,
}

impl<E: ExtensionField> ZKVMWitnesses<E> {
    pub fn get_witness(&self, name: &String) -> Option<&Vec<ChipInput<E>>> {
        self.witnesses.get(name)
    }

    pub fn get_lk_mlt(&self, name: &String) -> Option<&Multiplicity<u64>> {
        self.lk_mlts.get(name)
    }

    pub fn combined_lk_mlt(&self) -> Option<&Vec<FxHashMap<u64, usize>>> {
        self.combined_lk_mlt.as_ref()
    }

    pub fn lk_mlts(&self) -> &BTreeMap<String, Multiplicity<u64>> {
        &self.lk_mlts
    }

    pub fn assign_opcode_circuit<OC: Instruction<E>>(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        config: &OC::InstructionConfig,
        shard_steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(), ZKVMError> {
        assert!(self.combined_lk_mlt.is_none());

        let cs = cs.get_cs(&OC::name()).unwrap();
        let (witness, logup_multiplicity) = OC::assign_instances(
            config,
            shard_ctx,
            cs.zkvm_v1_css.num_witin as usize,
            cs.zkvm_v1_css.num_structural_witin as usize,
            shard_steps,
            indices,
        )?;
        let witness_instances = witness[0].num_instances();
        let structural_instances = witness[1].num_instances();
        if witness_instances > 0 && structural_instances > 0 {
            assert_eq!(
                witness_instances,
                structural_instances,
                "{}: mismatched num_instances between witness and structural RMMs",
                OC::name()
            );
        }
        let num_instances = if witness_instances > 0 {
            witness_instances
        } else {
            structural_instances
        };
        let num_instances = [num_instances, 0];
        let mut input = ChipInput::new(OC::name(), witness, num_instances);
        #[cfg(feature = "gpu")]
        if cs.zkvm_v1_css.num_witin > 0
            && crate::instructions::gpu::config::is_gpu_witgen_enabled()
            && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit(
            )
            && (input.witness_rmms[0].has_device_backing()
                || (num_instances[0] > 0
                    && input.witness_rmms[0].num_instances() == 0
                    && crate::instructions::gpu::config::should_materialize_witness_on_gpu()))
        {
            // The initial witness assignment already happened above. Building
            // the replay plan here only records how to reconstruct this chip's
            // witness later from shard-resident raw data; it is not used during
            // this first assign pass.
            input.gpu_replay_plan = OC::build_gpu_replay_plan(
                config,
                shard_ctx,
                cs.zkvm_v1_css.num_witin as usize,
                cs.zkvm_v1_css.num_structural_witin as usize,
                shard_steps,
                indices,
            );
            assert_eq!(
                input.witness_rmms[0].num_instances(),
                0,
                "{}: cache-none GPU replay path must not keep an eager witness RMM after initial assign",
                OC::name()
            );
        }
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
        let witness_instances = witness[0].num_instances();
        let structural_instances = witness[1].num_instances();
        if witness_instances > 0 && structural_instances > 0 {
            assert_eq!(
                witness_instances,
                structural_instances,
                "{}: mismatched num_instances between witness and structural RMMs",
                TC::name()
            );
        }
        let num_instances = std::cmp::max(witness_instances, structural_instances);
        let input = ChipInput::new(TC::name(), witness, [num_instances, 0]);
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
        use tracing::info_span;

        // Try the full GPU pipeline: keep data on device, minimal CPU roundtrips.
        // Only when GPU witgen is enabled (otherwise witgen must not touch GPU).
        #[cfg(feature = "gpu")]
        if crate::instructions::gpu::config::is_gpu_witgen_enabled() {
            let gpu_result = self.try_assign_shared_circuit_gpu(cs, shard_ctx, final_mem, config);
            match gpu_result {
                Ok(true) => return Ok(()),
                Ok(false) => {} /* GPU pipeline unavailable (no shared buffers), fall through to CPU */
                Err(e) => return Err(e),
            }
        }

        let perm = <E::BaseField as PoseidonField>::get_default_perm();
        let addr_accessed =
            info_span!("get_addr_accessed").in_scope(|| shard_ctx.get_addr_accessed());

        // future shard needed records := shard_ctx.write_records ∪
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
        let n_global = global_input.len();
        let circuit_inputs =
            info_span!("shard_ram_assign_instances", n = n_global).in_scope(|| {
                global_input
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
                            [num_reads, num_writes],
                        ))
                    })
                    .collect::<Result<Vec<_>, ZKVMError>>()
            })?;
        // set num_read, num_write as separate instance
        assert!(
            self.witnesses
                .insert(ShardRamCircuit::<E>::name(), circuit_inputs)
                .is_none()
        );

        Ok(())
    }

    /// Full GPU pipeline for assign_shared_circuit: keep data on device, minimal CPU roundtrips.
    ///
    /// Returns Ok(true) if successful, Ok(false) if unavailable (no shared device buffers).
    #[cfg(feature = "gpu")]
    fn try_assign_shared_circuit_gpu(
        &mut self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &ShardContext,
        final_mem: &[(&'static str, Option<Range<Addr>>, &[MemFinalRecord])],
        config: &<ShardRamCircuit<E> as TableCircuit<E>>::TableConfig,
    ) -> Result<bool, ZKVMError> {
        assert!(self.combined_lk_mlt.is_some());
        let cs_inner = cs.get_cs(&ShardRamCircuit::<E>::name()).unwrap();
        let num_witin = cs_inner.zkvm_v1_css.num_witin as usize;
        let num_structural_witin = cs_inner.zkvm_v1_css.num_structural_witin as usize;

        match crate::instructions::gpu::chips::shard_ram::try_gpu_assign_shared_circuit::<E>(
            shard_ctx,
            final_mem,
            config,
            num_witin,
            num_structural_witin,
            shard_ctx.max_num_cross_shard_accesses,
        )? {
            Some(circuit_inputs) => {
                assert!(
                    self.witnesses
                        .insert(ShardRamCircuit::<E>::name(), circuit_inputs)
                        .is_none()
                );
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn get_witnesses_name_instance(&self) -> Vec<(String, [usize; 2])> {
        self.witnesses
            .iter()
            .flat_map(|(_, chip_inputs)| {
                chip_inputs
                    .iter()
                    .map(|chip_input| (chip_input.name.clone(), chip_input.num_instances))
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
    pub(crate) fn mem_addresses(mem_record: &MemFinalRecord) -> (WordAddr, Addr) {
        match mem_record.ram_type {
            RAMType::Register => (
                Platform::register_vma(mem_record.addr as RegIdx).into(),
                mem_record.addr,
            ),
            RAMType::Memory => (mem_record.addr.into(), mem_record.addr),
            _ => unimplemented!(),
        }
    }

    /// Filter and construct a cross-shard ShardRamInput with EC computation.
    /// Used by the CPU path where EC is computed per-record via Poseidon2.
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
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProvingKey<E, PCS> {
    pub(crate) fn new(pp: PCS::ProverParam, vp: PCS::VerifierParam) -> Self {
        Self {
            pp,
            vp,
            program_ctx: None,
            entry_pc: 0,
            circuit_pks: BTreeMap::new(),
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
    pub fn get_vk_slow(&self) -> ZKVMVerifyingKey<E, PCS> {
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
            circuit_index_to_name: self
                .circuit_pks
                .keys()
                .enumerate()
                .map(|(index, name)| (index, name.clone()))
                .collect(),
        }
    }

    pub fn set_program_ctx(&mut self, ctx: E2EProgramCtx<E>) {
        self.program_ctx = Some(ctx)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned",
))]
pub struct ZKVMVerifyingKey<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
where
    PCS::VerifierParam: Sized,
{
    pub vp: PCS::VerifierParam,
    // entry program counter
    pub entry_pc: u32,
    // vk for opcode and table circuits
    pub circuit_vks: BTreeMap<String, VerifyingKey<E>>,
    pub fixed_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    pub fixed_no_omc_init_commit: Option<<PCS as PolynomialCommitmentScheme<E>>::Commitment>,
    // circuit index -> circuit name
    // mainly used for debugging
    pub circuit_index_to_name: BTreeMap<usize, String>,
}
