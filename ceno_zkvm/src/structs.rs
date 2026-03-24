use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::{E2EProgramCtx, GPU_SHARD_RAM_RECORD_SIZE, ShardContext},
    error::ZKVMError,
    instructions::Instruction,
    scheme::septic_curve::{SepticExtension, SepticPoint},
    state::StateCircuit,
    tables::{
        ECPoint, MemFinalRecord, RMMCollections, ShardRamCircuit, ShardRamInput, ShardRamRecord,
        TableCircuit,
    },
};
use ceno_emul::{Addr, CENO_PLATFORM, Platform, RegIdx, StepIndex, StepRecord, WordAddr};
use ff_ext::{ExtensionField, PoseidonField};
use gkr_iop::{gkr::GKRCircuit, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{Expression, Instance};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use rustc_hash::FxHashMap;
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
        use tracing::info_span;

        // Try the full GPU pipeline: keep data on device, minimal CPU roundtrips.
        // Falls back to the traditional path on failure.
        #[cfg(feature = "gpu")]
        {
            let gpu_result = self.try_assign_shared_circuit_gpu(
                cs, shard_ctx, final_mem, config,
            );
            match gpu_result {
                Ok(true) => return Ok(()),  // GPU pipeline succeeded
                Ok(false) => {}             // GPU pipeline unavailable, fall through
                Err(e) => {
                    tracing::warn!("GPU full pipeline failed, falling back: {e:?}");
                }
            }
        }

        let addr_accessed = info_span!("get_addr_accessed").in_scope(|| {
            shard_ctx.get_addr_accessed_sorted()
        });

        // GPU EC records: convert raw bytes to ShardRamInput (EC points already computed on GPU)
        // Partition into writes and reads to maintain the ordering invariant required by
        // ShardRamCircuit::assign_instances (writes first, reads after).
        let (gpu_ec_writes, gpu_ec_reads) =
            info_span!("gpu_ec_convert", n = shard_ctx.gpu_ec_records.len() / 104).in_scope(|| {
                if shard_ctx.has_gpu_ec_records() {
                    gpu_ec_records_to_shard_ram_inputs::<E>(&shard_ctx.gpu_ec_records)
                } else {
                    (vec![], vec![])
                }
            });

        // Collect cross-shard records (filter only, no EC computation yet)
        let (write_record_pairs, read_record_pairs) = info_span!("collect_records").in_scope(|| {
            let first_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> =
                if shard_ctx.is_first_shard() {
                    final_mem
                        .par_iter()
                        .filter(|(_, range, _)| range.is_none())
                        .flat_map(|(mem_name, _, final_mem)| {
                            final_mem.par_iter().filter_map(|mem_record| {
                                let (waddr, addr) = Self::mem_addresses(mem_record);
                                Self::make_cross_shard_record(
                                    mem_name,
                                    mem_record,
                                    waddr,
                                    addr,
                                    shard_ctx,
                                    &addr_accessed,
                                )
                            })
                        })
                        .collect()
                } else {
                    vec![]
                };

            let current_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> = final_mem
                .par_iter()
                .filter(|(_, range, _)| range.is_some())
                .flat_map(|(mem_name, range, final_mem)| {
                    let range = range.as_ref().unwrap();
                    final_mem.par_iter().filter_map(|mem_record| {
                        let (waddr, addr) = Self::mem_addresses(mem_record);
                        if !range.contains(&addr) {
                            return None;
                        }
                        Self::make_cross_shard_record(
                            mem_name,
                            mem_record,
                            waddr,
                            addr,
                            shard_ctx,
                            &addr_accessed,
                        )
                    })
                })
                .collect();

            let write_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
                .write_records()
                .iter()
                .flat_map(|records| {
                    records.iter().map(|(vma, record)| {
                        ((vma, record, true).into(), "current_shard_external_write")
                    })
                })
                .chain(first_shard_access_later_recs)
                .chain(current_shard_access_later_recs)
                .collect();

            let read_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
                .read_records()
                .iter()
                .flat_map(|records| {
                    records.iter().map(|(vma, record)| {
                        ((vma, record, false).into(), "current_shard_external_read")
                    })
                })
                .collect();

            (write_record_pairs, read_record_pairs)
        });

        // Compute EC points: GPU path (fast) or CPU fallback
        let global_input = {
            #[cfg(feature = "gpu")]
            let ec_result = {
                use crate::instructions::gpu::witgen_gpu::gpu_batch_continuation_ec;
                gpu_batch_continuation_ec::<E>(&write_record_pairs, &read_record_pairs)
                    .ok()
            };
            #[cfg(not(feature = "gpu"))]
            let ec_result: Option<(Vec<ShardRamInput<E>>, Vec<ShardRamInput<E>>)> = None;

            if let Some((computed_writes, computed_reads)) = ec_result {
                // GPU path: chain computed EC with pre-computed GPU EC records
                computed_writes
                    .into_iter()
                    .chain(gpu_ec_writes)
                    .chain(computed_reads)
                    .chain(gpu_ec_reads)
                    .collect::<Vec<_>>()
            } else {
                // CPU fallback: compute EC points with Poseidon2 permutation
                let perm = <E::BaseField as PoseidonField>::get_default_perm();
                let cpu_writes: Vec<ShardRamInput<E>> = write_record_pairs
                    .into_par_iter()
                    .map(|(record, name)| {
                        let ec_point = record.to_ec_point(&perm);
                        ShardRamInput { name, record, ec_point }
                    })
                    .collect();
                let cpu_reads: Vec<ShardRamInput<E>> = read_record_pairs
                    .into_par_iter()
                    .map(|(record, name)| {
                        let ec_point = record.to_ec_point(&perm);
                        ShardRamInput { name, record, ec_point }
                    })
                    .collect();
                cpu_writes
                    .into_iter()
                    .chain(gpu_ec_writes)
                    .chain(cpu_reads)
                    .chain(gpu_ec_reads)
                    .collect::<Vec<_>>()
            }
        };

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

        // Invariant: all writes (is_to_write_set=true) must precede all reads.
        // ShardRamCircuit::assign_instances uses take_while to count writes.
        // Activate with CENO_DEBUG_SHARD_RAM_ORDER=1.
        if std::env::var_os("CENO_DEBUG_SHARD_RAM_ORDER").is_some() {
            let mut seen_read = false;
            for (i, input) in global_input.iter().enumerate() {
                if input.record.is_to_write_set {
                    if seen_read {
                        tracing::error!(
                            "[SHARD_RAM_ORDER] BUG: write after read at index={i} \
                             addr={} ram_type={:?} shard={} global_clk={} \
                             (total={} writes={} reads={})",
                            input.record.addr,
                            input.record.ram_type,
                            shard_ctx.shard_id,
                            input.record.global_clk,
                            global_input.len(),
                            global_input.iter().filter(|x| x.record.is_to_write_set).count(),
                            global_input.iter().filter(|x| !x.record.is_to_write_set).count(),
                        );
                        break;
                    }
                } else {
                    seen_read = true;
                }
            }
        }

        assert!(self.combined_lk_mlt.is_some());
        let cs = cs.get_cs(&ShardRamCircuit::<E>::name()).unwrap();
        let n_global = global_input.len();
        let circuit_inputs = info_span!("shard_ram_assign_instances", n = n_global).in_scope(|| {
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
                        vec![num_reads, num_writes],
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
        use crate::instructions::gpu::witgen_gpu::{
            gpu_batch_continuation_ec_on_device, take_shared_device_buffers,
        };
        use ceno_gpu::Buffer;
        use gkr_iop::gpu::get_cuda_hal;
        use tracing::info_span;

        // 1. Take shared device buffers (if available)
        let mut shared = match take_shared_device_buffers() {
            Some(s) => s,
            None => return Ok(false),
        };

        let hal = match get_cuda_hal() {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };

        tracing::info!("[GPU full pipeline] starting device-resident assign_shared_circuit");

        // 2. D2H the EC count and addr count
        let ec_count = {
            let cv: Vec<u32> = shared.ec_count.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("shared_ec_count D2H: {e}").into())
            })?;
            cv[0] as usize
        };
        let addr_count = {
            let cv: Vec<u32> = shared.addr_count.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("shared_addr_count D2H: {e}").into())
            })?;
            cv[0] as usize
        };

        tracing::info!(
            "[GPU full pipeline] shared buffers: {} EC records, {} addr_accessed",
            ec_count, addr_count,
        );

        // 3. GPU sort addr_accessed + dedup, then D2H sorted unique addrs
        let addr_accessed: Vec<WordAddr> = if addr_count > 0 {
            info_span!("gpu_sort_addr").in_scope(|| {
                let (deduped, unique_count) = hal.witgen
                    .sort_and_dedup_u32(&mut shared.addr_buf, addr_count, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("GPU sort addr: {e}").into())
                    })?;
                if unique_count == 0 {
                    return Ok::<Vec<WordAddr>, ZKVMError>(vec![]);
                }
                // GPU-sorted + CPU-deduped; convert to WordAddr
                let addrs: Vec<WordAddr> = deduped.into_iter().map(WordAddr).collect();
                tracing::info!(
                    "[GPU full pipeline] sorted {} addrs → {} unique",
                    addr_count, unique_count,
                );
                Ok(addrs)
            })?
        } else {
            vec![]
        };

        // 4. CPU collect_records (24ms, uses sorted unique addrs)
        let (write_record_pairs, read_record_pairs) = info_span!("collect_records").in_scope(|| {
            // This is the same logic as the existing path
            let first_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> =
                if shard_ctx.is_first_shard() {
                    final_mem
                        .par_iter()
                        .filter(|(_, range, _)| range.is_none())
                        .flat_map(|(mem_name, _, final_mem)| {
                            final_mem.par_iter().filter_map(|mem_record| {
                                let (waddr, addr) = Self::mem_addresses(mem_record);
                                Self::make_cross_shard_record(
                                    mem_name,
                                    mem_record,
                                    waddr,
                                    addr,
                                    shard_ctx,
                                    &addr_accessed,
                                )
                            })
                        })
                        .collect()
                } else {
                    vec![]
                };

            let current_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> = final_mem
                .par_iter()
                .filter(|(_, range, _)| range.is_some())
                .flat_map(|(mem_name, range, final_mem)| {
                    let range = range.as_ref().unwrap();
                    final_mem.par_iter().filter_map(|mem_record| {
                        let (waddr, addr) = Self::mem_addresses(mem_record);
                        if !range.contains(&addr) {
                            return None;
                        }
                        Self::make_cross_shard_record(
                            mem_name,
                            mem_record,
                            waddr,
                            addr,
                            shard_ctx,
                            &addr_accessed,
                        )
                    })
                })
                .collect();

            let write_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
                .write_records()
                .iter()
                .flat_map(|records| {
                    records.iter().map(|(vma, record)| {
                        ((vma, record, true).into(), "current_shard_external_write")
                    })
                })
                .chain(first_shard_access_later_recs)
                .chain(current_shard_access_later_recs)
                .collect();

            let read_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
                .read_records()
                .iter()
                .flat_map(|records| {
                    records.iter().map(|(vma, record)| {
                        ((vma, record, false).into(), "current_shard_external_read")
                    })
                })
                .collect();

            (write_record_pairs, read_record_pairs)
        });

        // 5. GPU batch EC on device for continuation records (25ms, results stay on GPU)
        let (cont_ec_buf, cont_n_writes, cont_n_reads) =
            info_span!("gpu_batch_ec_on_device").in_scope(|| {
                gpu_batch_continuation_ec_on_device(&write_record_pairs, &read_record_pairs)
            })?;
        let cont_total = cont_n_writes + cont_n_reads;

        tracing::info!(
            "[GPU full pipeline] batch EC on device: {} writes + {} reads = {} continuation records",
            cont_n_writes, cont_n_reads, cont_total,
        );

        // 6. GPU merge shared_ec + batch_ec, then partition by is_to_write_set
        let (partitioned_buf, num_writes, total_records) =
            info_span!("gpu_merge_partition").in_scope(|| {
                hal.witgen.merge_and_partition_records(
                    &shared.ec_buf,
                    ec_count,
                    &cont_ec_buf,
                    cont_total,
                    None,
                )
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU merge+partition: {e}").into())
                })
            })?;

        tracing::info!(
            "[GPU full pipeline] merged+partitioned: {} total ({} writes, {} reads)",
            total_records, num_writes, total_records - num_writes,
        );

        // 7. GPU assign_instances from device buffer (chunked by max_cross_shard)
        assert!(self.combined_lk_mlt.is_some());
        let cs_inner = cs.get_cs(&ShardRamCircuit::<E>::name()).unwrap();
        let num_witin = cs_inner.zkvm_v1_css.num_witin as usize;
        let num_structural_witin = cs_inner.zkvm_v1_css.num_structural_witin as usize;
        let max_chunk = shard_ctx.max_num_cross_shard_accesses;

        // Record sizes needed for chunking
        let record_u32s = std::mem::size_of::<ceno_gpu::common::witgen::types::GpuShardRamRecord>() / 4;

        let circuit_inputs = info_span!("shard_ram_assign_from_device", n = total_records)
            .in_scope(|| {
                // Process chunks sequentially (each chunk uses GPU exclusively)
                let mut inputs = Vec::new();
                let mut records_offset = 0usize;
                let mut writes_remaining = num_writes;

                while records_offset < total_records {
                    let chunk_size = max_chunk.min(total_records - records_offset);
                    let chunk_writes = writes_remaining.min(chunk_size);
                    writes_remaining = writes_remaining.saturating_sub(chunk_size);

                    // Create a view into the partitioned buffer for this chunk.
                    // SAFETY: chunk_buf borrows from partitioned_buf and is dropped
                    // at the end of each loop iteration, before partitioned_buf goes
                    // out of scope. The 'static lifetime is required by the HAL API.
                    let chunk_byte_start = records_offset * record_u32s * 4;
                    let chunk_byte_end = (records_offset + chunk_size) * record_u32s * 4;
                    let chunk_view = partitioned_buf.as_slice_range(chunk_byte_start..chunk_byte_end);
                    let chunk_buf: ceno_gpu::common::buffer::BufferImpl<'static, u32> =
                        unsafe { std::mem::transmute(ceno_gpu::common::buffer::BufferImpl::<u32>::new_from_view(chunk_view)) };

                    let witness = ShardRamCircuit::<E>::try_gpu_assign_instances_from_device(
                        config,
                        num_witin,
                        num_structural_witin,
                        &chunk_buf,
                        chunk_size,
                        chunk_writes,
                    )?;

                    let witness = witness.ok_or_else(|| {
                        ZKVMError::InvalidWitness("GPU shard_ram from_device returned None".into())
                    })?;

                    let num_reads = chunk_size - chunk_writes;
                    inputs.push(ChipInput::new(
                        ShardRamCircuit::<E>::name(),
                        witness,
                        vec![chunk_writes, num_reads],
                    ));

                    records_offset += chunk_size;
                }
                Ok::<_, ZKVMError>(inputs)
            })?;

        assert!(
            self.witnesses
                .insert(ShardRamCircuit::<E>::name(), circuit_inputs)
                .is_none()
        );

        tracing::info!(
            "[GPU full pipeline] assign_shared_circuit complete: {} total records",
            total_records,
        );

        Ok(true)
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

    /// Filter and construct a cross-shard ShardRamRecord without EC computation.
    /// Used by the GPU path where EC is computed in batch on device.
    #[inline(always)]
    fn make_cross_shard_record(
        mem_name: &'static str,
        mem_record: &MemFinalRecord,
        waddr: WordAddr,
        addr: u32,
        shard_ctx: &ShardContext,
        addr_accessed: &[WordAddr],
    ) -> Option<(ShardRamRecord, &'static str)> {
        if addr_accessed.binary_search(&waddr).is_ok()
            || !shard_ctx.after_current_shard_cycle(mem_record.cycle)
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
        Some((global_write, mem_name))
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
    // expression for global state in/out
    pub initial_global_state_expr: Expression<E>,
    pub finalize_global_state_expr: Expression<E>,
    // circuit index -> circuit name
    // mainly used for debugging
    pub circuit_index_to_name: BTreeMap<usize, String>,
}

/// Convert raw GPU EC record bytes to ShardRamInput.
/// The raw bytes are from `GpuShardRamRecord` structs (104 bytes each).
/// EC points are already computed on GPU — no Poseidon2/SepticCurve needed.
/// Returns (writes, reads) pre-partitioned using parallel iteration.
fn gpu_ec_records_to_shard_ram_inputs<E: ExtensionField>(
    raw: &[u8],
) -> (Vec<ShardRamInput<E>>, Vec<ShardRamInput<E>>) {
    assert!(raw.len() % GPU_SHARD_RAM_RECORD_SIZE == 0);
    let count = raw.len() / GPU_SHARD_RAM_RECORD_SIZE;

    #[inline(always)]
    fn convert_record<E: ExtensionField>(raw: &[u8], i: usize) -> ShardRamInput<E> {
        use gkr_iop::RAMType;
        use p3::field::FieldAlgebra;

        let base = i * GPU_SHARD_RAM_RECORD_SIZE;
        let r = &raw[base..base + GPU_SHARD_RAM_RECORD_SIZE];

        // Read fields directly from the byte buffer.
        // Layout matches GpuShardRamRecord (104 bytes, #[repr(C)]):
        //   0: addr(u32), 4: ram_type(u32), 8: value(u32), 12: _pad(u32),
        //   16: shard(u64), 24: local_clk(u64), 32: global_clk(u64),
        //   40: is_to_write_set(u32), 44: nonce(u32),
        //   48: point_x[7](u32×7), 76: point_y[7](u32×7)
        let addr = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let ram_type_val = u32::from_le_bytes(r[4..8].try_into().unwrap());
        let value = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let shard = u64::from_le_bytes(r[16..24].try_into().unwrap());
        let local_clk = u64::from_le_bytes(r[24..32].try_into().unwrap());
        let global_clk = u64::from_le_bytes(r[32..40].try_into().unwrap());
        let is_to_write_set = u32::from_le_bytes(r[40..44].try_into().unwrap()) != 0;
        let nonce = u32::from_le_bytes(r[44..48].try_into().unwrap());

        let mut point_x_arr = [E::BaseField::ZERO; 7];
        let mut point_y_arr = [E::BaseField::ZERO; 7];
        for j in 0..7 {
            point_x_arr[j] = E::BaseField::from_canonical_u32(
                u32::from_le_bytes(r[48 + j*4..52 + j*4].try_into().unwrap()),
            );
            point_y_arr[j] = E::BaseField::from_canonical_u32(
                u32::from_le_bytes(r[76 + j*4..80 + j*4].try_into().unwrap()),
            );
        }

        let record = ShardRamRecord {
            addr,
            ram_type: if ram_type_val == 1 { RAMType::Register } else { RAMType::Memory },
            value,
            shard,
            local_clk,
            global_clk,
            is_to_write_set,
        };

        ShardRamInput {
            name: if is_to_write_set {
                "current_shard_external_write"
            } else {
                "current_shard_external_read"
            },
            record,
            ec_point: ECPoint {
                nonce,
                point: SepticPoint::from_affine(
                    SepticExtension(point_x_arr),
                    SepticExtension(point_y_arr),
                ),
            },
        }
    }

    // Parallel convert + partition in one pass
    (0..count)
        .into_par_iter()
        .map(|i| convert_record::<E>(raw, i))
        .partition(|input| input.record.is_to_write_set)
}
