use ff_ext::ExtensionField;
#[cfg(feature = "gpu")]
use gkr_iop::error::BackendError;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    hal::ProverBackend,
};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

#[cfg(feature = "gpu")]
use std::collections::HashMap;

#[cfg(feature = "gpu")]
use crate::scheme::gpu::{
    estimate_chip_proof_memory, estimate_chip_proof_reservations, is_babybear_jagged_pcs,
};
use crate::scheme::{
    hal::{MainConstraintJob, MainConstraintResult, MainSumcheckEvals},
    scheduler::{ChipScheduler, ChipTask, ChipTaskResult},
};
use either::Either;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::Instance;
use p3::field::PrimeCharacteristicRing;
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use tracing::info_span;
use transcript::{BasicTranscript, ForkableTranscript, Transcript};

use super::{PublicValues, ZKVMChipProof, ZKVMProof, hal::ProverDevice};
use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    scheme::{
        hal::{DeviceProvingKey, ProofInput},
        utils::build_main_witness,
    },
    structs::{RV32imMemStateConfig, TowerProofs, VK_DIGEST_LEN, ZKVMProvingKey, ZKVMWitnesses},
};

type CreateTableProof<'a, PB> = (
    ZKVMChipProof<<PB as ProverBackend>::E>,
    MainConstraintJob<'a, PB>,
);

#[cfg(feature = "gpu")]
fn cast_gpu_chip_task<'a, E, PCS, PB>(
    task: ChipTask<'a, PB>,
) -> ChipTask<'a, gkr_iop::gpu::GpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
{
    let task = std::mem::ManuallyDrop::new(task);
    unsafe {
        std::ptr::read(
            (&*task as *const ChipTask<'a, PB>)
                .cast::<ChipTask<'a, gkr_iop::gpu::GpuBackend<E, PCS>>>(),
        )
    }
}

#[cfg(feature = "gpu")]
fn cast_gpu_chip_result<'a, E, PCS, PB>(
    result: ChipTaskResult<'a, gkr_iop::gpu::GpuBackend<E, PCS>>,
) -> ChipTaskResult<'a, PB>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
{
    let result = std::mem::ManuallyDrop::new(result);
    unsafe {
        std::ptr::read(
            (&*result as *const ChipTaskResult<'a, gkr_iop::gpu::GpuBackend<E, PCS>>)
                .cast::<ChipTaskResult<'a, PB>>(),
        )
    }
}

#[cfg(feature = "gpu")]
pub(crate) fn prepare_gpu_chip_input<E, PCS>(
    task: &mut ChipTask<'_, gkr_iop::gpu::GpuBackend<E, PCS>>,
    pcs_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData,
) where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    let num_vars = task.input.log2_num_instances() + task.pk.get_cs().rotation_vars().unwrap_or(0);

    if let Some(trace_idx) = task.witness_trace_idx {
        let _range = nvtx::range!("ceno.phase.input-extraction");
        task.input.witness = info_span!("[ceno] extract_witness_mles").in_scope(|| {
            crate::scheme::gpu::extract_witness_mles_for_trace::<E, PCS>(
                pcs_data,
                trace_idx,
                task.num_witin,
                num_vars,
            )
        });
    }

    let virtual_production_boundary = task.structural_rmm.as_ref().is_some_and(|rmm| {
        task.circuit_name.starts_with("TensorProductionBoundary") && rmm.width() == 0
    });
    if virtual_production_boundary {
        use multilinear_extensions::StructuralWitInType;
        let structural = &task.pk.get_cs().zkvm_v1_css.structural_witins;
        assert_eq!(
            structural.len(),
            5,
            "production boundary structural width changed"
        );
        let formula_num_vars = match structural[0].witin_type {
            StructuralWitInType::OuterRepeatingIncrementalSequence { k, n } => {
                assert_eq!(
                    k, n,
                    "production boundary index must span its formula domain"
                );
                n
            }
            other => panic!("production boundary index formula changed: {other:?}"),
        };
        assert_eq!(
            formula_num_vars, 23,
            "production boundary formula domain changed"
        );
        assert_eq!(
            structural[0].witin_type.max_len(),
            1usize << formula_num_vars,
            "production boundary structural height changed"
        );
        assert!(
            num_vars >= formula_num_vars,
            "production boundary task domain is smaller than its structural formula"
        );
        assert!(
            structural[1..]
                .iter()
                .all(|w| matches!(w.witin_type, StructuralWitInType::Empty))
        );
        assert_eq!(
            structural.iter().map(|w| w.id as usize).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4],
            "production boundary structural ordering changed"
        );
        let cuda_hal = gkr_iop::gpu::get_cuda_hal().expect("Failed to get CUDA HAL");
        let kinds = [
            ceno_gpu::GPU_VIRTUAL_FORMULA_INDEX_23,
            ceno_gpu::GPU_VIRTUAL_FORMULA_ZERO,
            ceno_gpu::GPU_VIRTUAL_FORMULA_ZERO,
            ceno_gpu::GPU_VIRTUAL_FORMULA_ZERO,
            ceno_gpu::GPU_VIRTUAL_FORMULA_ONE,
        ];
        task.input.structural_witness = kinds
            .into_iter()
            .map(|kind| {
                Arc::new(gkr_iop::gpu::MultilinearExtensionGpu::from_virtual_formula(
                    &cuda_hal, num_vars, kind,
                ))
            })
            .collect();
        assert!(
            task.input
                .structural_witness
                .iter()
                .zip(kinds)
                .all(|(mle, kind)| mle.virtual_formula_kind() == Some(kind))
        );
        for row in [
            0usize,
            1,
            2,
            3,
            (1usize << 22) + 3,
            (1usize << 23) - 1,
            (1usize << 23) + 3,
            (1usize << 24) - 1,
        ] {
            let point = (0..num_vars)
                .map(|bit| E::from_u64(((row >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            let expected = [
                E::from_usize(row & ((1usize << formula_num_vars) - 1)),
                E::ZERO,
                E::ZERO,
                E::ZERO,
                E::ONE,
            ];
            let actual = task
                .input
                .structural_witness
                .iter()
                .map(|mle| mle.evaluate(&point))
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "production boundary formula differs from dense oracle at row {row}"
            );
        }
        let rmm = task
            .structural_rmm
            .take()
            .expect("boundary structural marker missing");
        assert_eq!(rmm.width(), 0, "boundary retained dense structural columns");
        assert!(
            !rmm.has_device_backing(),
            "boundary retained structural device backing"
        );
        tracing::info!(
            circuit = %task.circuit_name,
            task_num_vars = num_vars,
            formula_num_vars,
            rows = 1usize << formula_num_vars,
            formulas = "[row mod 2^23,0,0,0,1]",
            dense_bytes_elided = 5usize * (1usize << num_vars) * std::mem::size_of::<E::BaseField>(),
            "production boundary structural formulas active"
        );
    } else if let Some(rmm) = task.structural_rmm.as_ref() {
        let _range = nvtx::range!("ceno.phase.structural-transfer");
        let num_structural_witin = task.pk.get_cs().zkvm_v1_css.num_structural_witin as usize;
        task.input.structural_witness =
            info_span!("[ceno] transport_structural_witness").in_scope(|| {
                crate::scheme::gpu::transport_structural_witness_to_gpu::<E>(
                    rmm,
                    num_structural_witin,
                    num_vars,
                )
            });
    }
}

#[cfg(feature = "gpu")]
fn prove_production_matrix_reduction<E, PCS>(
    input: &ProofInput<'_, gkr_iop::gpu::GpuBackend<E, PCS>>,
    descriptor: crate::scheme::matrix_reduction::MatrixReductionDescriptor,
    transcript: &mut impl Transcript<E>,
) -> Result<
    (
        crate::scheme::MatrixReductionProof<E>,
        crate::scheme::matrix_reduction::MatrixOpeningClaims<E>,
    ),
    ZKVMError,
>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    type ProductionE = ff_ext::BabyBearExt4;
    if std::any::TypeId::of::<E>() != std::any::TypeId::of::<ProductionE>() {
        return Err(ZKVMError::InvalidWitness(
            "production matrix reduction requires BabyBearExt4".into(),
        ));
    }
    let witness = unsafe {
        &*(&input.witness[..] as *const [Arc<gkr_iop::gpu::MultilinearExtensionGpu<'static, E>>]
            as *const [Arc<gkr_iop::gpu::MultilinearExtensionGpu<'static, ProductionE>>])
    };
    let production = crate::scheme::matrix_reduction::prove_production(
        witness,
        descriptor,
        crate::scheme::gpu::expect_basic_transcript(transcript),
    )?;
    let production = std::mem::ManuallyDrop::new(production);
    Ok(unsafe {
        std::ptr::read(
            (&*production
                as *const (
                    crate::scheme::MatrixReductionProof<ProductionE>,
                    crate::scheme::matrix_reduction::MatrixOpeningClaims<ProductionE>,
                ))
                .cast::<(
                    crate::scheme::MatrixReductionProof<E>,
                    crate::scheme::matrix_reduction::MatrixOpeningClaims<E>,
                )>(),
        )
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_chip_proof<'a, E, PCS>(
    task: &mut ChipTask<'a, gkr_iop::gpu::GpuBackend<E, PCS>>,
    transcript: &mut impl Transcript<E>,
) -> Result<CreateTableProof<'a, gkr_iop::gpu::GpuBackend<E, PCS>>, ZKVMError>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    let circuit_pk = task.pk;
    let input = &task.input;
    let challenges = &task.challenges;
    let cs = circuit_pk.get_cs();
    let log2_num_instances = input.log2_num_instances();
    let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);
    let input_num_instances = input.num_instances;

    let _main_witness_range = nvtx::range!("ceno.phase.main-witness-build");
    let records = info_span!("[ceno] build_main_witness").in_scope(|| {
        build_main_witness::<
            E,
            PCS,
            gkr_iop::gpu::GpuBackend<E, PCS>,
            gkr_iop::gpu::GpuProver<gkr_iop::gpu::GpuBackend<E, PCS>>,
        >(
            cs,
            input,
            challenges,
            crate::scheme::utils::WitnessBuildStage::Tower,
        )
    });
    // Gate-5's frozen hidden-K4096 E2E has one physical row per syscall
    // circuit.  Copy just its already-materialized tower-facing record MLEs
    // under an opt-in flag so a raw custom-record producer can be compared to
    // its tile/finalize consumer before the grouped GPU product tower hides
    // the individual record identities.  This is diagnostic-only D2H; it is
    // never used by proof construction.
    if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some()
        && task.circuit_name.starts_with("TensorProduction")
    {
        let cs = &cs.zkvm_v1_css;
        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
        for (record_idx, record) in records.iter().take(num_reads + num_writes).enumerate() {
            let (direction, namespace) = if record_idx < num_reads {
                (
                    "read",
                    cs.r_expressions_namespace_map.get(record_idx).or_else(|| {
                        cs.r_table_expressions_namespace_map
                            .get(record_idx - cs.r_expressions.len())
                    }),
                )
            } else {
                let write_idx = record_idx - num_reads;
                (
                    "write",
                    cs.w_expressions_namespace_map.get(write_idx).or_else(|| {
                        cs.w_table_expressions_namespace_map
                            .get(write_idx - cs.w_expressions.len())
                    }),
                )
            };
            let values = record.inner_to_mle().get_ext_field_vec().to_vec();
            tracing::info!(
                target: "ceno_gpu::tensor_record_path",
                circuit = %task.circuit_name,
                circuit_idx = task.circuit_idx,
                logical_instances = ?input_num_instances,
                record_idx,
                direction,
                namespace = ?namespace,
                values = ?values,
                "Gate-5 individual tower record MLE"
            );
        }
    }
    drop(_main_witness_range);

    let cuda_hal = gkr_iop::gpu::get_cuda_hal().expect("Failed to get CUDA HAL");
    let span = entered_span!("prove_tower_relation", profiling_2 = true);
    let _tower_range = nvtx::range!("ceno.phase.tower-build-prove");
    let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
        info_span!("[ceno] prove_tower_relation").in_scope(|| {
            crate::scheme::gpu::prove_tower_relation_impl::<E, PCS>(
                cs, input, &records, challenges, transcript, &cuda_hal,
            )
        })?;
    drop(_tower_range);
    exit_span!(span);

    assert!(
        rt_tower.len() >= num_var_with_rotation,
        "tower challenge point length {} is shorter than main point length {}",
        rt_tower.len(),
        num_var_with_rotation,
    );
    let rt_main = rt_tower[rt_tower.len() - num_var_with_rotation..].to_vec();
    drop(records);
    crate::scheme::scheduler::notify_tower_deallocation_enqueued().map_err(|err| {
        ZKVMError::BackendError(BackendError::CircuitError(
            format!(
                "failed to publish tower phase boundary for {}: {err}",
                task.circuit_name
            )
            .into_boxed_str(),
        ))
    })?;

    let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
    let _ecc_range = nvtx::range!("ceno.phase.ecc");
    let ecc_proof = info_span!("[ceno] prove_ec_sum_quark").in_scope(|| {
        crate::scheme::gpu::prove_ec_sum_quark_impl::<E, PCS>(cs, input, transcript)
    })?;
    drop(_ecc_range);
    exit_span!(span);

    let span = entered_span!("prove_rotation", profiling_2 = true);
    let _rotation_range = nvtx::range!("ceno.phase.rotation");
    let rotation = info_span!("[ceno] prove_rotation").in_scope(|| {
        crate::scheme::gpu::prove_rotation_impl::<E, PCS>(
            cs, input, &rt_main, challenges, transcript,
        )
    })?;
    let matrix_reduction = match crate::scheme::matrix_reduction::descriptor(&task.circuit_name) {
        Some(descriptor)
            if descriptor.kind == crate::scheme::matrix_reduction::MatrixReductionKind::Tiny =>
        {
            Some(crate::scheme::matrix_reduction::prove(
                &input.witness,
                input_num_instances.iter().sum(),
                descriptor.columns,
                transcript,
            )?)
        }
        Some(descriptor) => Some(prove_production_matrix_reduction::<E, PCS>(
            input, descriptor, transcript,
        )?),
        None => None,
    };
    drop(_rotation_range);
    exit_span!(span);

    let mut main_input = input.clone();
    main_input.witness.clear();
    let virtual_production_boundary = task.circuit_name.starts_with("TensorProductionBoundary")
        && main_input.structural_witness.len() == 5
        && main_input
            .structural_witness
            .iter()
            .all(|mle| mle.virtual_formula_kind().is_some());
    if !virtual_production_boundary {
        main_input.structural_witness.clear();
    } else {
        assert_eq!(main_input.structural_witness.len(), 5);
        assert!(
            main_input
                .structural_witness
                .iter()
                .all(|mle| mle.virtual_formula_kind().is_some())
        );
    }
    let structural_rmm = task.structural_rmm.take();

    Ok((
        ZKVMChipProof {
            r_out_evals,
            w_out_evals,
            lk_out_evals,
            main_out_evals: Vec::new(),
            main_sumcheck_proofs: None,
            gkr_iop_proof: None,
            rotation_proof: rotation.clone().map(|r| r.proof),
            tower_proof,
            ecc_proof: ecc_proof.clone(),
            matrix_reduction: matrix_reduction.as_ref().map(|(proof, _)| proof.clone()),
            num_instances: input_num_instances,
        },
        MainConstraintJob {
            circuit_name: task.circuit_name.clone(),
            circuit_idx: task.circuit_idx,
            input: main_input,
            witness_trace_idx: task.witness_trace_idx,
            num_witin: task.num_witin,
            structural_rmm,
            rt_tower: rt_main,
            main_out_evals: Vec::new(),
            rotation,
            matrix_claims: matrix_reduction.map(|(_, claims)| claims),
            ecc_proof,
            challenges: *challenges,
            cs,
        },
    ))
}

pub type ZkVMCpuProver<E, PCS> =
    ZKVMProver<E, PCS, CpuBackend<E, PCS>, CpuProver<CpuBackend<E, PCS>>>;

struct DevicePkLifecycle<PB: ProverBackend> {
    first: Option<DeviceProvingKey<'static, PB>>,
    non_first: Option<DeviceProvingKey<'static, PB>>,
    entered_non_first: bool,
}

fn clone_device_pk<PB: ProverBackend>(
    key: &DeviceProvingKey<'static, PB>,
) -> DeviceProvingKey<'static, PB> {
    DeviceProvingKey {
        fixed_mles: key.fixed_mles.clone(),
        pcs_data: key.pcs_data.clone(),
    }
}

#[cfg(feature = "gpu")]
fn gpu_pool_used_bytes() -> Option<u64> {
    let hal = gkr_iop::gpu::get_cuda_hal().ok()?;
    hal.inner.mem_pool().get_used_size().ok()
}

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, PB: ProverBackend, PD>
{
    pub pk: Arc<ZKVMProvingKey<E, PCS>>,
    vk_digest: [E; VK_DIGEST_LEN],
    device: PD,
    // device_pk might be none if there is no fixed commitment
    device_pk_lifecycle: Mutex<DevicePkLifecycle<PB>>,
    _marker: PhantomData<PB>,
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
> ZKVMProver<E, PCS, PB, PD>
{
    pub fn new_with_single_shard(pk: ZKVMProvingKey<E, PCS>, device: PD) -> Self {
        let vk_digest = pk.compute_vk_digest::<RV32imMemStateConfig>();
        let pk = Arc::new(pk);
        let device_first_shard_pk = if pk.as_ref().has_fixed_commitment() {
            Some(device.transport_proving_key(true, pk.clone()))
        } else {
            None
        };

        ZKVMProver {
            pk,
            vk_digest,
            device,
            device_pk_lifecycle: Mutex::new(DevicePkLifecycle {
                first: device_first_shard_pk,
                non_first: None,
                entered_non_first: false,
            }),
            _marker: PhantomData,
        }
    }

    pub fn new(pk: Arc<ZKVMProvingKey<E, PCS>>, device: PD) -> Self {
        let vk_digest = pk.compute_vk_digest::<RV32imMemStateConfig>();
        #[cfg(feature = "gpu")]
        let pool_before = gpu_pool_used_bytes();
        let device_first_shard_pk = pk
            .as_ref()
            .has_fixed_commitment()
            .then(|| device.transport_proving_key(true, pk.clone()));
        #[cfg(feature = "gpu")]
        if let (Some(before), Some(after)) = (pool_before, gpu_pool_used_bytes()) {
            tracing::info!(
                target: "ceno_pipeline",
                key = "first",
                before_bytes = before,
                after_bytes = after,
                constructed_bytes = after.saturating_sub(before),
                "constructed one fixed device proving key"
            );
        }

        ZKVMProver {
            pk,
            vk_digest,
            device,
            device_pk_lifecycle: Mutex::new(DevicePkLifecycle {
                first: device_first_shard_pk,
                non_first: None,
                entered_non_first: false,
            }),
            _marker: PhantomData,
        }
    }

    fn device_proving_key_for_shard(
        &self,
        shard_ctx: &ShardContext,
    ) -> Option<DeviceProvingKey<'static, PB>> {
        if !self.pk.as_ref().has_fixed_commitment() {
            return None;
        }
        let mut lifecycle = self.device_pk_lifecycle.lock().unwrap();
        if shard_ctx.is_first_shard() {
            assert!(
                !lifecycle.entered_non_first,
                "first-shard fixed key requested after entering non-first shards"
            );
            Some(clone_device_pk(lifecycle.first.as_ref().expect(
                "first shard is missing its fixed device proving key",
            )))
        } else {
            if !lifecycle.entered_non_first {
                let first = lifecycle
                    .first
                    .take()
                    .expect("non-first transition is missing the first-shard fixed key");
                drop(first);
                #[cfg(feature = "gpu")]
                let pool_before = gpu_pool_used_bytes();
                let non_first = self.device.transport_proving_key(false, self.pk.clone());
                #[cfg(feature = "gpu")]
                if let (Some(before), Some(after)) = (pool_before, gpu_pool_used_bytes()) {
                    tracing::info!(
                        target: "ceno_pipeline",
                        key = "non_first",
                        shard_id = shard_ctx.shard_id,
                        before_bytes = before,
                        after_bytes = after,
                        constructed_bytes = after.saturating_sub(before),
                        "released first fixed key and constructed non-first fixed key"
                    );
                }
                lifecycle.non_first = Some(non_first);
                lifecycle.entered_non_first = true;
            }
            assert!(
                lifecycle.first.is_none(),
                "first-shard fixed key survived the non-first transition"
            );
            Some(clone_device_pk(lifecycle.non_first.as_ref().expect(
                "non-first shard is missing its fixed device proving key",
            )))
        }
    }

    pub fn setup_init_mem(&self, hints: &[u32]) -> crate::e2e::InitMemState {
        let Some(ctx) = self.pk.program_ctx.as_ref() else {
            panic!("empty program ctx")
        };
        ctx.setup_init_mem(hints)
    }
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
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
        mut transcript: impl ForkableTranscript<E> + 'static,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError>
    where
        E: crate::scheme::mock_prover::LkMultiplicityKey,
    {
        #[cfg(feature = "gpu")]
        {
            crate::instructions::gpu::cache::release_all_shard_gpu_caches();
            crate::instructions::gpu::cache::assert_caches_released_before_prove();
        }

        // Pre-extract fixed_mles before entering the tracing scope to avoid lifetime issues with std::thread::scope
        let device_pk = self.device_proving_key_for_shard(shard_ctx);
        let fixed_mles_preload = device_pk
            .as_ref()
            .map(|dpk| dpk.fixed_mles.clone())
            .unwrap_or_default();

        info_span!(
            "[ceno] create_proof_of_shard",
            shard_id = shard_ctx.shard_id
        )
        .in_scope(|| {
            let digest_span = entered_span!("commit_to_vk_digest", profiling_1 = true);
            transcript.append_field_element_exts(&self.vk_digest);
            exit_span!(digest_span);

            let span = entered_span!("commit_to_pi", profiling_1 = true);
            // Include transcript-visible public values in canonical circuit order.
            // The order must match verifier and recursion verifier exactly.
            for (_, circuit_pk) in self.pk.circuit_pks.iter() {
                for instance_value in circuit_pk.get_cs().zkvm_v1_css.instance.iter() {
                    transcript.append_field_element(&pi.query_by_index::<E>(instance_value.0));
                }
            }

            exit_span!(span);

            // commit to fixed commitment
            let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
            if let Some(fixed_commit) = self.pk.fixed_commit.as_ref() {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
            if let Some(fixed_commit) = self.pk.fixed_no_omc_init_commit.as_ref() {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
            exit_span!(span);

            let commit_to_traces_span = entered_span!("batch commit to traces", profiling_1 = true);
            let mut wits_rmms = BTreeMap::new();
            #[cfg(feature = "gpu")]
            let mut gpu_witness_traces = BTreeMap::new();

            let mock_lk_mlts = std::env::var_os("MOCK_PROVING")
                .is_some()
                .then(|| witnesses.lk_mlts().clone());

            // Extract chip metadata before consuming witnesses.
            // We reuse this for both transcript appends and task construction.
            let name_and_instances = witnesses.get_witnesses_name_instance();
            let mut structural_rmms = Vec::with_capacity(name_and_instances.len());
            #[cfg(feature = "gpu")]
            let mut witness_trace_rows = Vec::with_capacity(name_and_instances.len());
            // commit to opcode circuits first and then commit to table circuits, sorted by name
            for (i, chip_input) in witnesses.into_iter_sorted().enumerate() {
                let crate::structs::ChipInput {
                    witness_rmms,
                    ..
                } = chip_input;
                let [witness_rmm, structural_witness_rmm] = witness_rmms;

                #[cfg(feature = "gpu")]
                let use_gpu_witness_commit =
                    !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                        || is_babybear_jagged_pcs::<E, PCS>();
                #[cfg(feature = "gpu")]
                let trace_rows_for_estimate = if witness_rmm.num_instances() > 0 {
                    Some(if is_babybear_jagged_pcs::<E, PCS>() {
                        witness_rmm.occupied_physical_rows()
                    } else {
                        witness_rmm.height()
                    })
                } else {
                    None
                };

                #[cfg(feature = "gpu")]
                if use_gpu_witness_commit {
                    if witness_rmm.num_instances() > 0 && witness_rmm.width > 0 {
                        gpu_witness_traces.insert(i, witness_rmm);
                    }
                } else if witness_rmm.num_instances() > 0 && witness_rmm.width > 0 {
                    wits_rmms.insert(i, witness_rmm);
                }

                #[cfg(not(feature = "gpu"))]
                if witness_rmm.num_instances() > 0 && witness_rmm.width > 0 {
                    wits_rmms.insert(i, witness_rmm);
                }
                structural_rmms.push(structural_witness_rmm);
                #[cfg(feature = "gpu")]
                witness_trace_rows.push(trace_rows_for_estimate);
            }

            tracing::debug!(
                "witness rmm in {} MB",
                wits_rmms
                    .values()
                    .map(|v| v.values.len() * std::mem::size_of::<E::BaseField>())
                    .sum::<usize>() as f64
                    / (1024.0 * 1024.0)
            );

            for (trace_idx, rmm) in &wits_rmms {
                let bytes = rmm.values.len() * std::mem::size_of::<E::BaseField>();
                let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let circuit_name = name_and_instances
                    .get(*trace_idx)
                    .map(|(name, _)| name.as_str())
                    .unwrap_or("<unknown>");
                println!(
                    "[wits_rmms] trace_idx={} circuit={} num_instances={} elements={} size={:.6} GiB",
                    trace_idx,
                    circuit_name,
                    rmm.num_instances(),
                    rmm.values.len(),
                    gib
                );
            }

            // Build trace index map: maps circuit enum index -> trace index in pcs_data.
            // BTreeMap iterates in key order, so trace indices match insertion order.
            // GPU uses this for witness extraction; CPU ignores it.
            let circuit_trace_indices: Vec<Option<usize>> = {
                let mut next_trace = 0usize;
                (0..name_and_instances.len())
                    .map(|i| {
                        #[cfg(feature = "gpu")]
                        let has_trace = if !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                            || is_babybear_jagged_pcs::<E, PCS>()
                        {
                            gpu_witness_traces.contains_key(&i)
                        } else {
                            wits_rmms.contains_key(&i)
                        };
                        #[cfg(not(feature = "gpu"))]
                        let has_trace = wits_rmms.contains_key(&i);
                        if has_trace {
                            let idx = next_trace;
                            next_trace += 1;
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            #[cfg(feature = "gpu")]
            let using_gpu_backend = std::any::TypeId::of::<PB>()
                == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>();
            #[cfg(feature = "gpu")]
            let use_gpu_witness_commit = (!crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                || is_babybear_jagged_pcs::<E, PCS>())
                && using_gpu_backend;
            #[cfg(not(feature = "gpu"))]
            let _use_gpu_witness_commit = false;

            // commit to witness traces in batch
            #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
            let (witness_mles, mut witness_data, witin_commit): (
                Vec<Arc<PB::MultilinearPoly<'_>>>,
                PB::PcsData,
                PCS::Commitment,
            ) = {
                #[cfg(feature = "gpu")]
                if use_gpu_witness_commit {
                    info_span!("[ceno] commit_traces").in_scope(|| {
                        let gpu_device: &gkr_iop::gpu::GpuProver<gkr_iop::gpu::GpuBackend<E, PCS>> =
                            unsafe { std::mem::transmute(&self.device) };
                        let (gpu_witness_mles, gpu_witness_data, witin_commit) =
                            crate::scheme::gpu::commit_gpu_witness_traces_cache_none::<E, PCS>(
                                gpu_device,
                                gpu_witness_traces,
                            );
                        drop(gpu_witness_mles);
                        let witness_mles = Vec::new();
                        let witness_data = unsafe { std::mem::transmute_copy(&gpu_witness_data) };
                        std::mem::forget(gpu_witness_data);
                        (witness_mles, witness_data, witin_commit)
                    })
                } else {
                    info_span!("[ceno] commit_traces")
                        .in_scope(|| self.device.commit_traces(wits_rmms))
                }
                #[cfg(not(feature = "gpu"))]
                {
                    info_span!("[ceno] commit_traces").in_scope(|| self.device.commit_traces(wits_rmms))
                }
            };
            PCS::write_commitment(&witin_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
            exit_span!(commit_to_traces_span);

            // Use pre-loaded fixed_mles (extracted before in_scope to avoid lifetime issues)
            let fixed_mles = fixed_mles_preload.clone();

            // squeeze two challenges from transcript
            let challenges = [
                transcript.read_challenge().elements,
                transcript.read_challenge().elements,
            ];
            tracing::debug!("global challenges in prover: {:?}", challenges);
            let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);

            // Phase 1: Build all ChipTasks
            let build_tasks_span = entered_span!("build_chip_tasks", profiling_1 = true);
            let tasks = self.build_chip_tasks(
                shard_ctx,
                name_and_instances,
                structural_rmms,
                #[cfg(feature = "gpu")]
                witness_trace_rows,
                witness_mles,
                &witness_data,
                fixed_mles,
                challenges,
                &pi,
                &circuit_trace_indices,
            );
            exit_span!(build_tasks_span);

            #[cfg(feature = "gpu")]
            if let Some(lk_mlts) = mock_lk_mlts {
                assert_eq!(
                    std::any::TypeId::of::<PB>(),
                    std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>(),
                    "exact GPU MLE MockProver requires the GPU backend"
                );
                let gpu_tasks = tasks
                    .into_iter()
                    .map(cast_gpu_chip_task::<E, PCS, PB>)
                    .collect();
                let gpu_witness_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(&witness_data) };
                let ctx = self
                    .pk
                    .program_ctx
                    .as_ref()
                    .expect("MockProver requires the E2E program context");
                crate::scheme::mock_prover::MockProver::assert_satisfied_gpu_tasks::<PCS>(
                    ctx.zkvm_fixed_traces.clone(),
                    &lk_mlts,
                    gpu_tasks,
                    gpu_witness_data,
                    &ctx.program,
                );
                tracing::info!("Mock proving passed");
                return Err(ZKVMError::MockProvingComplete);
            }

            // Phase 2: Execute chip proof tasks
            // GPU concurrent: memory-aware backfilling with standalone impl.
            // Sequential (GPU + CPU): unified path via self.create_chip_proof.
            let execute_tasks_span = entered_span!("execute_chip_tasks", profiling_1 = true);
            let fork_transcript = BasicTranscript::<E>::new(b"fork");
            let (results, forked_samples) =
                self.run_chip_proofs(tasks, &fork_transcript, &witness_data)?;
            exit_span!(execute_tasks_span);

            // Phase 3: Collect results
            let collect_results_span = entered_span!("collect_chip_results", profiling_1 = true);
            let (chip_proofs, main_constraint_jobs) = Self::collect_chip_results(results);
            exit_span!(collect_results_span);
            exit_span!(main_proofs_span);

            // merge forked transcript samples into main transcript
            for sample in forked_samples {
                transcript.append_field_element_ext(&sample);
            }

            #[cfg(feature = "gpu")]
            if using_gpu_backend {
                let gpu_witness_data: &mut gkr_iop::gpu::GpuPcsData =
                    unsafe { std::mem::transmute(&mut witness_data) };
                crate::scheme::gpu::spill_gpu_digest_before_main(gpu_witness_data);
            }

            let main_constraints_span =
                entered_span!("prove_batched_main_constraints", profiling_1 = true);
            let (main_constraint_proof, main_constraint_results) =
                info_span!("[ceno] prove_batched_main_constraints").in_scope(|| {
                    self.device.prove_batched_main_constraints(
                        main_constraint_jobs,
                        &witness_data,
                        &mut transcript,
                    )
                })?;

            #[cfg(feature = "gpu")]
            if using_gpu_backend {
                let gpu_witness_data: &mut gkr_iop::gpu::GpuPcsData =
                    unsafe { std::mem::transmute(&mut witness_data) };
                crate::scheme::gpu::restore_gpu_digest_before_open(gpu_witness_data);
            }
            let (points, evaluations) = collect_main_constraint_openings(main_constraint_results);
            exit_span!(main_constraints_span);

            // batch opening pcs
            // generate static info from prover key for expected num variable
            let pcs_opening = entered_span!("pcs_opening", profiling_1 = true);
            let mpcs_opening_proof = info_span!("[ceno] pcs_opening").in_scope(|| {
                self.device.open(
                    witness_data,
                    device_pk.as_ref().map(|dpk| dpk.pcs_data.clone()),
                    points,
                    evaluations,
                    &mut transcript,
                )
            });
            exit_span!(pcs_opening);

            let vm_proof = ZKVMProof::new(
                pi,
                chip_proofs,
                main_constraint_proof,
                witin_commit,
                mpcs_opening_proof,
            );

            Ok(vm_proof)
        })
    }

    /// Phase 2: Execute all chip proof tasks via scheduler.
    ///
    /// Sequential mode (GPU + CPU): uses `self.create_chip_proof` via trait dispatch.
    ///
    /// Handles transcript forking and sampling internally via the scheduler.
    fn run_chip_proofs<'data, T: Transcript<E> + Clone>(
        &self,
        tasks: Vec<ChipTask<'data, PB>>,
        transcript: &T,
        witness_data: &PB::PcsData,
    ) -> Result<(Vec<ChipTaskResult<'data, PB>>, Vec<E>), ZKVMError> {
        let scheduler = ChipScheduler::new();

        #[cfg(feature = "gpu")]
        {
            if ChipScheduler::is_concurrent_mode() {
                // GPU concurrent: standalone function path (no &self needed for Send+Sync)
                // Verify at runtime that PB is indeed GpuBackend<E, PCS> before transmuting.
                assert_eq!(
                    std::any::TypeId::of::<PB>(),
                    std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>(),
                    "Concurrent GPU path requires PB = GpuBackend<E, PCS>"
                );
                // SAFETY: TypeId check above guarantees PB = GpuBackend<E, PCS>, so PcsData types match.
                let gpu_witness_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(witness_data) };

                // SAFETY: pcs_data is only read (via get_trace) during concurrent execution.
                use crate::scheme::utils::SyncRef;
                let gpu_wd = SyncRef(gpu_witness_data);

                let phase_releasable_by_task = tasks
                    .iter()
                    .map(|task| {
                        let gpu_task: &ChipTask<'_, gkr_iop::gpu::GpuBackend<E, PCS>> =
                            unsafe { std::mem::transmute(task) };
                        let structural_cached_on_device =
                            gpu_task.structural_rmm.as_ref().is_some_and(|rmm| {
                                (gpu_task
                                    .circuit_name
                                    .starts_with("TensorProductionBoundary")
                                    && rmm.width() == 0)
                                    || rmm.has_device_backing()
                            });
                        let reservation = estimate_chip_proof_reservations::<E, PCS>(
                            gpu_task.pk.get_cs(),
                            &gpu_task.input,
                            &gpu_task.circuit_name,
                            gpu_task.witness_trace_rows,
                            structural_cached_on_device,
                        );
                        (gpu_task.task_id, reservation.releasable_bytes)
                    })
                    .collect::<HashMap<_, _>>();

                return scheduler.execute_with_phase_reservations(
                    tasks,
                    transcript,
                    |task, transcript| {
                        // Bind global challenges and metadata in the same order as verifier.
                        transcript.append_field_element_ext(&task.challenges[0]);
                        transcript.append_field_element_ext(&task.challenges[1]);
                        transcript.append_field_element(&E::BaseField::from_usize(task.task_id));
                        // Append circuit_idx to per-task forked transcript (matching verifier)
                        transcript
                            .append_field_element(&E::BaseField::from_u64(task.circuit_idx as u64));
                        for num_instance in task.input.num_instances {
                            transcript
                                .append_field_element(&E::BaseField::from_usize(num_instance));
                        }

                        let mut gpu_task = cast_gpu_chip_task::<E, PCS, PB>(task);
                        prepare_gpu_chip_input(&mut gpu_task, gpu_wd.0);
                        let (proof, main_constraint_job) =
                            create_gpu_chip_proof::<E, PCS>(&mut gpu_task, transcript)?;
                        let gpu_result = ChipTaskResult {
                            task_id: gpu_task.task_id,
                            circuit_idx: gpu_task.circuit_idx,
                            proof,
                            opening_evals: MainSumcheckEvals {
                                wits_in_evals: vec![],
                                fixed_in_evals: vec![],
                            },
                            input_opening_point: vec![],
                            main_constraint_job: Some(main_constraint_job),
                            has_witness_or_fixed: gpu_task.has_witness_or_fixed,
                        };

                        Ok(cast_gpu_chip_result::<E, PCS, PB>(gpu_result))
                    },
                    phase_releasable_by_task,
                );
            }
        }

        // Sequential path (GPU + CPU unified):
        // Uses execute_sequentially directly to avoid Send+Sync requirement on the closure.
        scheduler.execute_sequentially(tasks, transcript, |mut task, transcript| {
            // Bind global challenges and metadata in the same order as verifier.
            transcript.append_field_element_ext(&task.challenges[0]);
            transcript.append_field_element_ext(&task.challenges[1]);
            transcript.append_field_element(&E::BaseField::from_usize(task.task_id));
            // Append circuit_idx to per-task forked transcript (matching verifier)
            transcript.append_field_element(&E::BaseField::from_u64(task.circuit_idx as u64));
            for num_instance in task.input.num_instances {
                transcript.append_field_element(&E::BaseField::from_usize(num_instance));
            }

            // Prepare: deferred extraction for GPU, no-op for CPU
            self.device.prepare_chip_input(&mut task, witness_data);

            let (proof, main_constraint_job) = self.create_chip_proof(&mut task, transcript)?;

            Ok(ChipTaskResult {
                task_id: task.task_id,
                circuit_idx: task.circuit_idx,
                proof,
                opening_evals: MainSumcheckEvals {
                    wits_in_evals: vec![],
                    fixed_in_evals: vec![],
                },
                input_opening_point: vec![],
                main_constraint_job: Some(main_constraint_job),
                has_witness_or_fixed: task.has_witness_or_fixed,
            })
        })
    }

    /// create proof for opcode and table circuits
    ///
    /// for each read/write/logup expression, we pack all records of that type
    /// into a single tower tree, and then feed these trees into tower prover.
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=%task.circuit_name, profiling_2
    ), level = "trace")]
    pub fn create_chip_proof<'a>(
        &self,
        task: &mut ChipTask<'a, PB>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<CreateTableProof<'a, PB>, ZKVMError> {
        let circuit_pk = task.pk;
        let input = &task.input;
        let challenges = &task.challenges;

        let cs = circuit_pk.get_cs();
        let log2_num_instances = input.log2_num_instances();
        let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);
        let input_num_instances = input.num_instances;
        #[cfg(not(feature = "gpu"))]
        let input_has_ecc_ops = input.has_ecc_ops;

        // build main witness
        let records = info_span!("[ceno] build_main_witness").in_scope(|| {
            // ECC and rotation have dedicated witness/eval flows. For tower proving we only
            // materialize the tower-facing GKR outputs here to avoid keeping unrelated output
            // MLEs resident in VRAM during tower prove.
            build_main_witness::<E, PCS, PB, PD>(
                cs,
                input,
                challenges,
                crate::scheme::utils::WitnessBuildStage::Tower,
            )
        });

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        // prove the product and logup sum relation between layers in tower
        // (internally calls build_tower_witness)
        let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
            info_span!("[ceno] prove_tower_relation").in_scope(|| {
                self.device
                    .prove_tower_relation(cs, input, &records, challenges, transcript)
            });
        exit_span!(span);

        drop(records);

        assert!(
            rt_tower.len() >= num_var_with_rotation,
            "tower challenge point length {} is shorter than main point length {}",
            rt_tower.len(),
            num_var_with_rotation,
        );
        let rt_main = rt_tower[rt_tower.len() - num_var_with_rotation..].to_vec();

        let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
        let ecc_proof = info_span!("[ceno] prove_ec_sum_quark")
            .in_scope(|| self.device.prove_ec_sum_quark(cs, input, transcript))?;
        exit_span!(span);

        let span = entered_span!("prove_rotation", profiling_2 = true);
        let rotation = info_span!("[ceno] prove_rotation").in_scope(|| {
            self.device
                .prove_rotation(cs, input, &rt_main, challenges, transcript)
        })?;

        let matrix_reduction = match crate::scheme::matrix_reduction::descriptor(&task.circuit_name)
        {
            Some(descriptor)
                if descriptor.kind
                    == crate::scheme::matrix_reduction::MatrixReductionKind::Tiny =>
            {
                Some(crate::scheme::matrix_reduction::prove(
                    &input.witness,
                    input_num_instances.iter().sum(),
                    descriptor.columns,
                    transcript,
                )?)
            }
            Some(descriptor) => {
                if std::any::TypeId::of::<PB>()
                    != std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>()
                {
                    return Err(ZKVMError::InvalidWitness(
                        "production matrix reduction has no CPU prover path".into(),
                    ));
                }
                let gpu_input = unsafe {
                    &*(input as *const ProofInput<'_, PB>
                        as *const ProofInput<'_, gkr_iop::gpu::GpuBackend<E, PCS>>)
                };
                Some(prove_production_matrix_reduction::<E, PCS>(
                    gpu_input, descriptor, transcript,
                )?)
            }
            None => None,
        };
        exit_span!(span);

        #[cfg(feature = "gpu")]
        let main_input = {
            let mut input = input.clone();
            if std::any::TypeId::of::<PB>()
                == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>()
            {
                input.witness.clear();
                let virtual_production_boundary =
                    task.circuit_name.starts_with("TensorProductionBoundary")
                        && task.structural_rmm.is_none();
                if !virtual_production_boundary {
                    input.structural_witness.clear();
                }
            }
            input
        };
        #[cfg(not(feature = "gpu"))]
        let main_input = std::mem::replace(
            &mut task.input,
            ProofInput {
                witness: Vec::new(),
                structural_witness: Vec::new(),
                fixed: Vec::new(),
                pi: Vec::new(),
                num_instances: input_num_instances,
                has_ecc_ops: input_has_ecc_ops,
            },
        );
        #[cfg(feature = "gpu")]
        let structural_rmm = task.structural_rmm.take();
        #[cfg(not(feature = "gpu"))]
        let structural_rmm = None;

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_out_evals: Vec::new(),
                main_sumcheck_proofs: None,
                gkr_iop_proof: None,
                rotation_proof: rotation.clone().map(|r| r.proof),
                tower_proof,
                ecc_proof: ecc_proof.clone(),
                matrix_reduction: matrix_reduction.as_ref().map(|(proof, _)| proof.clone()),
                num_instances: input_num_instances,
            },
            MainConstraintJob {
                circuit_name: task.circuit_name.clone(),
                circuit_idx: task.circuit_idx,
                input: main_input,
                witness_trace_idx: task.witness_trace_idx,
                num_witin: task.num_witin,
                structural_rmm,
                rt_tower: rt_main,
                main_out_evals: Vec::new(),
                rotation,
                matrix_claims: matrix_reduction.map(|(_, claims)| claims),
                ecc_proof,
                challenges: *challenges,
                cs,
            },
        ))
    }

    /// Phase 1: Build ChipTasks from witness data.
    /// All #[cfg] for eager vs deferred extraction are contained here.
    #[allow(clippy::too_many_arguments)]
    fn build_chip_tasks<'data>(
        &self,
        shard_ctx: &ShardContext,
        name_and_instances: Vec<(String, [usize; 2])>,
        structural_rmms: Vec<witness::RowMajorMatrix<E::BaseField>>,
        #[cfg(feature = "gpu")] witness_trace_rows: Vec<Option<usize>>,
        #[allow(unused_mut)] mut witness_mles: Vec<Arc<PB::MultilinearPoly<'data>>>,
        witness_data: &PB::PcsData,
        mut fixed_mles: Vec<Arc<PB::MultilinearPoly<'data>>>,
        challenges: [E; 2],
        pi: &PublicValues,
        circuit_trace_indices: &[Option<usize>],
    ) -> Vec<ChipTask<'_, PB>> {
        // CPU path: eagerly extract witness MLEs from pcs_data
        #[cfg(not(feature = "gpu"))]
        let mut witness_iter = self
            .device
            .extract_witness_mles(&mut witness_mles, witness_data);

        #[cfg(feature = "gpu")]
        let _ = (&witness_mles, witness_data); // suppress unused warnings on GPU path

        let mut tasks: Vec<ChipTask<'_, PB>> = Vec::new();
        let mut task_id = 0usize;

        for (circuit_enum_idx, ((circuit_name, num_instances), structural_rmm)) in
            name_and_instances
                .into_iter()
                .zip_eq(structural_rmms.into_iter())
                .enumerate()
        {
            let this_idx = circuit_enum_idx;

            let circuit_idx = self
                .pk
                .circuit_name_to_index
                .get(&circuit_name)
                .cloned()
                .expect("invalid circuit {} not exist in ceno zkvm");
            let pk = self.pk.circuit_pks.get(&circuit_name).unwrap();
            let cs = pk.get_cs();
            if !shard_ctx.is_first_shard() && cs.with_omc_init_only() {
                assert_eq!(num_instances, [0, 0]);
                // skip drain respective fixed because we use different set of fixed commitment
                continue;
            }
            if num_instances.iter().sum::<usize>() == 0 {
                // we need to drain respective fixed when num_instances is 0
                if cs.num_fixed() > 0 {
                    let _ = fixed_mles.drain(..cs.num_fixed()).collect_vec();
                }
                continue;
            }

            // GPU path: defer witness and structural witness extraction to task execution
            #[cfg(feature = "gpu")]
            let (witness_mle, structural_witness, task_structural_rmm) =
                { (vec![], vec![], Some(structural_rmm)) };

            // CPU path: eagerly extract witness and structural witness
            #[cfg(not(feature = "gpu"))]
            let (witness_mle, structural_witness, task_structural_rmm) = {
                let witness_mle = info_span!("[ceno] extract_witness_mles").in_scope(|| {
                    if cs.num_witin() > 0 {
                        let mles = witness_iter.by_ref().take(cs.num_witin()).collect_vec();
                        assert_eq!(
                            mles.len(),
                            cs.num_witin(),
                            "insufficient witness mles for circuit {}",
                            circuit_name
                        );
                        mles
                    } else {
                        vec![]
                    }
                });
                let structural_witness = info_span!("[ceno] transport_structural_witness")
                    .in_scope(|| {
                        let structural_mles = structural_rmm.to_mles();
                        self.device.transport_mles(structural_mles)
                    });
                (witness_mle, structural_witness, None)
            };

            let fixed = fixed_mles.drain(..cs.num_fixed()).collect_vec();

            let circuit_pi = cs
                .zkvm_v1_css
                .instance
                .iter()
                .map(|Instance(idx)| Either::Left(pi.query_by_index::<E>(*idx)))
                .collect_vec();

            let input_temp: ProofInput<'_, PB> = ProofInput {
                witness: witness_mle,
                fixed,
                structural_witness,
                pi: circuit_pi,
                num_instances,
                has_ecc_ops: cs.has_ecc_ops(),
            };
            // SAFETY: All Arcs in ProofInput contain 'static data:
            // - GPU path: `witness` and `structural_witness` are empty vecs (deferred extraction),
            //   `fixed` originates from `DeviceProvingKey<'static, PB>`.
            // - CPU path: `witness_mle` may borrow non-'static data, but the CPU path always
            //   uses sequential execution (never enters the concurrent scheduler), so the data
            //   remains valid for the lifetime of `build_chip_tasks`'s caller.
            // The inferred lifetime is shorter than 'static only because the compiler cannot
            // prove the Arc contents are 'static across both cfg paths.
            let input = unsafe {
                std::mem::transmute::<ProofInput<'_, PB>, ProofInput<'static, PB>>(input_temp)
            };

            #[cfg(feature = "gpu")]
            if [
                "TensorAttentionQKHeads",
                "TensorAttentionPVHeads",
                "TensorAttentionShiftHeads",
                "TensorAttentionSoftmaxHeads",
            ]
            .iter()
            .any(|prefix| circuit_name.starts_with(prefix))
            {
                let trace_rows = witness_trace_rows[this_idx].unwrap_or_else(|| {
                    panic!("{circuit_name}: production TensorVM trace rows are missing")
                });
                assert_eq!(
                    cs.rotation_vars().unwrap_or(0),
                    0,
                    "{circuit_name}: production TensorVM Core unexpectedly became rotating"
                );
                assert_eq!(
                    num_instances,
                    [trace_rows, 0],
                    "{circuit_name}: production TensorVM logical instances differ from committed trace rows"
                );
                let task_num_vars = input.log2_num_instances();
                assert_eq!(
                    trace_rows,
                    1usize << task_num_vars,
                    "{circuit_name}: production TensorVM committed and deferred logical domains differ"
                );
                tracing::info!(
                    target: "ceno_pipeline",
                    circuit = %circuit_name,
                    trace_rows,
                    logical_instances = num_instances[0],
                    task_num_vars,
                    "production TensorVM pre-scheduler domain validated"
                );
            }

            // Estimate memory for this task
            #[cfg(feature = "gpu")]
            let estimated_memory = {
                // SAFETY: TypeId check in run_chip_proofs guarantees PB = GpuBackend<E, PCS>.
                debug_assert_eq!(
                    std::any::TypeId::of::<PB>(),
                    std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>(),
                    "GPU memory estimation requires PB = GpuBackend<E, PCS>"
                );
                let gpu_input: &ProofInput<'_, gkr_iop::gpu::GpuBackend<E, PCS>> =
                    unsafe { std::mem::transmute(&input) };
                // Production boundaries use validated formula MLEs and have no
                // structural device allocation. Their empty RMM is a marker, not
                // an uncached dense structural matrix.
                let structural_cached_on_device = task_structural_rmm.as_ref().is_some_and(|rmm| {
                    (circuit_name.starts_with("TensorProductionBoundary") && rmm.width() == 0)
                        || rmm.has_device_backing()
                });
                estimate_chip_proof_memory::<E, PCS>(
                    cs,
                    gpu_input,
                    &circuit_name,
                    witness_trace_rows[this_idx],
                    structural_cached_on_device,
                )
            };
            #[cfg(not(feature = "gpu"))]
            let estimated_memory = 0u64; // CPU path doesn't need memory tracking

            #[cfg(feature = "gpu")]
            let booked_memory = if circuit_name.starts_with("TensorProductionBoundary") {
                let boundary_kind = if circuit_name.contains("ProjectionInput") {
                    "projection_input"
                } else if circuit_name.contains("ProjectionOutput") {
                    "projection_output"
                } else {
                    "other"
                };
                tracing::info!(
                    target: "ceno_pipeline",
                    circuit = %circuit_name,
                    boundary_kind,
                    estimated_bytes = estimated_memory,
                    booked_bytes = estimated_memory,
                    "production boundary exclusive estimator booking"
                );
                estimated_memory
            } else {
                estimated_memory
            };
            #[cfg(not(feature = "gpu"))]
            let booked_memory = estimated_memory;

            // Look up trace index for deferred extraction (GPU uses this; CPU ignores it)
            let witness_trace_idx = if cs.num_witin() > 0 {
                circuit_trace_indices[this_idx]
            } else {
                None
            };
            tasks.push(ChipTask {
                task_id,
                circuit_name: circuit_name.clone(),
                circuit_idx,
                pk,
                input,
                estimated_memory_bytes: estimated_memory,
                booked_memory_bytes: booked_memory,
                has_witness_or_fixed: cs.num_witin() > 0 || cs.num_fixed() > 0,
                challenges,
                witness_trace_idx,
                #[cfg(feature = "gpu")]
                witness_trace_rows: witness_trace_rows[this_idx],
                num_witin: cs.num_witin(),
                structural_rmm: task_structural_rmm,
            });
            task_id += 1;
        }
        #[cfg(not(feature = "gpu"))]
        drop(witness_iter);

        tasks
    }

    /// Phase 3: Collect chip proof results into proof components.
    #[allow(clippy::type_complexity)]
    fn collect_chip_results<'a>(
        results: Vec<ChipTaskResult<'a, PB>>,
    ) -> (
        BTreeMap<usize, ZKVMChipProof<E>>,
        Vec<MainConstraintJob<'a, PB>>,
    ) {
        let mut chip_proofs = BTreeMap::new();
        let mut main_constraint_jobs = Vec::new();

        for result in results {
            tracing::trace!(
                "generated proof for circuit {} with circuit_idx={}",
                result.circuit_idx,
                result.task_id
            );

            if let Some(job) = result.main_constraint_job {
                main_constraint_jobs.push(job);
            }
            let prev = chip_proofs.insert(result.circuit_idx, result.proof);
            assert!(
                prev.is_none(),
                "duplicate chip proof for circuit_idx={} is not supported",
                result.circuit_idx
            );
        }

        (chip_proofs, main_constraint_jobs)
    }
}

/// Preserve the main-sumcheck producer order while converting its output into
/// the paired point/evaluation input consumed by PCS opening.  This seam is
/// deliberately standalone so small PCS tests can exercise the same routing
/// without constructing the full RV registry.
pub(crate) fn collect_main_constraint_openings<E: ExtensionField>(
    results: Vec<MainConstraintResult<E>>,
) -> (Vec<Point<E>>, Vec<Vec<Vec<E>>>) {
    let trace_ownership_debug = std::env::var_os("CENO_GPU_TRACE_OWNERSHIP").is_some();
    let mut points = Vec::new();
    let mut evaluations = Vec::new();
    for result in results {
        if !result.opening_evals.wits_in_evals.is_empty()
            || !result.opening_evals.fixed_in_evals.is_empty()
        {
            if trace_ownership_debug {
                tracing::info!(
                    target: "ceno_gpu::basefold_ownership",
                    opening_idx = points.len(),
                    circuit_idx = result.circuit_idx,
                    query_dim = result.input_opening_point.len(),
                    witness_mles = result.opening_evals.wits_in_evals.len(),
                    fixed_mles = result.opening_evals.fixed_in_evals.len(),
                    "[basefold ownership] main/tower result source"
                );
            }
            points.push(result.input_opening_point);
            evaluations.push(vec![
                result.opening_evals.wits_in_evals,
                result.opening_evals.fixed_in_evals,
            ]);
        }
    }
    (points, evaluations)
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
