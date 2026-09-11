use std::{marker::PhantomData, sync::Arc};
#[cfg(feature = "gpu")]
use std::{sync::Mutex, time::Instant};

use anyhow::{Context, Result};
#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
use ceno_emul::StepCellExtractor;
use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
#[cfg(feature = "gpu")]
use ceno_recursion_v2::continuation::prover::{
    GpuRecursionBatchOutput, GpuRecursionSession, RecursionHostAssetsBuilder,
    RecursionWorkerMetrics, RootProvingOutput,
};
use ceno_recursion_v2::{
    continuation::prover::{AggProver, AggregationOptions, LeafVk, RootProof, SystemParams},
    system::{
        RecursionField, RecursionPcs, RecursionProof, utils::test_system_params_zero_pow,
        warm_child_vk_digest_cache,
    },
};
#[cfg(not(feature = "gpu"))]
use ceno_zkvm::e2e::run_e2e_proof_with_precompiled_aot;
#[cfg(feature = "gpu")]
use ceno_zkvm::e2e::{
    BaseDeviceReleased, BaseProofReady, BaseProvingEventSink,
    run_e2e_multi_gpu_proof_with_precompiled_aot_and_sink,
};
#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
use ceno_zkvm::e2e::{prepare_fulltracer_aot_program, prepare_preflight_aot_program};
#[cfg(feature = "gpu")]
use ceno_zkvm::multi_gpu::{MultiGpuConfig, PreparedMultiGpu};
#[cfg(not(feature = "gpu"))]
use ceno_zkvm::scheme::create_prover;
use ceno_zkvm::{
    e2e::{MultiProver, setup_program},
    scheme::{
        ZKVMProof, create_backend, hal::ProverDevice, mock_prover::LkMultiplicityKey,
        prover::ZKVMProver, verifier::ZKVMVerifier,
    },
    structs::{ZKVMProvingKey, ZKVMVerifyingKey},
};
use ff_ext::ExtensionField;
#[cfg(not(feature = "gpu"))]
use gkr_iop::cpu::{CpuBackend, CpuProver};
#[cfg(feature = "gpu")]
use gkr_iop::gpu::{GpuBackend, GpuProver};
use gkr_iop::hal::ProverBackend;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use serde::Serialize;

pub const DEFAULT_LEAF_FANIN: usize = 4;
pub const DEFAULT_INTERNAL_FANIN: usize = 4;
pub const DEFAULT_RECURSION_L_SKIP: usize = 5;
pub const DEFAULT_RECURSION_N_STACK: usize = 16;
pub const DEFAULT_RECURSION_K_WHIR: usize = 3;

pub type CenoRecursionV2Prover = AggProver<DEFAULT_LEAF_FANIN, DEFAULT_INTERNAL_FANIN>;
pub type CenoRecursionV2RootProof = RootProof;
pub type CenoRecursionV2LeafVk = LeafVk;
#[cfg(feature = "gpu")]
type DefaultGpuRecursionSession = GpuRecursionSession<DEFAULT_LEAF_FANIN, DEFAULT_INTERNAL_FANIN>;
#[cfg(feature = "gpu")]
type DefaultRecursionHostAssetsBuilder =
    RecursionHostAssetsBuilder<DEFAULT_LEAF_FANIN, DEFAULT_INTERNAL_FANIN>;

#[cfg(feature = "gpu")]
#[derive(Clone, Debug, Default)]
pub struct StreamingRecursionTimings {
    pub base_proving: std::time::Duration,
    pub recursion_streaming: std::time::Duration,
    pub root_verification: std::time::Duration,
    pub total: std::time::Duration,
}

#[cfg(feature = "gpu")]
pub struct StreamingRecursionOutput {
    pub base_proofs: Vec<RecursionProof>,
    pub root_output: RootProvingOutput,
    pub worker_metrics: Vec<RecursionWorkerMetrics>,
    pub timings: StreamingRecursionTimings,
}

#[cfg(feature = "gpu")]
struct RecursionOrchestrationState<S> {
    session: Option<S>,
    first_error: Option<String>,
    proof_count: usize,
    released_devices: usize,
    base_verified: bool,
}

#[cfg(feature = "gpu")]
impl<S> RecursionOrchestrationState<S> {
    fn new() -> Self {
        Self {
            session: None,
            first_error: None,
            proof_count: 0,
            released_devices: 0,
            base_verified: false,
        }
    }

    fn start(&mut self, session: S) -> Result<(), String> {
        if self.session.is_some() {
            return Err("base proving initialized recursion twice".to_owned());
        }
        self.session = Some(session);
        Ok(())
    }

    fn accept_proof(
        &mut self,
        accept: impl FnOnce(&mut S) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        accept(
            self.session
                .as_mut()
                .ok_or("base proof arrived before recursion initialization")?,
        )?;
        self.proof_count += 1;
        Ok(())
    }

    fn release_device(
        &mut self,
        release: impl FnOnce(&mut S) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        release(
            self.session
                .as_mut()
                .ok_or("GPU was released before recursion initialization")?,
        )?;
        self.released_devices += 1;
        Ok(())
    }

    fn fail(&mut self, error: &str, cancel: impl FnOnce(&mut S)) {
        if self.first_error.is_some() {
            return;
        }
        if let Some(session) = &mut self.session {
            cancel(session);
        }
        self.first_error = Some(error.to_owned());
    }

    fn mark_base_verified(&mut self) {
        self.base_verified = true;
    }

    fn take_verified_session(&mut self) -> Result<S, String> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if !self.base_verified {
            return Err("canonical base verification has not completed".to_owned());
        }
        self.session
            .take()
            .ok_or("base proving never initialized recursion".to_owned())
    }
}

#[cfg(feature = "gpu")]
pub struct StreamingRecursionOrchestrator {
    options: AggregationOptions,
    state: Mutex<RecursionOrchestrationState<DefaultGpuRecursionSession>>,
    assets_builder: Mutex<Option<DefaultRecursionHostAssetsBuilder>>,
    started: Instant,
}

#[cfg(feature = "gpu")]
impl StreamingRecursionOrchestrator {
    pub fn new(options: AggregationOptions) -> Self {
        Self {
            options,
            state: Mutex::new(RecursionOrchestrationState::new()),
            assets_builder: Mutex::new(None),
            started: Instant::now(),
        }
    }

    fn with_assets_builder(
        options: AggregationOptions,
        assets_builder: DefaultRecursionHostAssetsBuilder,
    ) -> Self {
        Self {
            options,
            state: Mutex::new(RecursionOrchestrationState::new()),
            assets_builder: Mutex::new(Some(assets_builder)),
            started: Instant::now(),
        }
    }

    pub fn mark_base_verified(&self) {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .mark_base_verified();
    }

    pub fn finish(&self) -> Result<GpuRecursionBatchOutput, String> {
        let (session, proof_count, released_devices) = {
            let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
            (
                state.take_verified_session()?,
                state.proof_count,
                state.released_devices,
            )
        };
        let output = session.finish().map_err(|error| error.to_string())?;
        log_recursion_completion(
            &output,
            proof_count,
            released_devices,
            self.started.elapsed(),
        );
        Ok(output)
    }
}

#[cfg(feature = "gpu")]
impl Drop for StreamingRecursionOrchestrator {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|err| err.into_inner());
        if let Some(session) = state.session.take() {
            session.cancel("streaming recursion orchestration ended before root publication");
            let _ = session.finish();
        }
    }
}

#[cfg(feature = "gpu")]
impl BaseProvingEventSink<RecursionField, RecursionPcs> for StreamingRecursionOrchestrator {
    fn on_started(
        &self,
        total_shards: usize,
        app_vk: ceno_zkvm::structs::ZKVMVerifyingKey<RecursionField, RecursionPcs>,
        app_vk_digest: [RecursionField; ceno_zkvm::structs::VK_DIGEST_LEN],
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let assets_builder = self
            .assets_builder
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
            .map(Ok)
            .unwrap_or_else(|| {
                RecursionHostAssetsBuilder::spawn(
                    Arc::new(app_vk),
                    app_vk_digest,
                    self.options.clone(),
                )
                .map_err(|error| error.to_string())
            })?;
        assets_builder
            .validate_child_vk_digest(&app_vk_digest)
            .map_err(|error| error.to_string())?;
        state.start(
            GpuRecursionSession::new_with_assets_builder(total_shards, assets_builder)
                .map_err(|error| error.to_string())?,
        )?;
        tracing::info!(
            target: "ceno_multi_gpu",
            total_shards,
            phase = "recursion_session_started",
            "streaming recursion scheduler initialized"
        );
        Ok(())
    }

    fn on_proof_ready(
        &self,
        ready: BaseProofReady<RecursionField, RecursionPcs>,
    ) -> Result<(), String> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .accept_proof(|session| {
                session
                    .accept_base_proof(ready.shard_id, ready.proof)
                    .map_err(|error| error.to_string())
            })
    }

    fn on_device_released(&self, released: BaseDeviceReleased) -> Result<(), String> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .release_device(|session| {
                session
                    .release_device(released.device_id)
                    .map_err(|error| error.to_string())
            })
    }

    fn on_failure(&self, error: &str) {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .fail(error, |session| session.cancel(error.to_owned()));
    }
}

#[cfg(feature = "gpu")]
fn log_recursion_completion(
    output: &GpuRecursionBatchOutput,
    proof_count: usize,
    released_devices: usize,
    elapsed: std::time::Duration,
) {
    for metrics in &output.worker_metrics {
        tracing::info!(
            target: "ceno_multi_gpu",
            device_id = metrics.device_id,
            task_count = metrics.task_count,
            leaf_tasks = metrics.leaf_tasks,
            leaf_bridge_tasks = metrics.leaf_bridge_tasks,
            recursive_tasks = metrics.recursive_tasks,
            root_tasks = metrics.root_tasks,
            asset_hydrations = metrics.asset_hydrations,
            asset_switches = metrics.asset_switches,
            hydration_ms = metrics.hydration_time.as_millis(),
            proving_ms = metrics.proving_time.as_millis(),
            total_ms = metrics.total_time.as_millis(),
            phase = "recursion_worker_metrics",
            "streaming recursion worker complete"
        );
    }
    tracing::info!(
        target: "ceno_multi_gpu",
        proof_count,
        released_devices,
        elapsed_ms = elapsed.as_millis(),
        root_verification_ms = output.root_verification_time.as_millis(),
        phase = "root_publication_gate",
        "canonical base verification succeeded; recursion root may be published"
    );
}

pub fn recursion_system_params(l_skip: usize, n_stack: usize, k_whir: usize) -> SystemParams {
    test_system_params_zero_pow(l_skip, n_stack, k_whir)
}

pub fn recursion_aggregation_options(
    leaf_system_params: SystemParams,
    internal_system_params: SystemParams,
    root_system_params: SystemParams,
) -> AggregationOptions {
    AggregationOptions::new(leaf_system_params)
        .with_internal_system_params(internal_system_params)
        .with_root_system_params(root_system_params)
}

pub fn default_aggregation_options() -> AggregationOptions {
    let params = recursion_system_params(
        DEFAULT_RECURSION_L_SKIP,
        DEFAULT_RECURSION_N_STACK,
        DEFAULT_RECURSION_K_WHIR,
    );
    recursion_aggregation_options(params.clone(), params.clone(), params)
}

#[allow(clippy::type_complexity)]
pub struct Sdk<E, PCS, PB, PD, SC = (), VC = ()>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    pub device: Option<PD>,
    pub app_program: Option<Program>,
    pub platform: Option<Platform>,
    pub multi_prover: Option<MultiProver>,
    #[cfg(feature = "gpu")]
    pub multi_gpu_config: Option<MultiGpuConfig>,
    #[cfg(feature = "gpu")]
    prepared_multi_gpu: Option<PreparedMultiGpu>,

    pub zkvm_pk: Option<Arc<ZKVMProvingKey<E, PCS>>>,
    pub zkvm_vk: Option<ZKVMVerifyingKey<E, PCS>>,
    pub zkvm_prover: Option<ZKVMProver<E, PCS, PB, PD>>,
    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub preflight_aot_program: Option<Arc<ceno_emul::aot::AotProgram>>,
    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub fulltracer_aot_program: Option<Arc<ceno_emul::aot::AotProgram>>,

    aggregation_options: Option<AggregationOptions>,
    #[cfg(feature = "gpu")]
    recursion_assets_builder: Option<DefaultRecursionHostAssetsBuilder>,
    _phantom: PhantomData<(SC, VC)>,
}

impl<E, PCS, PB, PD, SC, VC> Sdk<E, PCS, PB, PD, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + 'static + Serialize,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    pub fn new() -> Self {
        Self {
            device: None,
            app_program: None,
            platform: None,
            multi_prover: None,
            #[cfg(feature = "gpu")]
            multi_gpu_config: None,
            #[cfg(feature = "gpu")]
            prepared_multi_gpu: None,
            zkvm_pk: None,
            zkvm_vk: None,
            zkvm_prover: None,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            preflight_aot_program: None,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            fulltracer_aot_program: None,
            aggregation_options: None,
            #[cfg(feature = "gpu")]
            recursion_assets_builder: None,
            _phantom: PhantomData,
        }
    }

    pub fn new_with_app_config(
        program: Program,
        platform: Platform,
        multi_prover: MultiProver,
    ) -> Self {
        Self {
            device: None,
            app_program: Some(program),
            platform: Some(platform),
            multi_prover: Some(multi_prover),
            #[cfg(feature = "gpu")]
            multi_gpu_config: None,
            #[cfg(feature = "gpu")]
            prepared_multi_gpu: None,
            zkvm_pk: None,
            zkvm_vk: None,
            zkvm_prover: None,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            preflight_aot_program: None,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            fulltracer_aot_program: None,
            aggregation_options: None,
            #[cfg(feature = "gpu")]
            recursion_assets_builder: None,
            _phantom: PhantomData,
        }
    }

    pub fn set_app_pk(&mut self, pk: ZKVMProvingKey<E, PCS>) {
        self.zkvm_pk = Some(Arc::new(pk));
    }

    pub fn set_app_vk(&mut self, vk: ZKVMVerifyingKey<E, PCS>) {
        self.zkvm_vk = Some(vk);
    }

    pub fn set_aggregation_options(&mut self, options: AggregationOptions) {
        #[cfg(feature = "gpu")]
        assert!(
            self.recursion_assets_builder.is_none(),
            "aggregation options cannot change after streaming recursion preparation"
        );
        self.aggregation_options = Some(options);
    }

    #[cfg(feature = "gpu")]
    pub fn set_multi_gpu_config(&mut self, config: MultiGpuConfig) {
        config
            .validate_shape()
            .expect("invalid multi-GPU configuration");
        self.multi_gpu_config = Some(config);
    }

    pub fn aggregation_options(&self) -> AggregationOptions {
        self.aggregation_options
            .clone()
            .unwrap_or_else(default_aggregation_options)
    }

    fn set_zkvm_prover(&mut self, device: PD) {
        let (pk, vk) = self
            .zkvm_pk
            .clone()
            .zip(self.zkvm_vk.clone())
            .unwrap_or_else(|| {
                tracing::debug!("empty app proving/verifying key detected; running key generation");
                let (Some(program), Some(platform), Some(multi_prover)) = (
                    self.app_program.as_ref(),
                    self.platform.as_ref(),
                    self.multi_prover.as_ref(),
                ) else {
                    panic!("empty app config")
                };
                let start = std::time::Instant::now();
                let ctx =
                    setup_program::<E>(program.clone(), platform.clone(), multi_prover.clone());
                tracing::debug!("setup_program done in {:?}", start.elapsed());

                let start = std::time::Instant::now();
                let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
                tracing::debug!("keygen done in {:?}", start.elapsed());
                (pk.into(), vk)
            });

        self.zkvm_vk = Some(vk.clone());
        self.zkvm_pk = Some(pk.clone());
        self.zkvm_prover = Some(ZKVMProver::new(pk, device));
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub fn prepare_preflight_aot(&mut self, hints: &CenoStdin, prepare_fulltracer: bool) {
        let Some(zkvm_prover) = self.zkvm_prover.as_ref() else {
            panic!("ZKVMProver is not initialized")
        };
        let init_full_mem = zkvm_prover.setup_init_mem(&Vec::from(hints));
        let ctx = zkvm_prover.pk.program_ctx.as_ref().unwrap();
        let raw_step_cell_extractor = Arc::clone(&ctx.system_config.config);
        let step_cell_extractor: Arc<dyn StepCellExtractor> = raw_step_cell_extractor;
        let preflight_aot_program = prepare_preflight_aot_program(
            ctx.program.clone(),
            &ctx.platform,
            &ctx.multi_prover,
            step_cell_extractor,
            &init_full_mem,
        );
        self.fulltracer_aot_program = prepare_fulltracer
            .then(|| prepare_fulltracer_aot_program(preflight_aot_program.as_ref()));
        self.preflight_aot_program = Some(preflight_aot_program);
    }

    #[cfg(not(feature = "gpu"))]
    pub fn generate_base_proof(
        &self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
        _shard_id: Option<usize>,
    ) -> Vec<ZKVMProof<E, PCS>> {
        if let Some(zkvm_prover) = self.zkvm_prover.as_ref() {
            let init_full_mem = zkvm_prover.setup_init_mem(&Vec::from(&hints));
            run_e2e_proof_with_precompiled_aot::<E, PCS, PB, PD>(
                zkvm_prover,
                &init_full_mem,
                public_io_digest,
                max_steps,
                false,
                _shard_id,
                #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
                self.preflight_aot_program.clone(),
                #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
                self.fulltracer_aot_program.clone(),
            )
        } else {
            panic!("ZKVMProver is not initialized")
        }
    }

    pub fn get_app_pk(&self) -> Arc<ZKVMProvingKey<E, PCS>> {
        self.zkvm_pk.clone().expect("zkvm pk is not set")
    }

    pub fn get_app_vk(&self) -> ZKVMVerifyingKey<E, PCS> {
        self.zkvm_vk.clone().expect("zkvm vk is not set")
    }

    pub fn create_zkvm_verifier(&self) -> ZKVMVerifier<E, PCS> {
        let Some(app_vk) = self.zkvm_vk.clone() else {
            panic!("empty zkvm vk");
        };
        ZKVMVerifier::new(app_vk)
    }
}

impl<PB, PD, SC, VC> Sdk<RecursionField, RecursionPcs, PB, PD, SC, VC>
where
    PB: ProverBackend<E = RecursionField, Pcs = RecursionPcs> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    pub fn init_agg_prover(&self) -> Result<CenoRecursionV2Prover> {
        let app_vk = self
            .zkvm_vk
            .clone()
            .context("zkvm_vk is not set; call set_app_vk or init_base_prover first")?;
        #[cfg(not(feature = "gpu"))]
        let recursion_backend = "cpu";
        #[cfg(feature = "gpu")]
        let recursion_backend = "gpu";
        tracing::info!(
            recursion_backend,
            leaf = recursion_backend,
            internal = recursion_backend,
            root = recursion_backend,
            "ceno recursion backend summary"
        );
        let app_vk = Arc::new(app_vk);
        warm_child_vk_digest_cache(&app_vk);
        Ok(CenoRecursionV2Prover::new(
            app_vk,
            self.aggregation_options(),
        ))
    }

    pub fn init_agg_vk(&self) -> Result<Arc<CenoRecursionV2LeafVk>> {
        Ok(self.init_agg_prover()?.leaf_vk())
    }

    pub fn compress_to_root_proof(
        &self,
        base_proofs: Vec<RecursionProof>,
    ) -> Result<CenoRecursionV2RootProof> {
        let agg_prover = self.init_agg_prover()?;
        agg_prover
            .prove(&base_proofs)
            .map_err(|err| anyhow::anyhow!("{err}"))
    }
}

impl<E, PCS, PB, PD, SC, VC> Default for Sdk<E, PCS, PB, PD, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "gpu"))]
pub type CenoSDK<E, PCS, SC = (), VC = ()> =
    Sdk<E, PCS, CpuBackend<E, PCS>, CpuProver<CpuBackend<E, PCS>>, SC, VC>;

#[cfg(not(feature = "gpu"))]
impl<E, PCS, SC, VC> CenoSDK<E, PCS, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
{
    pub fn init_base_prover(&mut self, max_num_variables: usize, level: SecurityLevel) {
        let backend = create_backend(max_num_variables, level);
        let device = create_prover(backend);

        self.set_zkvm_prover(device);
    }
}

#[cfg(feature = "gpu")]
pub type CenoSDK<E, PCS, SC = (), VC = ()> =
    Sdk<E, PCS, GpuBackend<E, PCS>, GpuProver<GpuBackend<E, PCS>>, SC, VC>;

#[cfg(feature = "gpu")]
impl<E, PCS, SC, VC> CenoSDK<E, PCS, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PCS::ProverParam: Send + Sync,
    PCS::VerifierParam: Send + Sync,
    PCS::Commitment: Send + Sync,
    PCS::CommitmentWithWitness: Send + Sync,
    PCS::Proof: Send,
{
    pub fn init_base_prover(&mut self, max_num_variables: usize, level: SecurityLevel) {
        let backend = create_backend(max_num_variables, level);
        let config = self
            .multi_gpu_config
            .clone()
            .unwrap_or_else(|| MultiGpuConfig::new(vec![0]).unwrap());
        self.multi_gpu_config = Some(config.clone());
        let requested_max_cells = self
            .multi_prover
            .as_ref()
            .map_or(u64::MAX, |prover| prover.max_cell_per_shard);
        let prepared = config
            .prepare(requested_max_cells)
            .expect("multi-GPU device validation failed");
        if let Some(multi_prover) = self.multi_prover.as_mut() {
            multi_prover.max_cell_per_shard = prepared.max_cell_per_shard;
        }
        let device = GpuProver::new(backend, prepared.workers[0].hal.clone());

        self.set_zkvm_prover(device);
        self.prepared_multi_gpu = Some(prepared);
    }

    pub fn generate_multi_gpu_base_proof(
        &mut self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
        shard_id: Option<usize>,
    ) -> Vec<ZKVMProof<E, PCS>> {
        self.generate_multi_gpu_base_proof_with_sink(
            hints,
            public_io_digest,
            max_steps,
            shard_id,
            None,
        )
        .unwrap_or_else(|error| panic!("multi-GPU base proving failed: {error}"))
    }

    fn generate_multi_gpu_base_proof_with_sink(
        &mut self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
        shard_id: Option<usize>,
        event_sink: Option<Arc<dyn BaseProvingEventSink<E, PCS>>>,
    ) -> Result<Vec<ZKVMProof<E, PCS>>> {
        let config = self
            .multi_gpu_config
            .as_ref()
            .context("multi-GPU configuration was not initialized")?;
        let prepared = self
            .prepared_multi_gpu
            .as_ref()
            .context("multi-GPU devices were not prepared")?;
        let prover = self
            .zkvm_prover
            .as_ref()
            .context("ZKVMProver is not initialized")?;
        let init_mem_started = std::time::Instant::now();
        let init_full_mem = prover.setup_init_mem(&Vec::from(&hints));
        tracing::info!(
            target: "ceno_multi_gpu",
            elapsed_ms = init_mem_started.elapsed().as_millis(),
            phase = "sdk_init_memory",
            "multi-GPU base setup event"
        );
        let prover = self
            .zkvm_prover
            .take()
            .context("ZKVMProver is not initialized")?;
        run_e2e_multi_gpu_proof_with_precompiled_aot_and_sink(
            prover,
            prepared,
            config,
            &init_full_mem,
            public_io_digest,
            max_steps,
            shard_id,
            event_sink,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            self.preflight_aot_program.clone(),
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            self.fulltracer_aot_program.clone(),
        )
        .map_err(anyhow::Error::msg)
    }
}

#[cfg(feature = "gpu")]
impl<SC, VC> CenoSDK<RecursionField, RecursionPcs, SC, VC> {
    pub fn prepare_streaming_recursion(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.recursion_assets_builder.is_none(),
            "streaming recursion host assets were already prepared"
        );
        let prover = self
            .zkvm_prover
            .as_ref()
            .context("ZKVMProver is not initialized")?;
        let app_vk = Arc::new(
            prover
                .cached_verifier()
                .context("initial GPU prover has no cached verifier")?
                .vk
                .clone(),
        );
        let app_vk_digest = prover.vk_digest();
        // This is the earliest exact-VK point and intentionally precedes AOT/base replay. The
        // later shard-aware bind is cheap and occurs only after preflight reveals shard count.
        self.recursion_assets_builder = Some(
            RecursionHostAssetsBuilder::spawn(app_vk, app_vk_digest, self.aggregation_options())
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        );
        tracing::info!(
            target: "ceno_multi_gpu",
            phase = "recursion_host_assets_prebuild_started",
            "recursion host-asset template prebuild started"
        );
        Ok(())
    }

    pub fn generate_streaming_recursion_proof(
        &mut self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
    ) -> Result<StreamingRecursionOutput> {
        let total_started = Instant::now();
        let options = self.aggregation_options();
        let assets_builder = match self.recursion_assets_builder.take() {
            Some(builder) => builder,
            None => {
                let prover = self
                    .zkvm_prover
                    .as_ref()
                    .context("ZKVMProver is not initialized")?;
                let app_vk = Arc::new(
                    prover
                        .cached_verifier()
                        .context("initial GPU prover has no cached verifier")?
                        .vk
                        .clone(),
                );
                let app_vk_digest = prover.vk_digest();
                RecursionHostAssetsBuilder::spawn(app_vk, app_vk_digest, options.clone())
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
            }
        };
        let recursion = Arc::new(StreamingRecursionOrchestrator::with_assets_builder(
            options,
            assets_builder,
        ));
        let event_sink = recursion.clone() as Arc<dyn BaseProvingEventSink<_, _>>;
        let base_started = Instant::now();
        let base_proofs = self.generate_multi_gpu_base_proof_with_sink(
            hints,
            public_io_digest,
            max_steps,
            None,
            Some(event_sink),
        )?;
        let base_proving = base_started.elapsed();

        // The base call above owns the sole canonical full-trace verifier. Only its
        // successful return opens the root-publication gate.
        recursion.mark_base_verified();
        let GpuRecursionBatchOutput {
            root_output,
            worker_metrics,
            root_verification_time,
        } = recursion.finish().map_err(anyhow::Error::msg)?;
        let recursion_streaming = recursion.started.elapsed();

        Ok(StreamingRecursionOutput {
            base_proofs,
            root_output,
            worker_metrics,
            timings: StreamingRecursionTimings {
                base_proving,
                recursion_streaming,
                root_verification: root_verification_time,
                total: total_started.elapsed(),
            },
        })
    }
}

#[cfg(all(test, feature = "gpu"))]
mod streaming_recursion_tests {
    use ceno_recursion_v2::continuation::prover::{RecursionNodeKind, RecursionPlan};

    use super::{DEFAULT_INTERNAL_FANIN, DEFAULT_LEAF_FANIN, RecursionOrchestrationState};

    #[derive(Debug, Default)]
    struct FakeSession {
        events: Vec<&'static str>,
        cancel_count: usize,
    }

    #[test]
    fn fake_sink_routes_events_and_enforces_root_gate() {
        let mut state = RecursionOrchestrationState::<FakeSession>::new();
        assert!(state.accept_proof(|_| Ok(())).is_err());
        assert!(state.release_device(|_| Ok(())).is_err());

        state.start(FakeSession::default()).unwrap();
        state
            .accept_proof(|session| {
                session.events.push("proof_ready");
                Ok(())
            })
            .unwrap();
        state
            .release_device(|session| {
                session.events.push("device_released");
                Ok(())
            })
            .unwrap();
        assert!(state.take_verified_session().is_err());
        state.mark_base_verified();
        let session = state.take_verified_session().unwrap();
        assert_eq!(session.events, vec!["proof_ready", "device_released"]);
        assert_eq!(state.proof_count, 1);
        assert_eq!(state.released_devices, 1);
    }

    #[test]
    fn fake_sink_preserves_first_failure_and_cancels_once() {
        let mut state = RecursionOrchestrationState::new();
        state.start(FakeSession::default()).unwrap();
        state.fail("first", |session| session.cancel_count += 1);
        state.fail("second", |session| session.cancel_count += 1);
        assert_eq!(state.first_error.as_deref(), Some("first"));
        assert_eq!(state.session.as_ref().unwrap().cancel_count, 1);
        assert_eq!(state.take_verified_session().unwrap_err(), "first");
    }

    #[test]
    fn streaming_plan_uses_public_default_fanins() {
        let plan = RecursionPlan::new(11, DEFAULT_LEAF_FANIN, DEFAULT_INTERNAL_FANIN).unwrap();
        let count = |kind| plan.nodes.iter().filter(|node| node.kind == kind).count();

        assert_eq!(count(RecursionNodeKind::Leaf), 3);
        assert_eq!(count(RecursionNodeKind::LeafBridge), 1);
        assert_eq!(count(RecursionNodeKind::Recursive { level: 0 }), 1);
        assert_eq!(count(RecursionNodeKind::Root), 1);
        assert_eq!(plan.nodes.len(), 6);
    }
}

pub type RecursionCenoSDK<SC = (), VC = ()> = CenoSDK<RecursionField, RecursionPcs, SC, VC>;
