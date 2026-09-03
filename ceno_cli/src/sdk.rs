use std::{marker::PhantomData, sync::Arc};

use anyhow::{Context, Result};
#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
use ceno_emul::StepCellExtractor;
use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_recursion_v2::{
    continuation::prover::{AggProver, AggregationOptions, LeafVk, RootProof, SystemParams},
    system::{
        RecursionField, RecursionPcs, RecursionProof, utils::test_system_params_zero_pow,
        warm_child_vk_digest_cache,
    },
};
#[cfg(feature = "gpu")]
use ceno_zkvm::e2e::run_e2e_multi_gpu_proof_with_precompiled_aot;
#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
use ceno_zkvm::e2e::{prepare_fulltracer_aot_program, prepare_preflight_aot_program};
#[cfg(feature = "gpu")]
use ceno_zkvm::multi_gpu::{MultiGpuConfig, PreparedMultiGpu};
#[cfg(not(feature = "gpu"))]
use ceno_zkvm::scheme::create_prover;
use ceno_zkvm::{
    e2e::{MultiProver, run_e2e_proof_with_precompiled_aot, setup_program},
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

    pub fn generate_base_proof(
        &self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
        shard_id: Option<usize>,
    ) -> Vec<ZKVMProof<E, PCS>> {
        if let Some(zkvm_prover) = self.zkvm_prover.as_ref() {
            let init_full_mem = zkvm_prover.setup_init_mem(&Vec::from(&hints));
            run_e2e_proof_with_precompiled_aot::<E, PCS, PB, PD>(
                zkvm_prover,
                &init_full_mem,
                public_io_digest,
                max_steps,
                false,
                shard_id,
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
        &self,
        hints: CenoStdin,
        public_io_digest: [u32; 8],
        max_steps: usize,
        shard_id: Option<usize>,
    ) -> Vec<ZKVMProof<E, PCS>> {
        let config = self
            .multi_gpu_config
            .as_ref()
            .expect("multi-GPU configuration was not initialized");
        if shard_id.is_some() {
            return self.generate_base_proof(hints, public_io_digest, max_steps, shard_id);
        }
        let prepared = self
            .prepared_multi_gpu
            .as_ref()
            .expect("multi-GPU devices were not prepared");
        let prover = self
            .zkvm_prover
            .as_ref()
            .expect("ZKVMProver is not initialized");
        let init_full_mem = prover.setup_init_mem(&Vec::from(&hints));
        let proofs = run_e2e_multi_gpu_proof_with_precompiled_aot(
            prover.pk.clone(),
            prover.device().backend.clone(),
            prepared,
            config,
            &init_full_mem,
            public_io_digest,
            max_steps,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            self.preflight_aot_program.clone(),
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            self.fulltracer_aot_program.clone(),
        )
        .unwrap_or_else(|error| panic!("multi-GPU base proving failed: {error}"));
        let recursion_worker = prepared
            .workers
            .iter()
            .find(|worker| worker.info.logical_ordinal == config.recursion_device)
            .expect("recursion GPU was not prepared");
        gkr_iop::gpu::set_thread_cuda_hal(recursion_worker.hal.clone());
        tracing::info!(
            recursion_device = config.recursion_device,
            "bound Stage 1 recursion GPU after base workers"
        );
        proofs
    }
}

pub type RecursionCenoSDK<SC = (), VC = ()> = CenoSDK<RecursionField, RecursionPcs, SC, VC>;
