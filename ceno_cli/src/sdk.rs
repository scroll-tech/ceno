use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_recursion::{
    aggregation::{CenoAggregationProver, CenoRecursionProvingKeys, CenoRecursionVerifierKeys},
    zkvm_verifier::binding::E,
};
use ceno_zkvm::{
    e2e::{MultiProver, run_e2e_proof, setup_program},
    scheme::{
        ZKVMProof, create_backend, create_prover,
        hal::ProverDevice,
        mock_prover::LkMultiplicityKey,
        prover::ZKVMProver,
        verifier::{RiscvMemStateConfig, ZKVMVerifier},
    },
    structs::{ZKVMProvingKey, ZKVMVerifyingKey},
};
use ff_ext::{BabyBearExt4, ExtensionField};
#[cfg(not(feature = "gpu"))]
use gkr_iop::cpu::{CpuBackend, CpuProver};
#[cfg(feature = "gpu")]
use gkr_iop::gpu::{GpuBackend, GpuProver};
use gkr_iop::hal::ProverBackend;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme, SecurityLevel};
use openvm_continuations::verifier::internal::types::VmStarkProof;
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig};
use openvm_sdk::prover::vm::new_local_prover;
use openvm_stark_backend::config::StarkGenericConfig;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
#[cfg(not(feature = "gpu"))]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;

use serde::Serialize;
use std::sync::Arc;

#[allow(clippy::type_complexity)]
pub struct Sdk<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB,
    PD,
    SC: StarkGenericConfig,
    VC,
> where
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    pub device: Option<PD>,
    pub app_program: Option<Program>,
    pub platform: Option<Platform>,
    pub multi_prover: Option<MultiProver>,

    // base(app) layer
    pub zkvm_pk: Option<Arc<ZKVMProvingKey<E, PCS>>>,
    pub zkvm_vk: Option<ZKVMVerifyingKey<E, PCS, RiscvMemStateConfig>>,
    pub zkvm_prover: Option<ZKVMProver<E, PCS, PB, PD>>,

    // aggregation
    pub agg_pk: Option<CenoRecursionProvingKeys<SC, VC>>,
}

impl<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + 'static + Serialize,
    PB,
    PD,
    SC: StarkGenericConfig,
    VC,
> Sdk<E, PCS, PB, PD, SC, VC>
where
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    pub fn new() -> Self {
        Self {
            device: None,
            app_program: None,
            platform: None,
            multi_prover: None,
            zkvm_pk: None,
            zkvm_vk: None,
            zkvm_prover: None,
            agg_pk: None,
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
            zkvm_pk: None,
            zkvm_vk: None,
            zkvm_prover: None,
            agg_pk: None,
        }
    }
    pub fn set_app_pk(&mut self, pk: ZKVMProvingKey<E, PCS>) {
        self.zkvm_pk = Some(Arc::new(pk));
    }

    // allow us to read the app vk from file and then set it
    pub fn set_app_vk(&mut self, vk: ZKVMVerifyingKey<E, PCS, RiscvMemStateConfig>) {
        self.zkvm_vk = Some(vk);
    }

    pub fn set_agg_pk(&mut self, agg_pk: CenoRecursionProvingKeys<SC, VC>) {
        self.agg_pk = Some(agg_pk);
    }

    fn set_zkvm_prover(&mut self, device: PD) {
        let (pk, vk) = self
            .zkvm_pk
            .clone()
            .zip(self.zkvm_vk.clone())
            .unwrap_or_else(|| {
                tracing::debug!(
                    "empty app proving/verifying key detected — running key generation..."
                );
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

                // Keygen
                let start = std::time::Instant::now();
                let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
                tracing::debug!("keygen done in {:?}", start.elapsed());
                (pk.into(), vk)
            });

        self.zkvm_vk = Some(vk.clone());
        self.zkvm_pk = Some(pk.clone());
        self.zkvm_prover = Some(ZKVMProver::new(pk, device));
    }

    pub fn generate_base_proof(
        &self,
        hints: CenoStdin,
        pub_io: CenoStdin,
        max_steps: usize,
        shard_id: Option<usize>,
    ) -> Vec<ZKVMProof<E, PCS>> {
        if let Some(zkvm_prover) = self.zkvm_prover.as_ref() {
            let init_full_mem = zkvm_prover.setup_init_mem(&Vec::from(&hints), &Vec::from(&pub_io));
            run_e2e_proof::<E, PCS, PB, PD>(zkvm_prover, &init_full_mem, max_steps, false, shard_id)
        } else {
            panic!("ZKVMProver is not initialized")
        }
    }

    pub fn get_app_pk(&self) -> Arc<ZKVMProvingKey<E, PCS>> {
        self.zkvm_pk.clone().expect("zkvm pk is not set")
    }

    pub fn get_app_vk(&self) -> ZKVMVerifyingKey<E, PCS, RiscvMemStateConfig> {
        self.zkvm_vk.clone().expect("zkvm vk is not set")
    }

    pub fn get_agg_pk(&self) -> CenoRecursionProvingKeys<SC, VC> {
        self.agg_pk.clone().expect("agg pk is not set")
    }

    pub fn get_agg_vk(&self) -> CenoRecursionVerifierKeys<SC> {
        self.agg_pk.as_ref().expect("agg pk is not set").get_vk()
    }

    pub fn create_zkvm_verifier(&self) -> ZKVMVerifier<E, PCS, RiscvMemStateConfig> {
        let Some(app_vk) = self.zkvm_vk.clone() else {
            panic!("empty zkvm vk");
        };
        ZKVMVerifier::new(app_vk)
    }
}

impl<PB, PD>
    Sdk<BabyBearExt4, Basefold<E, BasefoldRSParams>, PB, PD, BabyBearPoseidon2Config, NativeConfig>
where
    PB: ProverBackend<E = BabyBearExt4, Pcs = Basefold<E, BasefoldRSParams>> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    /// aggregating base proofs into a root STARK proof
    pub fn compress_to_root_proof(
        &mut self,
        base_proofs: Vec<ZKVMProof<BabyBearExt4, Basefold<E, BasefoldRSParams>>>,
    ) -> VmStarkProof<BabyBearPoseidon2Config> {
        let vb = NativeBuilder::default();

        // TODO: cache agg_prover
        let mut agg_prover = if let Some(agg_pk) = self.agg_pk.as_ref() {
            let leaf_prover = new_local_prover::<BabyBearPoseidon2Engine, NativeBuilder>(
                vb.clone(),
                &agg_pk.leaf_vm_pk,
                agg_pk.leaf_committed_exe.exe.clone(),
            )
            .expect("leaf prover");
            let internal_prover = new_local_prover::<BabyBearPoseidon2Engine, NativeBuilder>(
                vb.clone(),
                &agg_pk.internal_vm_pk,
                agg_pk.internal_committed_exe.exe.clone(),
            )
            .expect("internal prover");

            CenoAggregationProver::new(leaf_prover, internal_prover, agg_pk.clone())
        } else {
            let agg_prover = CenoAggregationProver::from_base_vk(self.zkvm_vk.clone().unwrap());
            self.agg_pk = Some(agg_prover.pk.clone());

            agg_prover
        };

        agg_prover.generate_root_proof(base_proofs)
    }

    pub fn init_agg_pk(
        &mut self,
    ) -> CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig> {
        assert!(self.zkvm_vk.is_some(), "zkvm_vk is not set");

        if self.agg_pk.is_none() {
            let agg_prover = CenoAggregationProver::from_base_vk(self.zkvm_vk.clone().unwrap());
            self.agg_pk = Some(agg_prover.pk.clone());
        }
        self.agg_pk.clone().unwrap()
    }

    pub fn get_agg_verifier(&self) -> CenoRecursionVerifierKeys<BabyBearPoseidon2Config> {
        let Some(agg_pk) = self.agg_pk.as_ref() else {
            panic!("empty agg_pk")
        };

        agg_pk.get_vk()
    }
}

impl<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB,
    PD,
    SC: StarkGenericConfig,
    VC,
> Default for Sdk<E, PCS, PB, PD, SC, VC>
where
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "gpu"))]
pub type CenoSDK<E, PCS, SC, VC> =
    Sdk<E, PCS, CpuBackend<E, PCS>, CpuProver<CpuBackend<E, PCS>>, SC, VC>;

#[cfg(not(feature = "gpu"))]
impl<E, PCS, SC, VC> CenoSDK<E, PCS, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    SC: StarkGenericConfig,
    VC: 'static,
{
    pub fn init_base_prover(&mut self, max_num_variables: usize, level: SecurityLevel) {
        let backend = create_backend(max_num_variables, level);
        let device = create_prover(backend);

        self.set_zkvm_prover(device);
    }
}

#[cfg(feature = "gpu")]
pub type CenoSDK<E, PCS, SC, VC> =
    Sdk<E, PCS, GpuBackend<E, PCS>, GpuProver<GpuBackend<E, PCS>>, SC, VC>;

#[cfg(feature = "gpu")]
impl<E, PCS, SC, VC> CenoSDK<E, PCS, SC, VC>
where
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    SC: StarkGenericConfig,
    VC: 'static,
{
    pub fn init_base_prover(&mut self, max_num_variables: usize, level: SecurityLevel) {
        let backend = create_backend(max_num_variables, level);
        let device = create_prover(backend);

        self.set_zkvm_prover(device);
    }
}
