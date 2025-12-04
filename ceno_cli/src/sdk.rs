#![allow(dead_code)]
use ceno_emul::{Platform, Program};
use ceno_recursion::{
    aggregation::{CenoAggregationProver, CenoRecursionProvingKeys, CenoRecursionVerifierKeys},
    zkvm_verifier::binding::E,
};
use ceno_zkvm::{
    e2e::{MultiProver, setup_program},
    scheme::{hal::ProverDevice, prover::ZKVMProver, verifier::ZKVMVerifier},
    structs::{ZKVMProvingKey, ZKVMVerifyingKey},
};
use ff_ext::{BabyBearExt4, ExtensionField};
use gkr_iop::hal::ProverBackend;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use openvm_circuit::arch::VmInstance;
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig};
use openvm_sdk::prover::vm::new_local_prover;
use openvm_stark_backend::config::StarkGenericConfig;
#[cfg(not(feature = "gpu"))]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;

use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use std::{marker::PhantomData, sync::Arc};

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

    pub zkvm_pk: Option<Arc<ZKVMProvingKey<E, PCS>>>,
    pub zkvm_vk: Option<ZKVMVerifyingKey<E, PCS>>,

    // aggregation
    pub zkvm_agg: Option<Arc<ZKVMProvingKey<E, PCS>>>,
    pub agg_pk: Option<CenoRecursionProvingKeys<SC, VC>>,
    phantom: PhantomData<PB>,
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
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
            zkvm_agg: None,
            agg_pk: None,
            phantom: Default::default(),
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
            zkvm_agg: None,
            agg_pk: None,
            phantom: Default::default(),
        }
    }
    pub fn set_app_pk(&mut self, pk: ZKVMProvingKey<E, PCS>) {
        self.zkvm_pk = Some(Arc::new(pk));
    }

    pub fn set_app_vk(&mut self, vk: ZKVMVerifyingKey<E, PCS>) {
        self.zkvm_vk = Some(vk);
    }

    #[allow(clippy::type_complexity)]
    pub fn set_agg_pk(&mut self, agg_pk: CenoRecursionProvingKeys<SC, VC>) {
        self.agg_pk = Some(agg_pk);
    }

    pub fn create_zkvm_prover(&mut self, device: PD) -> ZKVMProver<E, PCS, PB, PD> {
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

        ZKVMProver::new(pk, device)
    }

    pub fn create_zkvm_verifier(&self) -> ZKVMVerifier<E, PCS> {
        let Some(app_vk) = self.zkvm_vk.clone() else {
            panic!("empty zkvm pk");
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
    // initialized agg prover
    pub fn create_agg_prover(
        &mut self,
    ) -> (
        VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
        VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
    ) {
        let vb = NativeBuilder::default();

        if let Some(agg_pk) = self.agg_pk.as_ref() {
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

            return (leaf_prover, internal_prover);
        }

        let agg_prover = CenoAggregationProver::new(vb, self.zkvm_vk.clone().unwrap());

        // set to agg_pk
        self.agg_pk = Some(agg_prover.pk.clone());

        (agg_prover.leaf_prover, agg_prover.internal_prover)
    }

    pub fn create_agg_verifier(&self) -> CenoRecursionVerifierKeys<BabyBearPoseidon2Config> {
        let Some(agg_pk) = self.agg_pk.as_ref() else {
            panic!("empty agg_pk")
        };

        agg_pk.get_vk()
    }
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
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
