use ceno_emul::{Platform, Program};
use ceno_recursion::{
    aggregation::{
        CenoLeafVmVerifierConfig, INTERNAL_LOG_BLOWUP, LEAF_LOG_BLOWUP, ROOT_LOG_BLOWUP, SBOX_SIZE,
    },
    zkvm_verifier::binding::E,
};
use ceno_zkvm::{
    e2e::{MultiProver, setup_program},
    scheme::{hal::ProverDevice, prover::ZKVMProver},
    structs::{ZKVMProvingKey, ZKVMVerifyingKey},
};
use ff_ext::{BabyBearExt4, ExtensionField};
use gkr_iop::hal::ProverBackend;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use openvm_circuit::{
    arch::{MemoryConfig, SystemConfig, VirtualMachine},
    system::program::trace::VmCommittedExe,
};
use openvm_continuations::verifier::{
    common::types::VmVerifierPvs,
    internal::{InternalVmVerifierConfig, types::InternalVmVerifierPvs},
};
use openvm_native_circuit::NativeConfig;
use openvm_native_compiler::conversion::CompilerOptions;
use openvm_sdk::prover::vm::{local::VmLocalProver, types::VmProvingKey};
use openvm_stark_backend::config::StarkGenericConfig;
use openvm_stark_sdk::{
    config::{
        FriParameters,
        baby_bear_poseidon2::{BabyBearPoseidon2Config, BabyBearPoseidon2Engine},
    },
    engine::StarkFriEngine,
};
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
    pub agg_pk: Option<(
        Arc<VmProvingKey<SC, VC>>,
        Arc<VmCommittedExe<SC>>,
        Arc<VmProvingKey<SC, VC>>,
        Arc<VmCommittedExe<SC>>,
    )>,
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
    pub fn set_agg_pk(
        &mut self,
        agg_pk: (
            Arc<VmProvingKey<SC, VC>>,
            Arc<VmCommittedExe<SC>>,
            Arc<VmProvingKey<SC, VC>>,
            Arc<VmCommittedExe<SC>>,
        ),
    ) {
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
        VmLocalProver<BabyBearPoseidon2Config, NativeConfig, BabyBearPoseidon2Engine>,
        VmLocalProver<BabyBearPoseidon2Config, NativeConfig, BabyBearPoseidon2Engine>,
    ) {
        let Some(app_vk) = self.zkvm_vk.clone() else {
            panic!("please call `create_zkvm_prover` to keygen vk first");
        };

        let (ceno_leaf_agg_pk, leaf_committed_exe, internal_vm_pk, internal_committed_exe) =
            self.agg_pk.clone().unwrap_or_else(|| {
                tracing::debug!(
                    "empty agg proving/verifying key detected — running key generation..."
                );
                let [leaf_fri_params, internal_fri_params, _root_fri_params] =
                    [LEAF_LOG_BLOWUP, INTERNAL_LOG_BLOWUP, ROOT_LOG_BLOWUP]
                        .map(FriParameters::standard_with_100_bits_conjectured_security);

                let leaf_vm_config = NativeConfig {
                    system: SystemConfig::new(
                        SBOX_SIZE.min(leaf_fri_params.max_constraint_degree()),
                        MemoryConfig {
                            max_access_adapter_n: 16,
                            ..Default::default()
                        },
                        VmVerifierPvs::<u8>::width(),
                    )
                    .with_max_segment_len((1 << 24) - 100)
                    .with_profiling(),
                    native: Default::default(),
                };

                let leaf_committed_exe: Arc<VmCommittedExe<BabyBearPoseidon2Config>> = {
                    let leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
                    let leaf_program = CenoLeafVmVerifierConfig {
                        vk: app_vk,
                        compiler_options: CompilerOptions::default().with_cycle_tracker(),
                    }
                    .build_program();

                    Arc::new(VmCommittedExe::commit(
                        leaf_program.into(),
                        leaf_engine.config.pcs(),
                    ))
                };

                // let recursion_proving_keys = RecursionProvingKeys::keygen(leaf_fri_params, leaf_vm_config);
                let ceno_leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
                let ceno_leaf_vm_pk = Arc::new({
                    let vm = VirtualMachine::new(ceno_leaf_engine, leaf_vm_config.clone());
                    let vm_pk = vm.keygen();
                    assert!(vm_pk.max_constraint_degree <= leaf_fri_params.max_constraint_degree());
                    VmProvingKey {
                        fri_params: leaf_fri_params,
                        vm_config: leaf_vm_config,
                        vm_pk,
                    }
                });

                // Internal engine and config
                let internal_engine = BabyBearPoseidon2Engine::new(internal_fri_params);
                let internal_vm_config = NativeConfig {
                    system: SystemConfig::new(
                        SBOX_SIZE.min(internal_fri_params.max_constraint_degree()),
                        MemoryConfig {
                            max_access_adapter_n: 8,
                            ..Default::default()
                        },
                        InternalVmVerifierPvs::<u8>::width(),
                    )
                    .with_max_segment_len((1 << 24) - 100),
                    native: Default::default(),
                };

                // Construct internal vm, pk and vk
                let internal_vm = VirtualMachine::new(internal_engine, internal_vm_config.clone());
                let internal_vm_pk = Arc::new({
                    let vm_pk = internal_vm.keygen();
                    assert!(
                        vm_pk.max_constraint_degree <= internal_fri_params.max_constraint_degree()
                    );
                    VmProvingKey {
                        fri_params: internal_fri_params,
                        vm_config: internal_vm_config,
                        vm_pk,
                    }
                });
                let internal_vm_vk = internal_vm_pk.vm_pk.get_vk();

                // Commit internal program
                let internal_program = InternalVmVerifierConfig {
                    leaf_fri_params,
                    internal_fri_params,
                    compiler_options: CompilerOptions::default(),
                }
                .build_program(&ceno_leaf_vm_pk.vm_pk.get_vk(), &internal_vm_vk);
                let internal_committed_exe: Arc<VmCommittedExe<BabyBearPoseidon2Config>> =
                    Arc::new(VmCommittedExe::commit(
                        internal_program.into(),
                        internal_vm.engine.config.pcs(),
                    ));

                (
                    ceno_leaf_vm_pk,
                    leaf_committed_exe,
                    internal_vm_pk,
                    internal_committed_exe,
                )
            });

        let leaf_prover = VmLocalProver::<_, NativeConfig, BabyBearPoseidon2Engine>::new(
            ceno_leaf_agg_pk.clone(),
            leaf_committed_exe.clone(),
        );

        let internal_prover = VmLocalProver::<_, NativeConfig, BabyBearPoseidon2Engine>::new(
            internal_vm_pk.clone(),
            internal_committed_exe.clone(),
        );

        // set to agg_pk
        self.agg_pk = Some((
            ceno_leaf_agg_pk,
            leaf_committed_exe,
            internal_vm_pk,
            internal_committed_exe,
        ));

        (leaf_prover, internal_prover)
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
