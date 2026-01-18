use crate::{
    aggregation::{CenoRecursionProvingKeys, root::CenoRootVmVerifierConfig},
    zkvm_verifier::{
        binding::{E, F, ZKVMProofInput, ZKVMProofInputVariable},
        verifier::verify_zkvm_proof,
    },
};
use mpcs::{Basefold, BasefoldRSParams};

use crate::aggregation::internal::InternalVmVerifierConfig;
use openvm_continuations::{
    C,
    static_verifier::StaticVerifierPvHandler,
    verifier::{
        common::types::SpecialAirIds, internal::types::InternalVmVerifierInput,
        root::types::RootVmVerifierInput,
    },
};
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig, NativeCpuBuilder};
use openvm_native_recursion::{
    config::outer::OuterConfig,
    halo2::{
        RawEvmProof,
        utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
        wrapper::{FallbackEvmVerifier, Halo2WrapperProvingKey},
    },
    hints::Hintable,
    vars::StarkProofVariable,
    witness::Witnessable,
};
use openvm_sdk::{
    SC,
    config::{DEFAULT_NUM_CHILDREN_INTERNAL, Halo2Config},
    keygen::{
        Halo2ProvingKey, RootVerifierProvingKey, dummy::compute_root_proof_heights,
        perm::AirIdPermutation,
    },
    prover::{
        EvmHalo2Prover, Halo2Prover,
        vm::{new_local_prover, types::VmProvingKey},
    },
    types::EvmProof,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use p3::field::FieldAlgebra;
use std::{fs::File, sync::Arc, time::Instant};
pub type RecPcs = Basefold<E, BasefoldRSParams>;
use crate::aggregation::root::CenoRootVmVerifierPvs;
use openvm_continuations::RootSC;
use openvm_native_compiler::{ir::Builder, prelude::*};
use openvm_stark_backend::proof::Proof;

pub const HALO2_VERIFIER_K: usize = 23;

pub struct StaticProverVerifier {
    config: Halo2Config,
    params_reader: CacheHalo2ParamsReader,
    static_pv_handler: StaticPvHandler,
    prover: Option<Halo2Prover>, // expensive to construct
    verifier: Option<FallbackEvmVerifier>,
}

pub struct StaticPvHandler {
    pub init_pc: F,
}
impl StaticPvHandler {
    pub fn init() -> Self {
        Self { init_pc: F::ZERO }
    }
}

impl StaticVerifierPvHandler for StaticPvHandler {
    fn handle_public_values(
        &self,
        builder: &mut Builder<OuterConfig>,
        input: &StarkProofVariable<OuterConfig>,
        special_air_ids: &SpecialAirIds,
    ) -> usize {
        let pv_air = builder.get(&input.per_air, special_air_ids.public_values_air_id);
        let public_values: Vec<_> = pv_air
            .public_values
            .vec()
            .into_iter()
            .map(|x| builder.cast_felt_to_var(x))
            .collect();
        let pvs = CenoRootVmVerifierPvs::from_flatten(public_values);
        let num_public_values = pvs.public_values.len();

        num_public_values
    }
}

impl StaticProverVerifier {
    pub fn new() -> Self {
        let params_reader = CacheHalo2ParamsReader::new("../params/");
        let halo2_config = Halo2Config {
            verifier_k: HALO2_VERIFIER_K,
            wrapper_k: None, // Auto-tuned
            profiling: true, // _debug: change to false in production
        };
        let static_pv_handler = StaticPvHandler::init();
        Self {
            config: halo2_config,
            params_reader,
            static_pv_handler,
            prover: None,
            verifier: None,
        }
    }
    pub fn init(
        &mut self,
        root_proof: &Proof<RootSC>,
        root_air_heights: &Vec<u32>,
        ceno_recursion_key: &CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) {
        let root_verifier_proving_key = RootVerifierProvingKey {
            vm_pk: ceno_recursion_key.root_vm_pk.clone(),
            root_committed_exe: ceno_recursion_key.root_committed_exe.clone(),
            air_heights: root_air_heights.clone(),
        };

        let verifier = root_verifier_proving_key.keygen_static_verifier(
            &self.params_reader.read_params(self.config.verifier_k),
            root_proof.clone(),
            &self.static_pv_handler,
        );

        let dummy_snark = verifier.generate_dummy_snark(&self.params_reader);
        let wrapper = if let Some(wrapper_k) = self.config.wrapper_k {
            Halo2WrapperProvingKey::keygen(&self.params_reader.read_params(wrapper_k), dummy_snark)
        } else {
            Halo2WrapperProvingKey::keygen_auto_tune(&self.params_reader, dummy_snark)
        };

        let halo2_pk = Halo2ProvingKey {
            verifier: Arc::new(verifier),
            wrapper: Arc::new(wrapper),
            profiling: self.config.profiling,
        };

        // Update prover/verifier
        let wrapper_k = halo2_pk.wrapper.pinning.metadata.config_params.k;
        let params = self.params_reader.read_params(wrapper_k);
        let static_verifier = halo2_pk.wrapper.generate_fallback_evm_verifier(&params);
        let prover = Halo2Prover::new(&self.params_reader, halo2_pk);

        self.prover = Some(prover);
        self.verifier = Some(static_verifier);
    }

    pub fn prove_static(
        &mut self,
        root_proof: &Proof<RootSC>,
        root_proof_air_heights: &Vec<u32>,
        ceno_recursion_key: &CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) -> RawEvmProof {
        if self.prover.is_none() {
            self.init(root_proof, root_proof_air_heights, ceno_recursion_key);
        }
        self.prover
            .as_ref()
            .unwrap()
            .prove_for_evm(&root_proof)
            .try_into()
            .expect("generate halo2 proof")
    }

    pub fn verify_static(&mut self, proof: RawEvmProof) {
        Halo2WrapperProvingKey::evm_verify(&self.verifier, &proof).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregation::{
            CenoAggregationProver, CenoRecursionProvingKeys, statics::StaticProverVerifier,
        },
        zkvm_verifier::binding::E,
    };
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_continuations::{RootSC, SC};
    use openvm_native_circuit::NativeConfig;
    use openvm_stark_backend::proof::Proof;
    use openvm_stark_sdk::config::{
        baby_bear_poseidon2::BabyBearPoseidon2Config, setup_tracing_with_log_level,
    };
    use std::fs::File;

    pub fn test_static_verifier_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let vk_path = "./src/imported/vk.bin";
        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");
        let mut agg_prover = CenoAggregationProver::from_base_vk(vk);

        let root_proof_path = "./src/exports/root_proof.bin";
        let root_proof: Proof<RootSC> = bincode::deserialize_from(
            File::open(root_proof_path).expect("Failed to open proof file"),
        )
        .expect("Deserialize root proof");

        let halo2_proof = agg_prover.prove_static(&root_proof);
    }

    #[test]
    // #[ignore = "need to generate proof first"]
    pub fn test_static_verifier() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(test_static_verifier_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
