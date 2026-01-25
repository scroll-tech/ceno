use crate::{
    aggregation::{CenoRecursionProvingKeys, root::CenoRootVmVerifierPvs},
    zkvm_verifier::binding::F,
};
use anyhow::Result;
use openvm_continuations::{
    RootSC, static_verifier::StaticVerifierPvHandler, verifier::common::types::SpecialAirIds,
};
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::NativeConfig;
use openvm_native_compiler::ir::Builder;
use openvm_native_recursion::{
    config::outer::OuterConfig,
    halo2::{
        RawEvmProof,
        utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
        wrapper::{FallbackEvmVerifier, Halo2WrapperProvingKey},
    },
    vars::StarkProofVariable,
};
use openvm_sdk::{config::Halo2Config, keygen::Halo2ProvingKey, prover::Halo2Prover};
use openvm_stark_backend::proof::Proof;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use p3::field::FieldAlgebra;
use std::{sync::Arc, path::PathBuf};

fn params_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("/src/params")
}

pub const HALO2_VERIFIER_K: usize = 23;

pub struct StaticProverVerifier {
    config: Halo2Config,
    params_reader: CacheHalo2ParamsReader,
    static_pv_handler: StaticPvHandler,
    prover: Option<Halo2Prover>, // expensive to construct
    verifier: Option<FallbackEvmVerifier>,
}

pub struct StaticPvHandler {
    pub _init_pc: F,
}
impl StaticPvHandler {
    pub fn init() -> Self {
        Self { _init_pc: F::ZERO }
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

        pvs.public_values.len()
    }
}
impl Default for StaticProverVerifier {
    fn default() -> Self {
        Self::new()
    }
}
impl StaticProverVerifier {
    pub fn new() -> Self {
        let params_reader = CacheHalo2ParamsReader::new(params_dir());
        let halo2_config = Halo2Config {
            verifier_k: HALO2_VERIFIER_K,
            wrapper_k: None, // Auto-tuned
            profiling: false,
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
        ceno_recursion_key: &CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) {
        assert!(ceno_recursion_key.permuted_root_pk.is_some());

        let verifier = ceno_recursion_key
            .permuted_root_pk
            .as_ref()
            .unwrap()
            .keygen_static_verifier(
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
        ceno_recursion_key: &CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) -> RawEvmProof {
        if self.prover.is_none() {
            self.init(root_proof, ceno_recursion_key);
        }
        self.prover
            .as_ref()
            .unwrap()
            .prove_for_evm(root_proof)
            .try_into()
            .expect("generate halo2 proof")
    }

    pub fn verify_static(&mut self, proof: RawEvmProof) -> Result<()> {
        let static_verifier = self
            .verifier
            .as_ref()
            .expect("static verifier must be initiated");
        Halo2WrapperProvingKey::evm_verify(static_verifier, &proof).unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{aggregation::CenoAggregationProver, zkvm_verifier::binding::E};
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_continuations::RootSC;
    use openvm_stark_backend::proof::Proof;
    use openvm_stark_sdk::config::setup_tracing_with_log_level;
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
        agg_prover
            .verify_static(halo2_proof)
            .expect("halo2 proof exists");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_static_verifier() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(test_static_verifier_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
