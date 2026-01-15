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
    verifier::{internal::types::InternalVmVerifierInput, root::types::RootVmVerifierInput, common::types::SpecialAirIds},
    static_verifier::StaticVerifierPvHandler
};
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig, NativeCpuBuilder};
use openvm_native_recursion::{halo2::utils::CacheHalo2ParamsReader, hints::Hintable, config::outer::OuterConfig, vars::StarkProofVariable};
use openvm_sdk::{
    SC, config::{DEFAULT_NUM_CHILDREN_INTERNAL, Halo2Config}, keygen::Halo2ProvingKey, prover::{EvmHalo2Prover, Halo2Prover, vm::{new_local_prover, types::VmProvingKey}}
};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::BabyBearPoseidon2Config,
};
use p3::field::FieldAlgebra;
use std::{fs::File, sync::Arc, time::Instant};
pub type RecPcs = Basefold<E, BasefoldRSParams>;
use crate::aggregation::{
    root::CenoRootVmVerifierPvs,
};
use openvm_continuations::RootSC;
use openvm_native_compiler::{
    ir::{Builder},
};
use openvm_stark_backend::proof::Proof;
pub const HALO2_VERIFIER_K: usize = 23;

pub struct StaticProverVerifier {
    config: Halo2Config,
    params_reader: CacheHalo2ParamsReader,
    static_pv_handler: StaticPvHandler,
    prover: Option<Halo2Prover>,    // expensive to construct
}

pub struct StaticPvHandler {
    pub _phantom: F,
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
            wrapper_k: None,    // Auto-tuned
            profiling: true,    // _debug: change to false in production
        };
        let static_pv_handler = StaticPvHandler {
            _phantom: F::ONE,
        };
        Self {
            config: halo2_config,
            params_reader,
            static_pv_handler,
            prover: None,
        }
    }
    pub fn gen_static_proof(
        &self,
        root_proof: &Proof<RootSC>,
        ceno_proving_key: &CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>
    ) {
        // let halo2_pk = Halo2ProvingKey::keygen(
        //     self.config,
        //     &self.params_reader,
        //     &self.static_pv_handler,
        //     agg_pk,
        //     dummy_internal_proof.clone(),
        // )?;
        if !self.prover.is_some() {
            let halo2_verifier_proving_key = {
                let mut witness: Vec<Vec<F>> = Vec::new();
                witness.extend(root_proof.write());

                let special_air_ids = AirIdPermutation::compute(&ceno_proving_key.root_air_heights).get_special_air_ids();
                let config = StaticVerifierConfig {
                    root_verifier_fri_params: self.vm_pk.fri_params,
                    special_air_ids,
                    root_verifier_program_commit: self.root_committed_exe.get_program_commit().into(),
                };

            };
        }

        // let special_air_ids = root_proof.get_air_ids().slice(0, 3);

        let verifier = agg_pk.root_verifier_pk.keygen_static_verifier(
            &self.params_reader.read_params(self.config.verifier_k),
            dummy_root_proof,
            self.pv_handler,
        );



        // pub fn keygen_static_verifier(
        //     &self,
        //     params: &Halo2Params,
        //     root_proof: Proof<RootSC>,
        //     pv_handler: &impl StaticVerifierPvHandler,
        // ) -> Halo2VerifierProvingKey {
        //     let mut witness = Witness::default();
        //     root_proof.write(&mut witness);
        //     let special_air_ids = self.air_id_permutation().get_special_air_ids();
        //     let config = StaticVerifierConfig {
        //         root_verifier_fri_params: self.vm_pk.fri_params,
        //         special_air_ids,
        //         root_verifier_program_commit: self.root_committed_exe.get_program_commit().into(),
        //     };
        //     let dsl_operations = config.build_static_verifier_operations(
        //         &self.vm_pk.vm_pk.get_vk(),
        //         &root_proof,
        //         pv_handler,
        //     );
        //     Halo2VerifierProvingKey {
        //         pinning: Halo2Prover::keygen(params, dsl_operations.clone(), witness),
        //         dsl_ops: dsl_operations,
        //     }
        // }





        let dummy_snark = verifier.generate_dummy_snark(self.params_reader);
        let wrapper = if let Some(wrapper_k) = self.config.wrapper_k {
            Halo2WrapperProvingKey::keygen(&self.params_reader.read_params(wrapper_k), dummy_snark)
        } else {
            Halo2WrapperProvingKey::keygen_auto_tune(self.params_reader, dummy_snark)
        };
        let halo2_pk = Halo2ProvingKey {
            verifier: Arc::new(verifier),
            wrapper: Arc::new(wrapper),
            profiling: self.config.profiling,
        };





        let prover = Halo2Prover::new(&self.params_reader, halo2_pk);
        self.prover = Some(prover);
    }
}
