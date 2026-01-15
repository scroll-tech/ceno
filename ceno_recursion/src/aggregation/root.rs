use openvm_continuations::{C, F, SC};
use openvm_instructions::program::Program;
use openvm_native_compiler::{
    conversion::CompilerOptions,
    ir::{Array, Builder, Config, DIGEST_SIZE, Felt, Variable},
};
use openvm_native_recursion::{
    fri::TwoAdicFriPcsVariable, hints::Hintable, types::new_from_inner_multi_vk,
    utils::const_fri_config,
};
use openvm_stark_backend::keygen::types::MultiStarkVerifyingKey;
use openvm_stark_sdk::config::FriParameters;
use std::array;

use crate::aggregation::{SEPTIC_EXTENSION_DEGREE, internal::NonLeafVerifierVariables};
use openvm_native_compiler::prelude::*;
use openvm_native_recursion::vars::StarkProofVariable;
use openvm_stark_sdk::openvm_stark_backend::{
    config::{StarkGenericConfig, Val},
    proof::Proof,
};
use p3::field::FieldAlgebra;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CenoRootVmVerifierInput<SC: StarkGenericConfig> {
    /// The proofs of leaf verifier or internal verifier in the execution order.
    pub proofs: Vec<Proof<SC>>,
    /// Public values to expose directly
    pub public_values: Vec<Val<SC>>,
}

#[derive(DslVariable, Clone)]
pub struct CenoRootVmVerifierInputVariable<C: Config> {
    /// The proofs of leaf verifier or internal verifier in the execution order.
    pub proofs: Array<C, StarkProofVariable<C>>,
    /// Public values to expose
    pub public_values: Array<C, Felt<C::F>>,
}

impl Hintable<C> for CenoRootVmVerifierInput<SC> {
    type HintVariable = CenoRootVmVerifierInputVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let proofs = Vec::<Proof<SC>>::read(builder);
        let public_values = Vec::<Val<SC>>::read(builder);
        Self::HintVariable {
            proofs,
            public_values,
        }
    }

    fn write(&self) -> Vec<Vec<<C as Config>::N>> {
        let mut stream = self.proofs.write();
        stream.extend(self.public_values.write());
        stream
    }
}

pub struct CenoRootVmVerifierConfig {
    pub leaf_fri_params: FriParameters,
    pub internal_fri_params: FriParameters,
    pub num_user_public_values: usize,
    pub internal_vm_verifier_commit: [F; DIGEST_SIZE],
    pub compiler_options: CompilerOptions,
}

#[derive(Debug)]
pub struct CenoRootVmVerifierPvs<T> {
    pub init_pc: T,
    pub public_values: Vec<T>,
}
impl<F: Copy> CenoRootVmVerifierPvs<F> {
    pub fn flatten(self) -> Vec<F> {
        let mut ret = vec![];
        ret.extend(vec![self.init_pc]);
        ret.extend(self.public_values);
        ret
    }
    pub fn from_flatten(flatten: Vec<F>) -> Self {
        let init_pc = flatten[1];
        let public_values = flatten[1..].to_vec();

        Self {
            init_pc,
            public_values,
        }
    }
}

impl CenoRootVmVerifierConfig {
    pub fn build_program(
        &self,
        leaf_vm_vk: &MultiStarkVerifyingKey<SC>,
        internal_vm_vk: &MultiStarkVerifyingKey<SC>,
    ) -> Program<F> {
        let mut builder = Builder::<C>::default();

        builder.cycle_tracker_start("ReadProofsFromInput");
        let root_verifier_input = CenoRootVmVerifierInput::<SC>::read(&mut builder);
        builder.cycle_tracker_end("ReadProofsFromInput");

        let pvs = {
            let leaf_advice = new_from_inner_multi_vk(leaf_vm_vk);
            let internal_advice = new_from_inner_multi_vk(internal_vm_vk);
            let CenoRootVmVerifierInputVariable {
                proofs,
                public_values,
            } = root_verifier_input;

            builder.cycle_tracker_start("InitializePcsConst");
            let leaf_pcs = TwoAdicFriPcsVariable {
                config: const_fri_config(&mut builder, &self.leaf_fri_params),
            };
            let internal_pcs = TwoAdicFriPcsVariable {
                config: const_fri_config(&mut builder, &self.internal_fri_params),
            };
            builder.cycle_tracker_end("InitializePcsConst");
            let internal_program_commit =
                array::from_fn(|i| builder.eval(self.internal_vm_verifier_commit[i]));
            builder.cycle_tracker_start("VerifyProofs");
            let non_leaf_verifier = NonLeafVerifierVariables {
                internal_program_commit,
                leaf_pcs,
                leaf_advice,
                internal_pcs,
                internal_advice,
            };
            let (merged_pvs, _expected_leaf_commit) =
                non_leaf_verifier.verify_internal_or_leaf_verifier_proofs(&mut builder, &proofs);
            builder.cycle_tracker_end("VerifyProofs");

            // Assert final ec sum is zero
            let z: Felt<_> = builder.constant(<C as openvm_native_compiler::ir::Config>::F::ZERO);
            for i in 0..SEPTIC_EXTENSION_DEGREE {
                builder.assert_felt_eq(merged_pvs.shard_ram_connector.x[i], z);
                builder.assert_felt_eq(merged_pvs.shard_ram_connector.y[i], z);
            }
            let one: Felt<_> = builder.constant(<C as openvm_native_compiler::ir::Config>::F::ONE);
            builder.assert_felt_eq(merged_pvs.shard_ram_connector.is_infinity, one);

            /* _todo: Change merged pv operations, including checking final ec sum is infinity
            // App Program should terminate
            builder.assert_felt_eq(merged_pvs.connector.is_terminate, F::ONE);
            // App Program should exit successfully
            builder.assert_felt_eq(merged_pvs.connector.exit_code, F::ZERO);
            */

            builder.cycle_tracker_start("ExtractPublicValues");
            // builder.assert_usize_eq(public_values.len(), RVar::from(self.num_user_public_values));
            let public_values_vec: Vec<Felt<F>> = (0..(self.num_user_public_values - 1))    // The init_pc is read separately
                .map(|i| builder.get(&public_values, i))
                .collect();
            builder.cycle_tracker_end("ExtractPublicValues");

            CenoRootVmVerifierPvs {
                init_pc: merged_pvs.connector.initial_pc,
                public_values: public_values_vec,
            }
        };

        pvs.flatten()
            .into_iter()
            .for_each(|v| builder.commit_public_value(v));

        builder.halt();
        builder.compile_isa_with_options(self.compiler_options)
    }
}
