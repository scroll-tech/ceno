/// Most of the codes in this file are copied from the OpenVM project.
/// And we made a few modifications to fit in our continuation scheme.
/// https://github.com/openvm-org/openvm/blob/main/crates/continuations/src/verifier/common/non_leaf.rs
use std::{array, borrow::Borrow};

use ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE;
use openvm_circuit::arch::PUBLIC_VALUES_AIR_ID;
use openvm_instructions::program::Program;
use openvm_native_compiler::{
    conversion::CompilerOptions,
    ir::{Array, Builder, Config, DIGEST_SIZE, Felt, RVar, Usize},
    prelude::*,
};
use openvm_native_recursion::{
    challenger::duplex::DuplexChallengerVariable, fri::TwoAdicFriPcsVariable, stark::StarkVerifier,
    types::MultiStarkVerificationAdvice, utils::const_fri_config, vars::StarkProofVariable,
};
use openvm_stark_backend::keygen::types::MultiStarkVerifyingKey;
use openvm_stark_sdk::{
    config::{FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Config},
    openvm_stark_backend::p3_field::PrimeField32,
};
use p3::field::FieldAlgebra;

use crate::{
    aggregation::{
        InternalVmVerifierInput,
        types::{InternalVmVerifierExtraPvs, InternalVmVerifierPvs, VmVerifierPvs},
    }, arithmetics::_print_ext_arr, zkvm_verifier::{
        binding::{SepticExtensionVariable, SepticPointVariable},
        verifier::add_septic_points_in_place,
    }
};
use openvm_continuations::verifier::{
    common::{
        assert_or_assign_connector_pvs, assert_required_air_for_agg_vm_present,
        assert_single_segment_vm_exit_successfully, get_program_commit,
    },
    internal::vars::InternalVmVerifierInputVariable,
};
use openvm_native_recursion::hints::Hintable;

use openvm_continuations::{C, F};
use openvm_native_recursion::types::new_from_inner_multi_vk;

pub(crate) fn assign_array_to_slice<C: Config>(
    builder: &mut Builder<C>,
    dst_slice: &[Felt<C::F>],
    src: &Array<C, Felt<C::F>>,
    src_offset: usize,
) {
    for (i, dst) in dst_slice.iter().enumerate() {
        let pv = builder.get(src, i + src_offset);
        builder.assign(dst, pv);
    }
}

/// Returns 1 if lhs == rhs, 0 otherwise.
pub(crate) fn eq_felt_slice<C: Config, const N: usize>(
    builder: &mut Builder<C>,
    lhs: &[Felt<C::F>; N],
    rhs: &[Felt<C::F>; N],
) -> Var<C::N> {
    let sub_res: [Felt<C::F>; N] = array::from_fn(|i| builder.eval(lhs[i] - rhs[i]));
    let var_res = sub_res.map(|f| builder.cast_felt_to_var(f));
    let ret: Var<C::N> = builder.eval(C::N::ONE);
    var_res.into_iter().for_each(|v| {
        builder
            .if_ne(v, C::N::ZERO)
            .then(|builder| builder.assign(&ret, C::N::ZERO))
    });
    ret
}

pub struct NonLeafVerifierVariables<C: Config> {
    pub internal_program_commit: [Felt<C::F>; DIGEST_SIZE],
    pub leaf_pcs: TwoAdicFriPcsVariable<C>,
    pub leaf_advice: MultiStarkVerificationAdvice<C>,
    pub internal_pcs: TwoAdicFriPcsVariable<C>,
    pub internal_advice: MultiStarkVerificationAdvice<C>,
}

impl<C: Config> NonLeafVerifierVariables<C> {
    /// Verify proofs of internal verifier or leaf verifier.
    /// Returns aggregated VmVerifierPvs and leaf verifier commitment of these proofs.
    #[allow(clippy::type_complexity)]
    pub fn verify_internal_or_leaf_verifier_proofs(
        &self,
        builder: &mut Builder<C>,
        proofs: &Array<C, StarkProofVariable<C>>,
    ) -> (VmVerifierPvs<Felt<C::F>>, [Felt<C::F>; DIGEST_SIZE])
    where
        C::F: PrimeField32,
    {
        // At least 1 proof should be provided.
        builder.assert_nonzero(&proofs.len());
        // TODO: use our own variant of VmVerifierPvs (defined in type.rs)
        let pvs = VmVerifierPvs::<Felt<C::F>>::uninit(builder);
        let leaf_verifier_commit = array::from_fn(|_| builder.uninit());

        let ec_sum = SepticPointVariable {
            x: SepticExtensionVariable {
                vs: builder.dyn_array(7),
            },
            y: SepticExtensionVariable {
                vs: builder.dyn_array(7),
            },
            is_infinity: Usize::uninit(builder),
        };

        builder.range(0, proofs.len()).for_each(|i_vec, builder| {
            let i = i_vec[0];
            let proof = builder.get(proofs, i);
            assert_required_air_for_agg_vm_present(builder, &proof);
            let proof_vm_pvs = self.verify_internal_or_leaf_verifier_proof(builder, &proof);

            assert_single_segment_vm_exit_successfully(builder, &proof);
            builder.if_eq(i, RVar::zero()).then_or_else(
                |builder| {
                    for i in 0..SEPTIC_EXTENSION_DEGREE {
                        let x = Ext::uninit(builder);
                        builder.assign(&x, proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.x[i]);
                        let y = Ext::uninit(builder);
                        builder.assign(&y, proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.y[i]);

                        builder.set(&ec_sum.x.vs, i, x);
                        builder.set(&ec_sum.y.vs, i, y);
                    }
                    let inf = Usize::Var(builder.cast_felt_to_var(
                        proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.is_infinity,
                    ));
                    builder.assign(&ec_sum.is_infinity, inf);

                    builder.assign(
                        &leaf_verifier_commit,
                        proof_vm_pvs.extra_pvs.leaf_verifier_commit,
                    );


                    // _debug
                    builder.print_debug(101);
                    _print_ext_arr(builder, &ec_sum.x.vs);
                    _print_ext_arr(builder, &ec_sum.y.vs);

                },
                |builder| {
                    let right = SepticPointVariable {
                        x: SepticExtensionVariable {
                            vs: builder.dyn_array(7),
                        },
                        y: SepticExtensionVariable {
                            vs: builder.dyn_array(7),
                        },
                        is_infinity: Usize::uninit(builder),
                    };

                    for i in 0..SEPTIC_EXTENSION_DEGREE {
                        let x = Ext::uninit(builder);
                        builder.assign(&x, proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.x[i]);
                        let y = Ext::uninit(builder);
                        builder.assign(&y, proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.y[i]);

                        builder.set(&right.x.vs, i, x);
                        builder.set(&right.y.vs, i, y);
                    }
                    let inf = Usize::Var(builder.cast_felt_to_var(
                        proof_vm_pvs.vm_verifier_pvs.shard_ram_connector.is_infinity,
                    ));
                    builder.assign(&right.is_infinity, inf);

                    // _debug
                    builder.print_debug(102);
                    _print_ext_arr(builder, &right.x.vs);
                    _print_ext_arr(builder, &right.y.vs);


                    add_septic_points_in_place(builder, &ec_sum, &right);

                    // _debug
                    builder.print_debug(103);
                    _print_ext_arr(builder, &ec_sum.x.vs);
                    _print_ext_arr(builder, &ec_sum.y.vs);


                    builder.assert_eq::<[_; DIGEST_SIZE]>(
                        leaf_verifier_commit,
                        proof_vm_pvs.extra_pvs.leaf_verifier_commit,
                    );
                },
            );

            assert_or_assign_connector_pvs(
                builder,
                &pvs.connector,
                i,
                &proof_vm_pvs.vm_verifier_pvs.connector,
            );

            for i in 0..SEPTIC_EXTENSION_DEGREE {
                let x_ext = builder.get(&ec_sum.x.vs, i);
                let y_ext = builder.get(&ec_sum.y.vs, i);
                let x_fs = builder.ext2felt(x_ext);
                let y_fs = builder.ext2felt(y_ext);
                let x = builder.get(&x_fs, 0);
                let y = builder.get(&y_fs, 0);

                builder.assign(&pvs.shard_ram_connector.x[i], x);
                builder.assign(&pvs.shard_ram_connector.y[i], y);
            }
            builder
                .if_eq(ec_sum.is_infinity.clone(), Usize::from(1))
                .then_or_else(
                    |builder| {
                        builder.assign(&pvs.shard_ram_connector.is_infinity, C::F::ONE);
                    },
                    |builder| {
                        builder.assign(&pvs.shard_ram_connector.is_infinity, C::F::ZERO);
                    },
                );

            // This is only needed when `is_terminate` but branching here won't save much, so we
            // always assign it.
            builder.assign(
                &pvs.public_values_commit,
                proof_vm_pvs.vm_verifier_pvs.public_values_commit,
            );
        });
        (pvs, leaf_verifier_commit)
    }
    fn verify_internal_or_leaf_verifier_proof(
        &self,
        builder: &mut Builder<C>,
        proof: &StarkProofVariable<C>,
    ) -> InternalVmVerifierPvs<Felt<C::F>>
    where
        C::F: PrimeField32,
    {
        let flatten_proof_vm_pvs = InternalVmVerifierPvs::<Felt<C::F>>::uninit(builder).flatten();
        let proof_vm_pvs_arr = builder
            .get(&proof.per_air, PUBLIC_VALUES_AIR_ID)
            .public_values;

        let program_commit = get_program_commit(builder, proof);
        let is_self_program =
            eq_felt_slice(builder, &self.internal_program_commit, &program_commit);

        builder.if_eq(is_self_program, RVar::one()).then_or_else(
            |builder| {
                builder.cycle_tracker_start("verify stark");
                StarkVerifier::verify::<DuplexChallengerVariable<C>>(
                    builder,
                    &self.internal_pcs,
                    &self.internal_advice,
                    proof,
                );
                builder.cycle_tracker_end("verify stark");
                assign_array_to_slice(builder, &flatten_proof_vm_pvs, &proof_vm_pvs_arr, 0);
                let proof_vm_pvs: &InternalVmVerifierPvs<_> =
                    flatten_proof_vm_pvs.as_slice().borrow();
                // Handle recursive verification
                // For proofs, its program commitment should be committed.
                builder.assert_eq::<[_; DIGEST_SIZE]>(
                    proof_vm_pvs.extra_pvs.internal_program_commit,
                    program_commit,
                );
            },
            |builder| {
                builder.cycle_tracker_start("verify stark");
                StarkVerifier::verify::<DuplexChallengerVariable<C>>(
                    builder,
                    &self.leaf_pcs,
                    &self.leaf_advice,
                    proof,
                );
                builder.cycle_tracker_end("verify stark");
                // Leaf verifier doesn't have extra public values.
                assign_array_to_slice(
                    builder,
                    &flatten_proof_vm_pvs[..VmVerifierPvs::<u8>::width()],
                    &proof_vm_pvs_arr,
                    0,
                );
                let proof_vm_pvs: &InternalVmVerifierPvs<_> =
                    flatten_proof_vm_pvs.as_slice().borrow();
                builder.assign(&proof_vm_pvs.extra_pvs.leaf_verifier_commit, program_commit);
            },
        );
        *flatten_proof_vm_pvs.as_slice().borrow()
    }
}

/// Config to generate internal VM verifier program.
pub struct InternalVmVerifierConfig {
    pub leaf_fri_params: FriParameters,
    pub internal_fri_params: FriParameters,
    pub compiler_options: CompilerOptions,
}

impl InternalVmVerifierConfig {
    pub fn build_program(
        &self,
        leaf_vm_vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
        internal_vm_vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
    ) -> Program<F> {
        let leaf_advice = new_from_inner_multi_vk(leaf_vm_vk);
        let internal_advice = new_from_inner_multi_vk(internal_vm_vk);
        let mut builder = Builder::<C>::default();
        {
            builder.cycle_tracker_start("ReadProofsFromInput");
            let InternalVmVerifierInputVariable {
                self_program_commit,
                proofs,
            } = InternalVmVerifierInput::<BabyBearPoseidon2Config>::read(&mut builder);
            builder.cycle_tracker_end("ReadProofsFromInput");
            builder.cycle_tracker_start("InitializePcsConst");
            let leaf_pcs = TwoAdicFriPcsVariable {
                config: const_fri_config(&mut builder, &self.leaf_fri_params),
            };
            let internal_pcs = TwoAdicFriPcsVariable {
                config: const_fri_config(&mut builder, &self.internal_fri_params),
            };
            builder.cycle_tracker_end("InitializePcsConst");
            let non_leaf_verifier = NonLeafVerifierVariables {
                internal_program_commit: self_program_commit,
                leaf_pcs,
                leaf_advice,
                internal_pcs,
                internal_advice,
            };

            builder.cycle_tracker_start("VerifyProofs");
            let (vm_verifier_pvs, leaf_verifier_commit) =
                non_leaf_verifier.verify_internal_or_leaf_verifier_proofs(&mut builder, &proofs);
            builder.cycle_tracker_end("VerifyProofs");
            let pvs = InternalVmVerifierPvs {
                vm_verifier_pvs,
                extra_pvs: InternalVmVerifierExtraPvs {
                    internal_program_commit: self_program_commit,
                    leaf_verifier_commit,
                },
            };
            for pv in pvs.flatten() {
                builder.commit_public_value(pv);
            }

            builder.halt();
        }

        builder.compile_isa_with_options(self.compiler_options)
    }
}
