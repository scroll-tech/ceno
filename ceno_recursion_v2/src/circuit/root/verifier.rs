use std::{array::from_fn, borrow::Borrow};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{DIGEST_SIZE, F};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use recursion_circuit::bus::{
    CachedCommitBus, CachedCommitBusMessage, PreHashBus, PreHashMessage, PublicValuesBus,
    PublicValuesBusMessage,
};
use stark_recursion_circuit_derive::AlignedBorrow;
use verify_stark::pvs::{CONSTRAINT_EVAL_CACHED_INDEX, VERIFIER_PVS_AIR_ID, VerifierBasePvs};

use crate::circuit::{
    inner::vm_pvs::VmPvs, recursive::prover::CENO_RECURSIVE_CONSTRAINT_EVAL_AIR_ID,
};

pub const CENO_VM_PVS_AIR_ID: usize = 1;

#[repr(C)]
#[derive(AlignedBorrow)]
pub struct CenoRootVerifierPvsCols<F> {
    pub child_verifier_pvs: VerifierBasePvs<F>,
    pub child_vm_pvs: VmPvs<F>,
}

#[repr(C)]
#[derive(AlignedBorrow, Clone, Copy)]
pub struct CenoRootPublicValues<F> {
    pub verifier_pvs: VerifierBasePvs<F>,
    pub vm_pvs: VmPvs<F>,
}

pub struct CenoRootVerifierPvsAir {
    pub public_values_bus: PublicValuesBus,
    pub cached_commit_bus: CachedCommitBus,
    pub pre_hash_bus: PreHashBus,
    pub child_vk_pre_hash: [F; DIGEST_SIZE],
}

impl<F> BaseAir<F> for CenoRootVerifierPvsAir {
    fn width(&self) -> usize {
        CenoRootVerifierPvsCols::<u8>::width()
    }
}

impl<F> BaseAirWithPublicValues<F> for CenoRootVerifierPvsAir {
    fn num_public_values(&self) -> usize {
        CenoRootPublicValues::<u8>::width()
    }
}

impl<F> PartitionedBaseAir<F> for CenoRootVerifierPvsAir {}

impl<AB: AirBuilder + InteractionBuilder + AirBuilderWithPublicValues> Air<AB>
    for CenoRootVerifierPvsAir
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("root pvs air has one row");
        let local: &CenoRootVerifierPvsCols<AB::Var> = (*local).borrow();

        // Root proofs must wrap the final internal-recursive proof, not a leaf or
        // internal-for-leaf proof.
        builder.assert_eq(local.child_verifier_pvs.internal_flag, AB::F::TWO);
        builder.assert_bool(local.child_verifier_pvs.recursion_flag - AB::F::ONE);

        // Ceno full-trace root proofs must end successfully.
        assert_array_eq(
            builder,
            local.child_vm_pvs.exit_code,
            [AB::F::ZERO, AB::F::ZERO],
        );
        builder.assert_zero(local.child_vm_pvs.shard_id);

        for (pv_idx, value) in local.child_verifier_pvs.as_slice().iter().enumerate() {
            self.public_values_bus.receive(
                builder,
                AB::F::ZERO,
                PublicValuesBusMessage {
                    air_idx: AB::Expr::from_usize(VERIFIER_PVS_AIR_ID),
                    pv_idx: AB::Expr::from_usize(pv_idx),
                    value: (*value).into(),
                },
                AB::F::ONE,
            );
        }

        for (pv_idx, value) in local.child_vm_pvs.as_slice().iter().enumerate() {
            self.public_values_bus.receive(
                builder,
                AB::F::ZERO,
                PublicValuesBusMessage {
                    air_idx: AB::Expr::from_usize(CENO_VM_PVS_AIR_ID),
                    pv_idx: AB::Expr::from_usize(pv_idx),
                    value: (*value).into(),
                },
                AB::F::ONE,
            );
        }

        let cached_commit = from_fn(|i| {
            local
                .child_verifier_pvs
                .internal_for_leaf_vk_commit
                .cached_commit[i]
                * (AB::Expr::TWO - local.child_verifier_pvs.recursion_flag)
                + local
                    .child_verifier_pvs
                    .internal_recursive_vk_commit
                    .cached_commit[i]
                    * (local.child_verifier_pvs.recursion_flag - AB::F::ONE)
        });
        self.cached_commit_bus.receive(
            builder,
            AB::F::ZERO,
            CachedCommitBusMessage {
                air_idx: AB::Expr::from_usize(CENO_RECURSIVE_CONSTRAINT_EVAL_AIR_ID),
                cached_idx: AB::Expr::from_usize(CONSTRAINT_EVAL_CACHED_INDEX),
                global_cached_idx: AB::Expr::ZERO,
                cached_commit,
            },
            AB::F::ONE,
        );

        let vk_pre_hash = self
            .child_vk_pre_hash
            .map(|value| AB::F::from_u32(value.as_canonical_u32()));
        self.pre_hash_bus.receive(
            builder,
            AB::F::ZERO,
            PreHashMessage { vk_pre_hash },
            AB::F::ONE,
        );

        let public_values = builder.public_values().to_vec();
        let public_values: &CenoRootPublicValues<_> = public_values.as_slice().borrow();

        for (local, public) in local
            .child_verifier_pvs
            .as_slice()
            .iter()
            .zip(public_values.verifier_pvs.as_slice())
        {
            builder.assert_eq(*local, *public);
        }

        for (local, public) in local
            .child_vm_pvs
            .as_slice()
            .iter()
            .zip(public_values.vm_pvs.as_slice())
        {
            builder.assert_eq(*local, *public);
        }
    }
}
