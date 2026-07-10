use std::{array::from_fn, borrow::Borrow};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use recursion_circuit::{
    bus::{
        CachedCommitBus, CachedCommitBusMessage, PreHashBus, PreHashMessage, PublicValuesBus,
        PublicValuesBusMessage,
    },
    utils::assert_zeros,
};
use stark_recursion_circuit_derive::AlignedBorrow;
use verify_stark::pvs::{
    CONSTRAINT_EVAL_CACHED_INDEX, VERIFIER_PVS_AIR_ID, VerifierBasePvs, VkCommit,
};

#[repr(C)]
#[derive(AlignedBorrow)]
pub struct CenoRecursiveVerifierPvsCols<F> {
    pub proof_idx: F,
    pub is_valid: F,
    pub is_last: F,
    pub child_pvs: VerifierBasePvs<F>,
}

pub struct CenoRecursiveVerifierPvsAir {
    pub public_values_bus: PublicValuesBus,
    pub cached_commit_bus: CachedCommitBus,
    pub pre_hash_bus: PreHashBus,
    pub child_vk_commit: VkCommit<openvm_stark_sdk::config::baby_bear_poseidon2::F>,
    pub child_constraint_eval_air_id: usize,
    pub bridge_child_cached_commit: bool,
}

impl<F> BaseAir<F> for CenoRecursiveVerifierPvsAir {
    fn width(&self) -> usize {
        CenoRecursiveVerifierPvsCols::<u8>::width()
    }
}

impl<F> BaseAirWithPublicValues<F> for CenoRecursiveVerifierPvsAir {
    fn num_public_values(&self) -> usize {
        VerifierBasePvs::<u8>::width()
    }
}

impl<F> PartitionedBaseAir<F> for CenoRecursiveVerifierPvsAir {}

impl<AB: AirBuilder + InteractionBuilder + AirBuilderWithPublicValues> Air<AB>
    for CenoRecursiveVerifierPvsAir
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &CenoRecursiveVerifierPvsCols<AB::Var> = (*local).borrow();
        let next: &CenoRecursiveVerifierPvsCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_valid);
        builder.when_first_row().assert_one(local.is_valid);
        builder
            .when_transition()
            .assert_bool(local.is_valid - next.is_valid);
        builder.assert_bool(local.is_last);
        builder.when(local.is_last).assert_one(local.is_valid);
        builder
            .when(local.is_valid * (AB::Expr::ONE - local.is_last.into()))
            .assert_one(next.is_valid);
        builder
            .when(local.is_last)
            .assert_zero(next.is_valid * next.proof_idx);
        builder
            .when_last_row()
            .when(local.is_valid)
            .assert_one(local.is_last);
        builder.when_first_row().assert_zero(local.proof_idx);
        builder
            .when_transition()
            .when(local.is_valid * next.is_valid)
            .assert_eq(local.proof_idx + AB::Expr::ONE, next.proof_idx);

        builder.assert_tern(local.child_pvs.internal_flag);
        builder
            .when(local.child_pvs.recursion_flag)
            .assert_eq(local.child_pvs.internal_flag, AB::F::TWO);

        let both_valid = local.is_valid * next.is_valid;
        let mut when_both_valid = builder.when(both_valid);
        when_both_valid.assert_eq(local.child_pvs.internal_flag, next.child_pvs.internal_flag);
        when_both_valid.assert_eq(
            local.child_pvs.recursion_flag,
            next.child_pvs.recursion_flag,
        );
        assert_vk_commit_eq(
            &mut when_both_valid,
            local.child_pvs.app_vk_commit,
            next.child_pvs.app_vk_commit,
        );
        assert_vk_commit_eq(
            &mut when_both_valid,
            local.child_pvs.leaf_vk_commit,
            next.child_pvs.leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut when_both_valid,
            local.child_pvs.internal_for_leaf_vk_commit,
            next.child_pvs.internal_for_leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut when_both_valid,
            local.child_pvs.internal_recursive_vk_commit,
            next.child_pvs.internal_recursive_vk_commit,
        );

        for (pv_idx, value) in local.child_pvs.as_slice().iter().enumerate() {
            self.public_values_bus.receive(
                builder,
                local.proof_idx,
                PublicValuesBusMessage {
                    air_idx: AB::Expr::from_usize(VERIFIER_PVS_AIR_ID),
                    pv_idx: AB::Expr::from_usize(pv_idx),
                    value: (*value).into(),
                },
                local.is_valid,
            );
        }

        let public_values = builder.public_values().to_vec();
        let public_pvs: &VerifierBasePvs<_> =
            public_values[0..VerifierBasePvs::<u8>::width()].borrow();
        builder.assert_tern(public_pvs.internal_flag);
        builder.assert_tern(public_pvs.recursion_flag);

        builder
            .when_first_row()
            .when_ne(local.child_pvs.internal_flag, AB::F::TWO)
            .assert_eq(
                public_pvs.internal_flag,
                local.child_pvs.internal_flag + AB::F::ONE,
            );
        builder
            .when_first_row()
            .when(local.child_pvs.internal_flag)
            .assert_eq(public_pvs.internal_flag, AB::F::TWO);

        builder
            .when_first_row()
            .when(local.child_pvs.internal_flag * (local.child_pvs.internal_flag - AB::F::TWO))
            .assert_one(public_pvs.recursion_flag);
        builder
            .when_first_row()
            .when(local.child_pvs.recursion_flag)
            .assert_eq(public_pvs.recursion_flag, AB::F::TWO);
        builder
            .when_first_row()
            .when(
                (local.child_pvs.internal_flag - AB::F::ONE)
                    * (local.child_pvs.internal_flag - AB::F::TWO),
            )
            .assert_zero(public_pvs.recursion_flag);

        assert_vk_commit_eq(
            &mut builder.when_first_row(),
            local.child_pvs.app_vk_commit,
            public_pvs.app_vk_commit,
        );
        assert_vk_commit_eq(
            &mut builder.when_first_row().when(local.child_pvs.internal_flag),
            local.child_pvs.leaf_vk_commit,
            public_pvs.leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut builder
                .when_first_row()
                .when(local.child_pvs.recursion_flag),
            local.child_pvs.internal_for_leaf_vk_commit,
            public_pvs.internal_for_leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut builder.when_first_row().when(
                local.child_pvs.recursion_flag * (local.child_pvs.recursion_flag - AB::F::ONE),
            ),
            local.child_pvs.internal_recursive_vk_commit,
            public_pvs.internal_recursive_vk_commit,
        );

        let child_commit = vk_commit_const::<AB>(self.child_vk_commit);
        assert_vk_commit_eq(
            &mut builder.when_first_row().when(
                (local.child_pvs.internal_flag - AB::F::ONE)
                    * (local.child_pvs.internal_flag - AB::F::TWO),
            ),
            child_commit,
            public_pvs.leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut builder
                .when_first_row()
                .when(local.child_pvs.internal_flag * (local.child_pvs.internal_flag - AB::F::TWO)),
            child_commit,
            public_pvs.internal_for_leaf_vk_commit,
        );
        assert_vk_commit_eq(
            &mut builder
                .when_first_row()
                .when(local.child_pvs.recursion_flag),
            child_commit,
            public_pvs.internal_recursive_vk_commit,
        );

        assert_vk_commit_unset(
            &mut builder.when_first_row().when(
                (local.child_pvs.internal_flag - AB::F::ONE)
                    * (local.child_pvs.internal_flag - AB::F::TWO),
            ),
            public_pvs.internal_for_leaf_vk_commit,
        );
        assert_vk_commit_unset(
            &mut builder
                .when_first_row()
                .when(AB::Expr::ONE - local.child_pvs.recursion_flag.into()),
            public_pvs.internal_recursive_vk_commit,
        );

        self.pre_hash_bus.receive(
            builder,
            local.proof_idx,
            PreHashMessage {
                vk_pre_hash: child_commit.vk_pre_hash,
            },
            local.is_valid,
        );

        let half = AB::F::TWO.inverse();
        let is_internal_flag_zero = (local.child_pvs.internal_flag - AB::F::ONE)
            * (local.child_pvs.internal_flag - AB::F::TWO)
            * half;
        let is_internal_flag_one =
            (AB::Expr::TWO - local.child_pvs.internal_flag) * local.child_pvs.internal_flag;
        let is_recursion_flag_one =
            (AB::Expr::TWO - local.child_pvs.recursion_flag) * local.child_pvs.recursion_flag;
        let is_recursion_flag_two =
            (local.child_pvs.recursion_flag - AB::F::ONE) * local.child_pvs.recursion_flag * half;
        let cached_commit = from_fn(|i| {
            is_internal_flag_zero.clone() * local.child_pvs.app_vk_commit.cached_commit[i]
                + is_internal_flag_one.clone() * local.child_pvs.leaf_vk_commit.cached_commit[i]
                + is_recursion_flag_one.clone()
                    * local.child_pvs.internal_for_leaf_vk_commit.cached_commit[i]
                + is_recursion_flag_two.clone()
                    * local.child_pvs.internal_recursive_vk_commit.cached_commit[i]
        });
        let cached_commit_msg = CachedCommitBusMessage {
            air_idx: AB::Expr::from_usize(self.child_constraint_eval_air_id),
            cached_idx: AB::Expr::from_usize(CONSTRAINT_EVAL_CACHED_INDEX),
            global_cached_idx: AB::Expr::ZERO,
            cached_commit,
        };

        if self.bridge_child_cached_commit {
            self.cached_commit_bus.send(
                builder,
                local.proof_idx,
                cached_commit_msg.clone(),
                local.is_valid,
            );
        }
        self.cached_commit_bus
            .receive(builder, local.proof_idx, cached_commit_msg, local.is_valid);
    }
}

fn vk_commit_const<AB: AirBuilder>(
    commit: VkCommit<openvm_stark_sdk::config::baby_bear_poseidon2::F>,
) -> VkCommit<AB::F> {
    VkCommit {
        cached_commit: commit
            .cached_commit
            .map(|value| AB::F::from_u32(value.as_canonical_u32())),
        vk_pre_hash: commit
            .vk_pre_hash
            .map(|value| AB::F::from_u32(value.as_canonical_u32())),
    }
}

pub fn assert_vk_commit_eq<AB, I1, I2>(builder: &mut AB, left: VkCommit<I1>, right: VkCommit<I2>)
where
    AB: AirBuilder,
    I1: Into<AB::Expr> + Copy,
    I2: Into<AB::Expr> + Copy,
{
    assert_array_eq(builder, left.cached_commit, right.cached_commit);
    assert_array_eq(builder, left.vk_pre_hash, right.vk_pre_hash);
}

fn assert_vk_commit_unset<AB, I>(builder: &mut AB, commit: VkCommit<I>)
where
    AB: AirBuilder,
    I: Into<AB::Expr> + Copy,
{
    assert_zeros(builder, commit.cached_commit);
    assert_zeros(builder, commit.vk_pre_hash);
}
