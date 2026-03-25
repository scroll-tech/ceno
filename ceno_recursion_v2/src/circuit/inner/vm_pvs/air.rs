use std::borrow::Borrow;

use openvm_circuit::system::connector::DEFAULT_SUSPEND_EXIT_CODE;
use openvm_circuit_primitives::utils::{and, assert_array_eq, not};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use recursion_circuit::bus::{CachedCommitBus, PublicValuesBus};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::circuit::inner::{
    bus::{PvsAirConsistencyBus, PvsAirConsistencyMessage},
    vm_pvs::VmPvs,
};

#[repr(C)]
#[derive(AlignedBorrow)]
pub struct VmPvsCols<F> {
    pub proof_idx: F,
    pub is_valid: F,
    pub is_last: F,
    pub has_verifier_pvs: F,
    pub child_pvs: VmPvs<F>,
}

pub struct VmPvsAir {
    pub public_values_bus: PublicValuesBus,
    pub cached_commit_bus: CachedCommitBus,
    pub pvs_air_consistency_bus: PvsAirConsistencyBus,
    pub deferral_enabled: bool,
}

impl<F> BaseAir<F> for VmPvsAir {
    fn width(&self) -> usize {
        VmPvsCols::<u8>::width() + (self.deferral_enabled as usize)
    }
}
impl<F> BaseAirWithPublicValues<F> for VmPvsAir {
    fn num_public_values(&self) -> usize {
        VmPvs::<u8>::width()
    }
}
impl<F> PartitionedBaseAir<F> for VmPvsAir {}

impl<AB: AirBuilder + InteractionBuilder + AirBuilderWithPublicValues> Air<AB> for VmPvsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );

        let base_cols_width = VmPvsCols::<AB::Var>::width();
        let (base_local, def_local) = local.split_at(base_cols_width);
        let (base_next, next_local) = next.split_at(base_cols_width);

        let local: &VmPvsCols<AB::Var> = (*base_local).borrow();
        let next: &VmPvsCols<AB::Var> = (*base_next).borrow();

        // If deferrals are enabled, this AIR expects an additional deferral_flag column. It
        // can be either 0 or 2 here, and in the latter case there can only be one row.
        let (deferral_flag, has_vm_pvs) = if self.deferral_enabled {
            debug_assert_eq!(def_local.len(), 1);
            debug_assert_eq!(next_local.len(), 1);
            self.eval_deferrals(builder, local, def_local[0], next_local[0])
        } else {
            debug_assert_eq!(def_local.len(), 0);
            debug_assert_eq!(next_local.len(), 0);
            (AB::Expr::ZERO, AB::Expr::ONE)
        };

        // Basic constraints for non-public value columns.
        // constrain all valid rows are at the beginning
        builder.assert_bool(local.is_valid);
        builder
            .when_first_row()
            .assert_eq(local.is_valid, has_vm_pvs);
        builder
            .when_transition()
            .assert_bool(local.is_valid - next.is_valid);

        // constrain increasing proof_idx
        builder.when_first_row().assert_zero(local.proof_idx);
        builder
            .when_transition()
            .when(and(local.is_valid, next.is_valid))
            .assert_eq(local.proof_idx + AB::Expr::ONE, next.proof_idx);

        // constrain is_last, note proof_idx on the first row is 0
        builder.assert_bool(local.is_last);
        builder.when(local.is_last).assert_one(local.is_valid);
        builder
            .when(and(local.is_valid, not(local.is_last)))
            .assert_one(next.is_valid);
        builder
            .when(local.is_last)
            .assert_zero(next.is_valid * next.proof_idx);
        builder
            .when_last_row()
            .when(local.is_valid)
            .assert_one(local.is_last);

        // constrain has_verifier_pvs, which will be compared with the other pv AIRs
        builder.assert_bool(local.has_verifier_pvs);
        builder
            .when(local.has_verifier_pvs)
            .assert_one(local.is_valid);
        builder
            .when(and(local.is_valid, next.is_valid))
            .assert_eq(local.has_verifier_pvs, next.has_verifier_pvs);

        // We constrain segment adjacency so adjacent rows correspond to adjacent segments.
        // Non-final segments must suspend with DEFAULT_SUSPEND_EXIT_CODE.
        let suspend_exit_code_lo = AB::Expr::from_u32(DEFAULT_SUSPEND_EXIT_CODE & 0xffff);
        let suspend_exit_code_hi = AB::Expr::from_u32((DEFAULT_SUSPEND_EXIT_CODE >> 16) & 0xffff);
        builder
            .when(and(local.is_valid, not(local.is_last)))
            .assert_eq(local.child_pvs.exit_code[0], suspend_exit_code_lo);
        builder
            .when(and(local.is_valid, not(local.is_last)))
            .assert_eq(local.child_pvs.exit_code[1], suspend_exit_code_hi);

        // when local and next are valid, constrain increasing proof_idx and adjacency
        let mut when_both_valid = builder.when(and(local.is_valid, not(local.is_last)));
        when_both_valid.assert_eq(local.child_pvs.end_pc, next.child_pvs.init_pc);
        when_both_valid.assert_eq(local.child_pvs.end_cycle, next.child_pvs.init_cycle);

        // TODO(vm-pvs-mapping): public_values_bus.receive mappings are intentionally disabled
        // until the new VmPvs -> PublicValuesBus index mapping is finalized.
        // self.public_values_bus.receive(...);

        // At the leaf level, this AIR is responsible for receiving the cached trace commit
        // program_commit.
        // TODO
        // self.cached_commit_bus.receive(
        //     builder,
        //     local.proof_idx,
        //     CachedCommitBusMessage {
        //         air_idx: AB::Expr::from_usize(PROGRAM_AIR_ID),
        //         cached_idx: AB::Expr::from_usize(PROGRAM_CACHED_TRACE_INDEX),
        //         cached_commit: local.child_pvs.program_commit.map(Into::into),
        //     },
        //     local.is_valid * is_leaf,
        // );

        // We look up proof metadata from VerifierPvsAir here to ensure consistency on each row.
        self.pvs_air_consistency_bus.lookup_key(
            builder,
            local.proof_idx,
            PvsAirConsistencyMessage {
                deferral_flag,
                has_verifier_pvs: local.has_verifier_pvs.into(),
            },
            local.is_valid,
        );

        // Finally, constrain that this AIR's output public values are consistent with child_pvs.
        let &VmPvs::<_> {
            fixed_commit,
            fixed_no_omc_init_commit,
            exit_code,
            init_pc,
            init_cycle,
            end_pc,
            end_cycle,
            shard_id,
            heap_start_addr,
            heap_shard_len,
            hint_start_addr,
            hint_shard_len,
            public_io,
            shard_rw_sum,
        } = builder.public_values().borrow();

        // constrain first proof pvs
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.init_pc, init_pc);
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.init_cycle, init_cycle);

        // constrain last proof pvs
        builder
            .when(local.is_last)
            .assert_eq(local.child_pvs.end_pc, end_pc);
        builder
            .when(local.is_last)
            .assert_eq(local.child_pvs.end_cycle, end_cycle);
        assert_array_eq(
            &mut builder.when(local.is_last),
            local.child_pvs.exit_code,
            exit_code,
        );

        // constrain static per-proof public values
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.shard_id, shard_id);
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.heap_start_addr, heap_start_addr);
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.heap_shard_len, heap_shard_len);
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.hint_start_addr, hint_start_addr);
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.hint_shard_len, hint_shard_len);
        assert_array_eq(
            &mut builder.when(local.is_valid),
            local.child_pvs.public_io,
            public_io,
        );
        assert_array_eq(
            &mut builder.when(local.is_valid),
            local.child_pvs.shard_rw_sum,
            shard_rw_sum,
        );

        // constrain fixed commits
        assert_array_eq(
            &mut builder.when(local.is_valid),
            local.child_pvs.fixed_commit,
            fixed_commit,
        );
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.init_pc, init_pc);
        builder
            .when(local.is_valid)
            .assert_eq(local.child_pvs.init_cycle, init_cycle);
        assert_array_eq(
            &mut builder.when(local.is_valid),
            local.child_pvs.fixed_no_omc_init_commit,
            fixed_no_omc_init_commit,
        );
    }
}

impl VmPvsAir {
    fn eval_deferrals<AB>(
        &self,
        builder: &mut AB,
        local: &VmPvsCols<AB::Var>,
        local_def_flag: AB::Var,
        next_def_flag: AB::Var,
    ) -> (AB::Expr, AB::Expr)
    where
        AB: AirBuilder + InteractionBuilder + AirBuilderWithPublicValues,
    {
        // Constrain that deferral_flag must be in {0, 1, 2}. If:
        // - deferral_flag == 0: all proofs have VmPvs only, ignore deferral-related constraints
        // - deferral_flag == 1: all proofs have DeferralPvs only, there should be no valid rows
        //   and output public values should all be 0
        // - deferral_flag == 2: there is a single child proof with both sets of pvs
        builder.assert_tern(local_def_flag);
        builder.assert_eq(local_def_flag, next_def_flag);

        let mut when_deferral_flag = builder.when(local_def_flag);
        when_deferral_flag.assert_zero(local.proof_idx);

        let mut when_deferral_flag_two = when_deferral_flag.when_ne(local_def_flag, AB::Expr::ONE);
        when_deferral_flag_two.assert_one(local.is_valid);
        when_deferral_flag_two.assert_one(local.is_last);

        let mut when_deferral_flag_one = when_deferral_flag.when_ne(local_def_flag, AB::Expr::TWO);
        when_deferral_flag_one.assert_zero(local.is_valid);

        let vm_pvs: &VmPvs<_> = builder.public_values().borrow();
        let vm_pvs = vm_pvs.as_slice().to_vec();

        for value in vm_pvs {
            builder
                .when(local_def_flag)
                .when_ne(local_def_flag, AB::Expr::TWO)
                .assert_zero(value);
        }

        (
            local_def_flag.into(),
            (local_def_flag - AB::Expr::ONE).square(),
        )
    }
}
