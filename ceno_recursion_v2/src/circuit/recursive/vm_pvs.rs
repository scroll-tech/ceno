use std::borrow::Borrow;

use ceno_emul::WORD_SIZE;
use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use recursion_circuit::bus::{PublicValuesBus, PublicValuesBusMessage};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::circuit::{inner::vm_pvs::VmPvs, root::verifier::CENO_VM_PVS_AIR_ID};

#[repr(C)]
#[derive(AlignedBorrow)]
pub struct CenoRecursiveVmPvsCols<F> {
    pub proof_idx: F,
    pub is_valid: F,
    pub is_last: F,
    pub child_pvs: VmPvs<F>,
}

pub struct CenoRecursiveVmPvsAir {
    pub public_values_bus: PublicValuesBus,
}

impl<F> BaseAir<F> for CenoRecursiveVmPvsAir {
    fn width(&self) -> usize {
        CenoRecursiveVmPvsCols::<u8>::width()
    }
}

impl<F> BaseAirWithPublicValues<F> for CenoRecursiveVmPvsAir {
    fn num_public_values(&self) -> usize {
        VmPvs::<u8>::width()
    }
}

impl<F> PartitionedBaseAir<F> for CenoRecursiveVmPvsAir {}

impl<AB: AirBuilder + InteractionBuilder + AirBuilderWithPublicValues> Air<AB>
    for CenoRecursiveVmPvsAir
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &CenoRecursiveVmPvsCols<AB::Var> = (*local).borrow();
        let next: &CenoRecursiveVmPvsCols<AB::Var> = (*next).borrow();

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

        let mut when_both_valid =
            builder.when(local.is_valid * (AB::Expr::ONE - local.is_last.into()));
        when_both_valid.assert_eq(local.child_pvs.end_pc, next.child_pvs.init_pc);
        when_both_valid.assert_eq(
            local.child_pvs.shard_id + local.child_pvs.shard_count,
            next.child_pvs.shard_id,
        );
        when_both_valid.assert_eq(
            local.child_pvs.heap_start_addr
                + local.child_pvs.heap_shard_len * AB::Expr::from_u32(WORD_SIZE as u32),
            next.child_pvs.heap_start_addr,
        );
        when_both_valid.assert_eq(
            local.child_pvs.hint_start_addr
                + local.child_pvs.hint_shard_len * AB::Expr::from_u32(WORD_SIZE as u32),
            next.child_pvs.hint_start_addr,
        );

        for (pv_idx, value) in local.child_pvs.as_slice().iter().enumerate() {
            self.public_values_bus.receive(
                builder,
                local.proof_idx,
                PublicValuesBusMessage {
                    air_idx: AB::Expr::from_usize(CENO_VM_PVS_AIR_ID),
                    pv_idx: AB::Expr::from_usize(pv_idx),
                    value: (*value).into(),
                },
                local.is_valid,
            );
        }

        let public_values = builder.public_values().to_vec();
        let public_pvs: &VmPvs<_> = public_values[0..VmPvs::<u8>::width()].borrow();

        assert_array_eq(
            &mut builder.when_first_row(),
            local.child_pvs.fixed_commit,
            public_pvs.fixed_commit,
        );
        assert_array_eq(
            &mut builder.when_first_row(),
            local.child_pvs.fixed_no_omc_init_commit,
            public_pvs.fixed_no_omc_init_commit,
        );
        assert_array_eq(
            &mut builder.when_first_row(),
            local.child_pvs.witness_commit,
            public_pvs.witness_commit,
        );
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.init_pc, public_pvs.init_pc);
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.init_cycle, public_pvs.init_cycle);
        builder
            .when(local.is_last)
            .assert_eq(local.child_pvs.end_pc, public_pvs.end_pc);
        builder
            .when(local.is_last)
            .assert_eq(local.child_pvs.end_cycle, public_pvs.end_cycle);
        assert_array_eq(
            &mut builder.when(local.is_last),
            local.child_pvs.exit_code,
            public_pvs.exit_code,
        );
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.shard_id, public_pvs.shard_id);
        builder.when(local.is_last).assert_eq(
            local.child_pvs.shard_id + local.child_pvs.shard_count,
            public_pvs.shard_id.into() + public_pvs.shard_count.into(),
        );
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.heap_start_addr, public_pvs.heap_start_addr);
        builder.when(local.is_last).assert_eq(
            local.child_pvs.heap_start_addr
                + local.child_pvs.heap_shard_len * AB::Expr::from_u32(WORD_SIZE as u32),
            public_pvs.heap_start_addr.into()
                + public_pvs.heap_shard_len.into() * AB::Expr::from_u32(WORD_SIZE as u32),
        );
        builder
            .when_first_row()
            .assert_eq(local.child_pvs.hint_start_addr, public_pvs.hint_start_addr);
        builder.when(local.is_last).assert_eq(
            local.child_pvs.hint_start_addr
                + local.child_pvs.hint_shard_len * AB::Expr::from_u32(WORD_SIZE as u32),
            public_pvs.hint_start_addr.into()
                + public_pvs.hint_shard_len.into() * AB::Expr::from_u32(WORD_SIZE as u32),
        );
        assert_array_eq(
            &mut builder.when_first_row(),
            local.child_pvs.public_io,
            public_pvs.public_io,
        );
        assert_array_eq(
            &mut builder.when_first_row(),
            local.child_pvs.shard_rw_sum,
            public_pvs.shard_rw_sum,
        );
    }
}
