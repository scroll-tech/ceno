use std::borrow::Borrow;

use openvm_circuit_primitives::AlignedBorrow;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::DIGEST_SIZE;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;

use crate::{
    bus::{TranscriptBus, TranscriptBusMessage},
    proof_shape::bus::{CommitmentsBus, CommitmentsBusMessage},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct CommitAirCols<T> {
    pub proof_idx: T,
    pub commitment: [T; DIGEST_SIZE],
    pub is_valid: T,
    pub tidx: T,
}

pub struct CommitAir {
    pub commitments_bus: CommitmentsBus,
    pub transcript_bus: TranscriptBus,
}

impl<F> BaseAir<F> for CommitAir {
    fn width(&self) -> usize {
        CommitAirCols::<F>::width()
    }
}
impl<F> BaseAirWithPublicValues<F> for CommitAir {}
impl<F> PartitionedBaseAir<F> for CommitAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for CommitAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &CommitAirCols<AB::Var> = (*local).borrow();
        let next: &CommitAirCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_valid);
        builder.when(next.is_valid).assert_one(local.is_valid);
        builder
            .when(local.is_valid * next.is_valid)
            .assert_eq(next.proof_idx, local.proof_idx + AB::Expr::ONE);

        self.commitments_bus.receive(
            builder,
            local.proof_idx,
            CommitmentsBusMessage {
                tidx: local.tidx.into(),
            },
            local.is_valid,
        );

        for (idx, commit_val) in local.commitment.iter().enumerate() {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.tidx.into() + AB::Expr::from_usize(idx),
                    value: (*commit_val).into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_valid,
            );
        }
    }
}
