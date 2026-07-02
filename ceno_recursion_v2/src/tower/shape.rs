use core::borrow::{Borrow, BorrowMut};

use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::primitives::bus::{RangeCheckerBus, RangeCheckerBusMessage};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{AirShapeBus, AirShapeBusMessage},
    proof_shape::bus::AirShapeProperty,
    tower::bus::{TowerActivityBus, TowerActivityMessage, TowerShapeBus, TowerShapeMessage},
    tracegen::RowMajorChip,
};

pub(crate) const TOWER_ACTIVITY_READ: usize = 0;
pub(crate) const TOWER_ACTIVITY_WRITE: usize = 1;
pub(crate) const TOWER_ACTIVITY_LOGUP: usize = 2;
pub(crate) const TOWER_ACTIVITY_KINDS: usize = 3;

#[derive(Debug, Clone, Default)]
pub(crate) struct TowerShapeRecord {
    pub(crate) proof_idx: usize,
    /// Compact per-proof tower row index used inside the tower module.
    pub(crate) idx: usize,
    /// ProofShapeAir sorted row index used to agree on AirShapeBus.
    pub(crate) air_idx: usize,
    pub(crate) num_vars: usize,
    pub(crate) read_op_vars: usize,
    pub(crate) write_op_vars: usize,
    pub(crate) logup_op_vars: usize,
    pub(crate) has_read: bool,
    pub(crate) has_write: bool,
    pub(crate) has_logup: bool,
    pub(crate) read_tower_vars: usize,
    pub(crate) write_tower_vars: usize,
    pub(crate) logup_tower_vars: usize,
    pub(crate) max_tower_vars: usize,
    pub(crate) max_layer_count: usize,
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerShapeCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub air_idx: T,
    pub num_vars: T,
    pub read_op_vars: T,
    pub write_op_vars: T,
    pub logup_op_vars: T,
    pub has_read: T,
    pub has_write: T,
    pub has_logup: T,
    pub read_tower_vars: T,
    pub write_tower_vars: T,
    pub logup_tower_vars: T,
    pub max_tower_vars: T,
    pub max_layer_count: T,
    pub is_read_max: T,
    pub is_write_max: T,
    pub is_logup_max: T,
}

pub struct TowerShapeAir {
    pub air_shape_bus: AirShapeBus,
    pub range_bus: RangeCheckerBus,
    pub shape_bus: TowerShapeBus,
}

impl<F: Field> BaseAir<F> for TowerShapeAir {
    fn width(&self) -> usize {
        TowerShapeCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerShapeAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerShapeAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerShapeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("row exists");
        let local: &TowerShapeCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.has_read);
        builder.assert_bool(local.has_write);
        builder.assert_bool(local.has_logup);
        builder.assert_bool(local.is_read_max);
        builder.assert_bool(local.is_write_max);
        builder.assert_bool(local.is_logup_max);

        let has_any = local.has_read + local.has_write + local.has_logup;
        let max_selector = local.is_read_max + local.is_write_max + local.is_logup_max;
        builder
            .when(local.is_enabled * has_any)
            .assert_one(max_selector.clone());

        builder.when(local.is_enabled).assert_eq(
            local.read_tower_vars,
            local.has_read * (local.num_vars + local.read_op_vars),
        );
        builder.when(local.is_enabled).assert_eq(
            local.write_tower_vars,
            local.has_write * (local.num_vars + local.write_op_vars),
        );
        builder.when(local.is_enabled).assert_eq(
            local.logup_tower_vars,
            local.has_logup * (local.num_vars + local.logup_op_vars),
        );
        builder.when(local.is_enabled).assert_eq(
            local.max_tower_vars,
            local.is_read_max * local.read_tower_vars
                + local.is_write_max * local.write_tower_vars
                + local.is_logup_max * local.logup_tower_vars,
        );
        builder
            .when(local.is_enabled)
            .assert_eq(local.max_layer_count + max_selector, local.max_tower_vars);

        for tower_vars in [
            local.read_tower_vars,
            local.write_tower_vars,
            local.logup_tower_vars,
        ] {
            self.range_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.max_tower_vars - tower_vars,
                    max_bits: AB::Expr::from_usize(8),
                },
                local.is_enabled,
            );
        }

        for (property_idx, value) in [
            (AirShapeProperty::BaseTowerVars, local.num_vars.into()),
            (AirShapeProperty::ReadOpVars, local.read_op_vars.into()),
            (AirShapeProperty::WriteOpVars, local.write_op_vars.into()),
            (AirShapeProperty::LogupOpVars, local.logup_op_vars.into()),
        ] {
            self.air_shape_bus.lookup_key(
                builder,
                local.proof_idx,
                AirShapeBusMessage {
                    sort_idx: local.air_idx.into(),
                    property_idx: property_idx.to_field(),
                    value,
                },
                local.is_enabled,
            );
        }

        self.shape_bus.send(
            builder,
            local.proof_idx,
            TowerShapeMessage {
                idx: local.idx.into(),
                num_vars: local.num_vars.into(),
                read_op_vars: local.read_op_vars.into(),
                write_op_vars: local.write_op_vars.into(),
                logup_op_vars: local.logup_op_vars.into(),
                has_read: local.has_read.into(),
                has_write: local.has_write.into(),
                has_logup: local.has_logup.into(),
                read_tower_vars: local.read_tower_vars.into(),
                write_tower_vars: local.write_tower_vars.into(),
                logup_tower_vars: local.logup_tower_vars.into(),
                max_tower_vars: local.max_tower_vars.into(),
                max_layer_count: local.max_layer_count.into(),
            },
            local.is_enabled * local.max_layer_count * AB::Expr::from_usize(TOWER_ACTIVITY_KINDS),
        );
    }
}

pub struct TowerShapeTraceGenerator;

impl RowMajorChip<openvm_stark_sdk::config::baby_bear_poseidon2::F> for TowerShapeTraceGenerator {
    type Ctx<'a> = &'a [TowerShapeRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<openvm_stark_sdk::config::baby_bear_poseidon2::F>> {
        use openvm_stark_sdk::config::baby_bear_poseidon2::F;

        let records = *records;
        let width = TowerShapeCols::<F>::width();
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let mut trace = vec![F::ZERO; height * width];

        for (row, record) in trace
            .chunks_exact_mut(width)
            .take(records.len())
            .zip(records.iter())
        {
            let cols: &mut TowerShapeCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.air_idx = F::from_usize(record.air_idx);
            cols.num_vars = F::from_usize(record.num_vars);
            cols.read_op_vars = F::from_usize(record.read_op_vars);
            cols.write_op_vars = F::from_usize(record.write_op_vars);
            cols.logup_op_vars = F::from_usize(record.logup_op_vars);
            cols.has_read = F::from_bool(record.has_read);
            cols.has_write = F::from_bool(record.has_write);
            cols.has_logup = F::from_bool(record.has_logup);
            cols.read_tower_vars = F::from_usize(record.read_tower_vars);
            cols.write_tower_vars = F::from_usize(record.write_tower_vars);
            cols.logup_tower_vars = F::from_usize(record.logup_tower_vars);
            cols.max_tower_vars = F::from_usize(record.max_tower_vars);
            cols.max_layer_count = F::from_usize(record.max_layer_count);

            let max = record.max_tower_vars;
            if record.has_read && record.read_tower_vars == max {
                cols.is_read_max = F::ONE;
            } else if record.has_write && record.write_tower_vars == max {
                cols.is_write_max = F::ONE;
            } else if record.has_logup && record.logup_tower_vars == max {
                cols.is_logup_max = F::ONE;
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerActivityCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub layer_idx: T,
    pub kind: T,
    pub is_read: T,
    pub is_write: T,
    pub is_logup: T,
    pub active: T,
    pub selected_has_kind: T,
    pub selected_tower_vars: T,
    pub selected_op_vars: T,
    pub num_vars: T,
    pub read_op_vars: T,
    pub write_op_vars: T,
    pub logup_op_vars: T,
    pub has_read: T,
    pub has_write: T,
    pub has_logup: T,
    pub read_tower_vars: T,
    pub write_tower_vars: T,
    pub logup_tower_vars: T,
    pub max_tower_vars: T,
    pub max_layer_count: T,
    pub prefix_len: T,
}

pub struct TowerActivityAir {
    pub range_bus: RangeCheckerBus,
    pub shape_bus: TowerShapeBus,
    pub activity_bus: TowerActivityBus,
}

impl<F: Field> BaseAir<F> for TowerActivityAir {
    fn width(&self) -> usize {
        TowerActivityCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerActivityAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerActivityAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerActivityAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("row exists");
        let local: &TowerActivityCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_read);
        builder.assert_bool(local.is_write);
        builder.assert_bool(local.is_logup);
        builder.assert_bool(local.active);
        builder
            .when(local.is_enabled)
            .assert_one(local.is_read + local.is_write + local.is_logup);
        builder.when(local.is_enabled).assert_eq(
            local.kind,
            local.is_write * AB::Expr::from_usize(TOWER_ACTIVITY_WRITE)
                + local.is_logup * AB::Expr::from_usize(TOWER_ACTIVITY_LOGUP),
        );

        let selected_has = local.is_read * local.has_read
            + local.is_write * local.has_write
            + local.is_logup * local.has_logup;
        let selected_op_vars = local.is_read * local.read_op_vars
            + local.is_write * local.write_op_vars
            + local.is_logup * local.logup_op_vars;
        let selected_tower_vars = local.is_read * local.read_tower_vars
            + local.is_write * local.write_tower_vars
            + local.is_logup * local.logup_tower_vars;
        builder
            .when(local.is_enabled)
            .assert_eq(local.selected_has_kind, selected_has.clone());
        builder
            .when(local.is_enabled)
            .assert_eq(local.selected_op_vars, selected_op_vars);
        builder
            .when(local.is_enabled)
            .assert_eq(local.selected_tower_vars, selected_tower_vars.clone());
        builder.when(local.is_enabled).assert_eq(
            local.prefix_len + local.selected_tower_vars,
            local.max_tower_vars,
        );
        builder
            .when(local.is_enabled)
            .assert_zero(local.active * (AB::Expr::ONE - local.selected_has_kind));

        let active_limit = selected_tower_vars - AB::Expr::ONE;
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: active_limit.clone() - local.layer_idx,
                max_bits: AB::Expr::from_usize(8),
            },
            local.is_enabled * local.active,
        );
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: local.layer_idx - active_limit,
                max_bits: AB::Expr::from_usize(8),
            },
            local.is_enabled * (AB::Expr::ONE - local.active),
        );

        self.shape_bus.receive(
            builder,
            local.proof_idx,
            TowerShapeMessage {
                idx: local.idx.into(),
                num_vars: local.num_vars.into(),
                read_op_vars: local.read_op_vars.into(),
                write_op_vars: local.write_op_vars.into(),
                logup_op_vars: local.logup_op_vars.into(),
                has_read: local.has_read.into(),
                has_write: local.has_write.into(),
                has_logup: local.has_logup.into(),
                read_tower_vars: local.read_tower_vars.into(),
                write_tower_vars: local.write_tower_vars.into(),
                logup_tower_vars: local.logup_tower_vars.into(),
                max_tower_vars: local.max_tower_vars.into(),
                max_layer_count: local.max_layer_count.into(),
            },
            local.is_enabled,
        );
        self.activity_bus.send(
            builder,
            local.proof_idx,
            TowerActivityMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                kind: local.kind.into(),
                active: local.active.into(),
            },
            local.is_enabled,
        );
    }
}

pub struct TowerActivityTraceGenerator;

impl RowMajorChip<openvm_stark_sdk::config::baby_bear_poseidon2::F>
    for TowerActivityTraceGenerator
{
    type Ctx<'a> = &'a [TowerShapeRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<openvm_stark_sdk::config::baby_bear_poseidon2::F>> {
        use openvm_stark_sdk::config::baby_bear_poseidon2::F;

        let records = *records;
        let width = TowerActivityCols::<F>::width();
        let num_valid_rows: usize = records
            .iter()
            .map(|record| record.max_layer_count * TOWER_ACTIVITY_KINDS)
            .sum();
        let num_valid_rows = num_valid_rows.max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let mut trace = vec![F::ZERO; height * width];
        let mut rows = trace.chunks_exact_mut(width);

        for record in records {
            for layer_idx in 0..record.max_layer_count {
                for kind in 0..TOWER_ACTIVITY_KINDS {
                    let row = rows.next().unwrap();
                    let cols: &mut TowerActivityCols<F> = row.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.layer_idx = F::from_usize(layer_idx);
                    cols.kind = F::from_usize(kind);
                    cols.is_read = F::from_bool(kind == TOWER_ACTIVITY_READ);
                    cols.is_write = F::from_bool(kind == TOWER_ACTIVITY_WRITE);
                    cols.is_logup = F::from_bool(kind == TOWER_ACTIVITY_LOGUP);
                    cols.num_vars = F::from_usize(record.num_vars);
                    cols.read_op_vars = F::from_usize(record.read_op_vars);
                    cols.write_op_vars = F::from_usize(record.write_op_vars);
                    cols.logup_op_vars = F::from_usize(record.logup_op_vars);
                    cols.has_read = F::from_bool(record.has_read);
                    cols.has_write = F::from_bool(record.has_write);
                    cols.has_logup = F::from_bool(record.has_logup);
                    cols.read_tower_vars = F::from_usize(record.read_tower_vars);
                    cols.write_tower_vars = F::from_usize(record.write_tower_vars);
                    cols.logup_tower_vars = F::from_usize(record.logup_tower_vars);
                    cols.max_tower_vars = F::from_usize(record.max_tower_vars);
                    cols.max_layer_count = F::from_usize(record.max_layer_count);

                    let (has_kind, op_vars, tower_vars) = match kind {
                        TOWER_ACTIVITY_READ => {
                            (record.has_read, record.read_op_vars, record.read_tower_vars)
                        }
                        TOWER_ACTIVITY_WRITE => (
                            record.has_write,
                            record.write_op_vars,
                            record.write_tower_vars,
                        ),
                        TOWER_ACTIVITY_LOGUP => (
                            record.has_logup,
                            record.logup_op_vars,
                            record.logup_tower_vars,
                        ),
                        _ => unreachable!(),
                    };
                    cols.selected_has_kind = F::from_bool(has_kind);
                    cols.selected_op_vars = F::from_usize(op_vars);
                    cols.selected_tower_vars = F::from_usize(tower_vars);
                    cols.prefix_len = F::from_usize(record.max_tower_vars - tower_vars);
                    cols.active = F::from_bool(has_kind && layer_idx + 1 < tower_vars);
                }
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
