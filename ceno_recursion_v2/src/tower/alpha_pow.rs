use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::{assert_zeros, ext_field_multiply};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    tower::{
        TOWER_ACTIVITY_LOGUP, TOWER_ACTIVITY_READ, TOWER_ACTIVITY_WRITE, TowerAlphaPowBus,
        TowerAlphaPowMessage, layer::TowerLayerRecord,
    },
    tracegen::RowMajorChip,
};

const TOWER_ALPHA_SLOT_LOGUP_Q: usize = TOWER_ACTIVITY_LOGUP + 1;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerAlphaPowCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_air_idx: T,
    pub is_first_slot: T,
    pub is_last_slot: T,
    pub layer_idx: T,
    pub slot_idx: T,
    pub slot_kind: T,
    pub active: T,
    pub alpha: [T; D_EF],
    pub power: [T; D_EF],
    pub next_power: [T; D_EF],
    pub weight: [T; D_EF],
}

pub struct TowerAlphaPowAir {
    pub alpha_pow_bus: TowerAlphaPowBus,
}

impl<F: Field> BaseAir<F> for TowerAlphaPowAir {
    fn width(&self) -> usize {
        TowerAlphaPowCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerAlphaPowAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerAlphaPowAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerAlphaPowAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerAlphaPowCols<AB::Var> = (*local).borrow();
        let next: &TowerAlphaPowCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first_air_idx);
        builder.assert_bool(local.is_first_slot);
        builder.assert_bool(local.is_last_slot);
        builder.assert_bool(local.active);
        builder
            .when(local.is_first_air_idx)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_first_slot)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_last_slot)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_first_slot)
            .assert_zero(local.slot_idx);

        let alpha_power_next = ext_field_multiply::<AB::Expr>(local.power, local.alpha);
        assert_array_eq(builder, local.next_power, alpha_power_next.clone());
        assert_array_eq(&mut builder.when(local.active), local.weight, local.power);
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.active),
            local.weight.map(Into::into),
        );

        let is_slot_transition = local.is_enabled * (AB::Expr::ONE - local.is_last_slot);
        builder
            .when(is_slot_transition.clone())
            .assert_one(next.is_enabled);
        builder
            .when(is_slot_transition.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when(is_slot_transition.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when(is_slot_transition.clone())
            .assert_eq(next.layer_idx, local.layer_idx);
        builder
            .when(is_slot_transition.clone())
            .assert_eq(next.slot_idx, local.slot_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when(is_slot_transition.clone()),
            next.alpha,
            local.alpha,
        );
        assert_array_eq(
            &mut builder.when(is_slot_transition),
            next.power,
            alpha_power_next,
        );

        self.alpha_pow_bus.send(
            builder,
            local.proof_idx,
            TowerAlphaPowMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                slot_kind: local.slot_kind.into(),
                alpha: local.alpha.map(Into::into),
                weight: local.weight.map(Into::into),
            },
            local.is_enabled * local.active,
        );
    }
}

pub struct TowerAlphaPowTraceGenerator;

impl RowMajorChip<F> for TowerAlphaPowTraceGenerator {
    type Ctx<'a> = &'a [TowerLayerRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let records = *records;
        let width = TowerAlphaPowCols::<F>::width();
        let num_valid_rows: usize = records
            .iter()
            .map(|record| {
                let has_read = record.read_counts.iter().any(|&count| count != 0);
                let has_write = record.write_counts.iter().any(|&count| count != 0);
                let has_logup = record.logup_counts.iter().any(|&count| count != 0);
                record.layer_count().max(1)
                    * (usize::from(has_read) + usize::from(has_write) + 2 * usize::from(has_logup))
                        .max(1)
            })
            .sum::<usize>()
            .max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let mut trace = vec![F::ZERO; height * width];
        let mut row_idx = 0usize;

        for record in records {
            let has_read = record.read_counts.iter().any(|&count| count != 0);
            let has_write = record.write_counts.iter().any(|&count| count != 0);
            let has_logup = record.logup_counts.iter().any(|&count| count != 0);
            let layer_count = record.layer_count().max(1);

            for layer_idx in 0..layer_count {
                let mut slots = Vec::with_capacity(4);
                if has_read {
                    slots.push((TOWER_ACTIVITY_READ, record.read_active_at(layer_idx)));
                }
                if has_write {
                    slots.push((TOWER_ACTIVITY_WRITE, record.write_active_at(layer_idx)));
                }
                if has_logup {
                    slots.push((TOWER_ACTIVITY_LOGUP, record.logup_active_at(layer_idx)));
                    slots.push((TOWER_ALPHA_SLOT_LOGUP_Q, record.logup_active_at(layer_idx)));
                }
                if slots.is_empty() {
                    slots.push((TOWER_ACTIVITY_READ, false));
                }

                let alpha = record.lambda_at(layer_idx);
                let mut power = EF::ONE;
                for (slot_idx, (slot_kind, active)) in slots.iter().copied().enumerate() {
                    let cols: &mut TowerAlphaPowCols<F> =
                        trace[row_idx * width..(row_idx + 1) * width].borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.is_first_air_idx = F::from_bool(layer_idx == 0 && slot_idx == 0);
                    cols.is_first_slot = F::from_bool(slot_idx == 0);
                    cols.is_last_slot = F::from_bool(slot_idx + 1 == slots.len());
                    cols.layer_idx = F::from_usize(layer_idx);
                    cols.slot_idx = F::from_usize(slot_idx);
                    cols.slot_kind = F::from_usize(slot_kind);
                    cols.active = F::from_bool(active);
                    cols.alpha = alpha.as_basis_coefficients_slice().try_into().unwrap();
                    cols.power = power.as_basis_coefficients_slice().try_into().unwrap();
                    let next_power = power * alpha;
                    cols.next_power = next_power.as_basis_coefficients_slice().try_into().unwrap();
                    let weight = if active { power } else { EF::ZERO };
                    cols.weight = weight.as_basis_coefficients_slice().try_into().unwrap();
                    power = next_power;
                    row_idx += 1;
                }
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
