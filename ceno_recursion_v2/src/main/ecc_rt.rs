use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::{
    ext_field_add, ext_field_multiply, ext_field_multiply_scalar, ext_field_one_minus,
    ext_field_subtract,
};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{EccRtBus, EccRtMessage, ForkedTranscriptBus, ForkedTranscriptBusMessage},
    system::MainEccRtRecord,
    tracegen::RowMajorChip,
};

const SEPTIC_DEGREE: usize = 7;
const ECC_ALPHA_POWS: usize = 49;
const MAX_ECC_VARS: usize = 32;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub fork_id: T,
    pub round_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub tidx: T,
    pub out_tidx: T,
    pub alpha_tidx: T,
    pub lookup_count: T,
    pub rt: [T; D_EF],
    pub out_rt: [T; D_EF],
    pub alpha: [T; D_EF],
    pub alpha_pows: [[T; D_EF]; ECC_ALPHA_POWS],
    pub ev1: [T; D_EF],
    pub ev2: [T; D_EF],
    pub ev3: [T; D_EF],
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
    pub sel_add: [T; D_EF],
    pub sel_bypass: [T; D_EF],
    pub sel_export: [T; D_EF],
    pub s0: [[T; D_EF]; SEPTIC_DEGREE],
    pub x0: [[T; D_EF]; SEPTIC_DEGREE],
    pub y0: [[T; D_EF]; SEPTIC_DEGREE],
    pub x1: [[T; D_EF]; SEPTIC_DEGREE],
    pub y1: [[T; D_EF]; SEPTIC_DEGREE],
    pub x3: [[T; D_EF]; SEPTIC_DEGREE],
    pub y3: [[T; D_EF]; SEPTIC_DEGREE],
    pub sum_x: [[T; D_EF]; SEPTIC_DEGREE],
    pub sum_y: [[T; D_EF]; SEPTIC_DEGREE],
    pub eq_in: [T; D_EF],
    pub eq_out: [T; D_EF],
    pub last_in: [T; D_EF],
    pub last_out: [T; D_EF],
    pub export_out_in: [T; D_EF],
    pub export_out_out: [T; D_EF],
    pub export_rt_in: [T; D_EF],
    pub export_rt_out: [T; D_EF],
    pub quark_in: [T; D_EF],
    pub quark_factor: [T; D_EF],
    pub quark_out: [T; D_EF],
    pub add_eval: [T; D_EF],
    pub bypass_eval: [T; D_EF],
    pub export_eval: [T; D_EF],
    pub lte_out_point: [[T; D_EF]; MAX_ECC_VARS],
    pub lte_rt_point: [[T; D_EF]; MAX_ECC_VARS],
    pub lte_prefix_acc: [[T; D_EF]; MAX_ECC_VARS + 1],
    pub lte_less_acc: [[T; D_EF]; MAX_ECC_VARS + 1],
    pub lte_bits: [T; MAX_ECC_VARS],
    pub lte_active: [T; MAX_ECC_VARS],
    pub quark_prefix_count: T,
    pub quark_prefix_is_zero: T,
    pub quark_prefix_inv: T,
    pub quark_layer_n: T,
    pub quark_parity: T,
}

pub struct MainEccRtAir {
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub ecc_rt_bus: EccRtBus,
}

impl<F: Field> BaseAir<F> for MainEccRtAir {
    fn width(&self) -> usize {
        MainEccRtCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtAir {}

impl<AB> Air<AB> for MainEccRtAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.quark_parity);
        builder.assert_bool(local.quark_prefix_is_zero);
        builder
            .when(local.is_enabled)
            .assert_zero(local.quark_prefix_is_zero * local.quark_prefix_count);
        builder.when(local.is_enabled).assert_eq(
            local.quark_prefix_count * local.quark_prefix_inv,
            AB::Expr::ONE - local.quark_prefix_is_zero,
        );

        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.rt[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.out_tidx + AB::Expr::from_usize(i),
                    value: local.out_rt[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.alpha_tidx + AB::Expr::from_usize(i),
                    value: local.alpha[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * local.is_first,
            );
        }

        self.ecc_rt_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            EccRtMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.rt.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.alpha_pows[0],
            ext_one::<AB::Expr>(),
        );
        for i in 0..ECC_ALPHA_POWS - 1 {
            let next_pow =
                ext_field_multiply::<AB::Expr>(local.alpha_pows[i], local.alpha.map(Into::into));
            assert_array_eq(
                &mut builder.when(local.is_enabled),
                local.alpha_pows[i + 1],
                next_pow,
            );
        }

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.claim_in,
            ext_zero::<AB::Expr>(),
        );
        let ev0 = ext_field_subtract(local.claim_in, local.ev1);
        let claim_out = interpolate_cubic_at_0123(ev0, local.ev1, local.ev2, local.ev3, local.rt);
        assert_array_eq(&mut builder.when(local.is_enabled), local.claim_out, claim_out);

        let eq_factor = eq_factor::<AB>(local.out_rt, local.rt);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.eq_out,
            ext_field_multiply::<AB::Expr>(local.eq_in, eq_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.eq_in,
            ext_one::<AB::Expr>(),
        );

        let last_factor = ext_field_multiply::<AB::Expr>(local.out_rt, local.rt);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.last_out,
            ext_field_multiply::<AB::Expr>(local.last_in, last_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.last_in,
            ext_one::<AB::Expr>(),
        );

        let export_out_factor = choose_ext::<AB>(
            local.is_first,
            ext_field_one_minus(local.out_rt.map(Into::into)),
            local.out_rt.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_out_out,
            ext_field_multiply::<AB::Expr>(local.export_out_in, export_out_factor),
        );
        let export_rt_factor = choose_ext::<AB>(
            local.is_first,
            ext_field_one_minus(local.rt.map(Into::into)),
            local.rt.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_rt_out,
            ext_field_multiply::<AB::Expr>(local.export_rt_in, export_rt_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.export_out_in,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.export_rt_in,
            ext_one::<AB::Expr>(),
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.quark_in,
            ext_zero::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.quark_factor,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.quark_prefix_is_zero),
            local.quark_factor,
            ext_zero::<AB::Expr>(),
        );
        builder.when(local.is_enabled).assert_eq(
            local.quark_layer_n,
            local.quark_prefix_count * AB::Expr::from_usize(2) + local.quark_parity,
        );
        self::eval_lte_witness(builder, local);
        let quark_zero = ext_field_multiply::<AB::Expr>(
            one_minus_ext::<AB>(local.out_rt),
            one_minus_ext::<AB>(local.rt),
        );
        let quark_one = ext_field_multiply::<AB::Expr>(local.out_rt, local.rt);
        let quark_lhs =
            ext_field_multiply::<AB::Expr>(quark_zero, local.quark_factor.map(Into::into));
        let quark_rhs = ext_field_multiply::<AB::Expr>(quark_one, local.quark_in);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.quark_out,
            ext_field_add::<AB::Expr>(quark_lhs, quark_rhs),
        );

        let same_ecc = local.is_enabled * next.is_enabled * (AB::Expr::ONE - next.is_first);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.fork_id, local.fork_id);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.claim_out,
            next.claim_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.eq_out,
            next.eq_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.last_out,
            next.last_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.export_out_out,
            next.export_out_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.export_rt_out,
            next.export_rt_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.quark_out,
            next.quark_in,
        );
        builder
            .when_transition()
            .when(same_ecc)
            .assert_eq(
                next.quark_layer_n,
                local.quark_layer_n * AB::Expr::from_usize(2) - next.quark_parity,
            );

        let sel_bypass = ext_field_subtract::<AB::Expr>(
            ext_field_subtract::<AB::Expr>(local.eq_out, local.sel_add),
            local.last_out,
        );
        let sel_export =
            ext_field_multiply::<AB::Expr>(local.export_out_out, local.export_rt_out);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_add,
            local.quark_out,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_bypass,
            sel_bypass,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_export,
            sel_export,
        );
        let (add_eval, bypass_eval, export_eval) = ecc_equation_evals::<AB>(local);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.add_eval,
            add_eval,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.bypass_eval,
            bypass_eval,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_eval,
            export_eval,
        );
        let expected = ext_field_add::<AB::Expr>(
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.add_eval, local.sel_add),
                ext_field_multiply::<AB::Expr>(local.bypass_eval, local.sel_bypass),
            ),
            ext_field_multiply::<AB::Expr>(local.export_eval, local.sel_export),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.claim_out,
            expected,
        );
    }
}

fn eval_lte_witness<AB>(builder: &mut AB, local: &MainEccRtCols<AB::Var>)
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let mut active_count = AB::Expr::ZERO;
    let mut bit_value = AB::Expr::ZERO;
    assert_array_eq(
        &mut builder.when(local.is_enabled),
        local.lte_prefix_acc[0].clone(),
        ext_one::<AB::Expr>(),
    );
    assert_array_eq(
        &mut builder.when(local.is_enabled),
        local.lte_less_acc[0].clone(),
        ext_zero::<AB::Expr>(),
    );
    for i in 0..MAX_ECC_VARS {
        builder.assert_bool(local.lte_active[i]);
        builder.assert_bool(local.lte_bits[i]);
        builder.assert_zero(local.lte_bits[i] * (AB::Expr::ONE - local.lte_active[i]));
        if i + 1 < MAX_ECC_VARS {
            builder.assert_zero(local.lte_active[i + 1] * (AB::Expr::ONE - local.lte_active[i]));
        }
        active_count += local.lte_active[i];
        bit_value += local.lte_bits[i] * AB::Expr::from_usize(1usize << i);

        let same_one = ext_field_multiply::<AB::Expr>(
            local.lte_out_point[i].clone(),
            local.lte_rt_point[i].clone(),
        );
        let same_zero = ext_field_multiply::<AB::Expr>(
            one_minus_ext::<AB>(local.lte_out_point[i].clone()),
            one_minus_ext::<AB>(local.lte_rt_point[i].clone()),
        );
        let same_any = ext_field_add::<AB::Expr>(same_one.clone(), same_zero.clone());
        let equal_choice = choose_ext::<AB>(local.lte_bits[i], same_one, same_zero.clone());
        let active_prefix = ext_field_multiply::<AB::Expr>(
            local.lte_prefix_acc[i].clone(),
            equal_choice,
        );
        let inactive_prefix = local.lte_prefix_acc[i].clone().map(Into::into);
        assert_array_eq(
            builder,
            local.lte_prefix_acc[i + 1].clone(),
            choose_ext::<AB>(local.lte_active[i], active_prefix, inactive_prefix),
        );
        let less_from_prior =
            ext_field_multiply::<AB::Expr>(local.lte_less_acc[i].clone(), same_any);
        let less_from_equal = ext_field_multiply::<AB::Expr>(
            local.lte_prefix_acc[i].clone(),
            same_zero,
        );
        let active_less = ext_field_add::<AB::Expr>(
            less_from_prior,
            ext_field_multiply_scalar::<AB::Expr>(less_from_equal, local.lte_bits[i]),
        );
        let inactive_less = local.lte_less_acc[i].clone().map(Into::into);
        assert_array_eq(
            builder,
            local.lte_less_acc[i + 1].clone(),
            choose_ext::<AB>(local.lte_active[i], active_less, inactive_less),
        );
    }
    builder.assert_eq(active_count, local.round_idx);
    builder.when(local.is_enabled).assert_zero(
        (AB::Expr::ONE - local.quark_prefix_is_zero)
            * (bit_value + AB::Expr::ONE - local.quark_prefix_count),
    );
    let lte_value = ext_field_add::<AB::Expr>(
        local.lte_prefix_acc[MAX_ECC_VARS].clone(),
        local.lte_less_acc[MAX_ECC_VARS].clone(),
    );
    assert_array_eq(
        &mut builder.when(
            local.is_enabled
                * (AB::Expr::ONE - local.is_first)
                * (AB::Expr::ONE - local.quark_prefix_is_zero),
        ),
        local.quark_factor,
        lte_value,
    );
}

fn ecc_equation_evals<AB: AirBuilder>(
    local: &MainEccRtCols<AB::Var>,
) -> ([AB::Expr; D_EF], [AB::Expr; D_EF], [AB::Expr; D_EF])
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let mut add_eval = ext_zero::<AB::Expr>();
    let mut bypass_eval = ext_zero::<AB::Expr>();
    let mut export_eval = ext_zero::<AB::Expr>();
    for i in 0..SEPTIC_DEGREE {
        let v1 = ext_field_subtract::<AB::Expr>(
            ext_field_multiply::<AB::Expr>(
                local.s0[i].clone(),
                ext_field_subtract::<AB::Expr>(local.x0[i].clone(), local.x1[i].clone()),
            ),
            ext_field_subtract::<AB::Expr>(local.y0[i].clone(), local.y1[i].clone()),
        );
        let v2 = ext_field_subtract::<AB::Expr>(
            ext_field_subtract::<AB::Expr>(
                ext_field_subtract::<AB::Expr>(
                    ext_field_multiply::<AB::Expr>(local.s0[i].clone(), local.s0[i].clone()),
                    local.x0[i].clone(),
                ),
                local.x1[i].clone(),
            ),
            local.x3[i].clone(),
        );
        let v3 = ext_field_subtract::<AB::Expr>(
            ext_field_multiply::<AB::Expr>(
                local.s0[i].clone(),
                ext_field_subtract::<AB::Expr>(local.x0[i].clone(), local.x3[i].clone()),
            ),
            ext_field_add::<AB::Expr>(local.y0[i].clone(), local.y3[i].clone()),
        );
        let v4 = ext_field_subtract::<AB::Expr>(local.x3[i].clone(), local.x0[i].clone());
        let v5 = ext_field_subtract::<AB::Expr>(local.y3[i].clone(), local.y0[i].clone());
        add_eval = ext_field_add::<AB::Expr>(
            add_eval,
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(v1, local.alpha_pows[i].clone()),
                ext_field_add::<AB::Expr>(
                    ext_field_multiply::<AB::Expr>(
                        v2,
                        local.alpha_pows[SEPTIC_DEGREE + i].clone(),
                    ),
                    ext_field_multiply::<AB::Expr>(
                        v3,
                        local.alpha_pows[2 * SEPTIC_DEGREE + i].clone(),
                    ),
                ),
            ),
        );
        bypass_eval = ext_field_add::<AB::Expr>(
            bypass_eval,
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(
                    v4,
                    local.alpha_pows[3 * SEPTIC_DEGREE + i].clone(),
                ),
                ext_field_multiply::<AB::Expr>(
                    v5,
                    local.alpha_pows[4 * SEPTIC_DEGREE + i].clone(),
                ),
            ),
        );
        export_eval = ext_field_add::<AB::Expr>(
            export_eval,
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(
                    ext_field_subtract::<AB::Expr>(local.x3[i].clone(), local.sum_x[i].clone()),
                    local.alpha_pows[5 * SEPTIC_DEGREE + i].clone(),
                ),
                ext_field_multiply::<AB::Expr>(
                    ext_field_subtract::<AB::Expr>(local.y3[i].clone(), local.sum_y[i].clone()),
                    local.alpha_pows[6 * SEPTIC_DEGREE + i].clone(),
                ),
            ),
        );
    }
    (add_eval, bypass_eval, export_eval)
}

pub struct MainEccRtTraceGenerator;

impl RowMajorChip<F> for MainEccRtTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtCols::<F>::width();
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
        if records.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtCols<F> = row.borrow_mut();
            fill_cols(record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

fn fill_cols(record: &MainEccRtRecord, cols: &mut MainEccRtCols<F>) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.fork_id = F::from_usize(record.fork_id);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.is_first = F::from_bool(record.is_first);
    cols.is_last = F::from_bool(record.is_last);
    cols.tidx = F::from_usize(record.tidx);
    cols.out_tidx = F::from_usize(record.out_tidx);
    cols.alpha_tidx = F::from_usize(record.alpha_tidx);
    cols.lookup_count = F::from_usize(record.lookup_count);
    cols.rt = ext_to_basis(record.value);
    cols.out_rt = ext_to_basis(record.out_value);
    cols.alpha = ext_to_basis(record.alpha);
    cols.alpha_pows = record.alpha_pows.map(ext_to_basis);
    cols.ev1 = ext_to_basis(record.ev1);
    cols.ev2 = ext_to_basis(record.ev2);
    cols.ev3 = ext_to_basis(record.ev3);
    cols.claim_in = ext_to_basis(record.claim_in);
    cols.claim_out = ext_to_basis(record.claim_out);
    cols.sel_add = ext_to_basis(record.sel_add);
    cols.sel_bypass = ext_to_basis(record.sel_bypass);
    cols.sel_export = ext_to_basis(record.sel_export);
    cols.s0 = record.s0.map(ext_to_basis);
    cols.x0 = record.x0.map(ext_to_basis);
    cols.y0 = record.y0.map(ext_to_basis);
    cols.x1 = record.x1.map(ext_to_basis);
    cols.y1 = record.y1.map(ext_to_basis);
    cols.x3 = record.x3.map(ext_to_basis);
    cols.y3 = record.y3.map(ext_to_basis);
    cols.sum_x = record.sum_x.map(ext_to_basis);
    cols.sum_y = record.sum_y.map(ext_to_basis);
    cols.eq_in = ext_to_basis(record.eq_in);
    cols.eq_out = ext_to_basis(record.eq_out);
    cols.last_in = ext_to_basis(record.last_in);
    cols.last_out = ext_to_basis(record.last_out);
    cols.export_out_in = ext_to_basis(record.export_out_in);
    cols.export_out_out = ext_to_basis(record.export_out_out);
    cols.export_rt_in = ext_to_basis(record.export_rt_in);
    cols.export_rt_out = ext_to_basis(record.export_rt_out);
    cols.quark_in = ext_to_basis(record.quark_in);
    cols.quark_factor = ext_to_basis(record.quark_factor);
    cols.quark_out = ext_to_basis(record.quark_out);
    cols.add_eval = ext_to_basis(record.add_eval);
    cols.bypass_eval = ext_to_basis(record.bypass_eval);
    cols.export_eval = ext_to_basis(record.export_eval);
    cols.lte_out_point = record.lte_out_point.map(ext_to_basis);
    cols.lte_rt_point = record.lte_rt_point.map(ext_to_basis);
    cols.lte_prefix_acc = record.lte_prefix_acc.map(ext_to_basis);
    cols.lte_less_acc = record.lte_less_acc.map(ext_to_basis);
    cols.lte_bits = record.lte_bits.map(F::from_bool);
    cols.lte_active = record.lte_active.map(F::from_bool);
    cols.quark_prefix_count = F::from_usize(record.quark_prefix_count);
    cols.quark_prefix_is_zero = F::from_bool(record.quark_prefix_count == 0);
    cols.quark_prefix_inv = if record.quark_prefix_count == 0 {
        F::ZERO
    } else {
        F::from_usize(record.quark_prefix_count).inverse()
    };
    cols.quark_layer_n = F::from_usize(record.quark_layer_n);
    cols.quark_parity = F::from_bool(record.quark_parity);
}

fn ext_to_basis(value: openvm_stark_sdk::config::baby_bear_poseidon2::EF) -> [F; D_EF] {
    value.as_basis_coefficients_slice().try_into().unwrap()
}

fn eq_factor<AB: AirBuilder>(a: [AB::Var; D_EF], b: [AB::Var; D_EF]) -> [AB::Expr; D_EF]
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    ext_field_add::<AB::Expr>(
        ext_field_multiply::<AB::Expr>(a.clone(), b.clone()),
        ext_field_multiply::<AB::Expr>(one_minus_ext::<AB>(a), one_minus_ext::<AB>(b)),
    )
}

fn one_minus_ext<AB: AirBuilder>(value: [AB::Var; D_EF]) -> [AB::Expr; D_EF] {
    ext_field_one_minus(value.map(Into::into))
}

fn choose_ext<AB: AirBuilder>(
    flag: AB::Var,
    when_one: [AB::Expr; D_EF],
    when_zero: [AB::Expr; D_EF],
) -> [AB::Expr; D_EF] {
    core::array::from_fn(|i| {
        flag.clone() * when_one[i].clone()
            + (AB::Expr::ONE - flag.clone()) * when_zero[i].clone()
    })
}

fn ext_zero<FA: PrimeCharacteristicRing>() -> [FA; D_EF] {
    core::array::from_fn(|_| FA::ZERO)
}

fn ext_one<FA: PrimeCharacteristicRing>() -> [FA; D_EF] {
    let mut out = ext_zero::<FA>();
    out[0] = FA::ONE;
    out
}

fn interpolate_cubic_at_0123<F, FA>(
    ev0: [FA; D_EF],
    ev1: [F; D_EF],
    ev2: [F; D_EF],
    ev3: [F; D_EF],
    x: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let three: FA = FA::from_usize(3);
    let inv2: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(2).inverse());
    let inv6: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(6).inverse());

    let s1: [FA; D_EF] = ext_field_subtract(ev1, ev0.clone());
    let s2: [FA; D_EF] = ext_field_subtract(ev2, ev0.clone());
    let s3: [FA; D_EF] = ext_field_subtract(ev3, ev0.clone());

    let d3: [FA; D_EF] = ext_field_subtract::<FA>(
        s3,
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2.clone(), s1.clone()), three),
    );
    let p: [FA; D_EF] = ext_field_multiply_scalar(d3.clone(), inv6);
    let q: [FA; D_EF] = ext_field_subtract::<FA>(
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2, d3), inv2),
        s1.clone(),
    );
    let r: [FA; D_EF] = ext_field_subtract::<FA>(s1, ext_field_add::<FA>(p.clone(), q.clone()));

    ext_field_add::<FA>(
        ext_field_multiply::<FA>(
            ext_field_add::<FA>(
                ext_field_multiply::<FA>(ext_field_add::<FA>(ext_field_multiply::<FA>(p, x), q), x),
                r,
            ),
            x,
        ),
        ev0,
    )
}
