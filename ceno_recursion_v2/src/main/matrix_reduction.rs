use core::borrow::{Borrow, BorrowMut};

use ceno_zkvm::scheme::matrix_reduction::MATRIX_REDUCTION_SCALE;
use ff_ext::ExtensionField;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        ForkedTranscriptBus, ForkedTranscriptBusMessage, MatrixReductionPresenceBus,
        MatrixReductionPresenceMessage, MatrixReductionValueBus, MatrixReductionValueMessage,
    },
    system::{Preflight, RecursionField, RecursionProof},
    tracegen::RowMajorChip,
    utils::{ext_field_add, ext_field_multiply, ext_field_one_minus, ext_field_subtract},
};

pub(crate) const OUTPUT_POINT: usize = 0;
pub(crate) const OUTPUT_EVAL: usize = 1;
pub(crate) const SUMCHECK_CHALLENGE: usize = 2;
const SUMCHECK_EVAL: usize = 3;
pub(crate) const FINAL_EVAL: usize = 4;

#[derive(Clone)]
pub struct MatrixValueRecord {
    pub(super) proof_idx: usize,
    pub(super) air_idx: usize,
    pub(super) fork_id: usize,
    pub(super) kind: usize,
    pub(super) idx: usize,
    pub(super) tidx: usize,
    pub(super) is_sample: bool,
    pub(super) lookup_count: usize,
    value: RecursionField,
}

#[derive(Clone)]
pub struct MatrixRoundRecord {
    pub(super) proof_idx: usize,
    pub(super) air_idx: usize,
    fork_id: usize,
    log_height: usize,
    final_sample_tidx: usize,
    output_point_tidx: usize,
    output_eval_tidx: usize,
    final_eval_tidx: usize,
    pub(super) round_idx: usize,
    num_rounds: usize,
    eval_tidx: usize,
    challenge_tidx: usize,
    evaluations: [RecursionField; 3],
    challenge: RecursionField,
    claim_in: RecursionField,
    claim_out: RecursionField,
    eq_target: RecursionField,
    eq_in: RecursionField,
    eq_out: RecursionField,
    output_evals: [RecursionField; 2],
    final_evals: [RecursionField; 2],
}

pub fn collect_records(
    _proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> (Vec<MatrixValueRecord>, Vec<MatrixRoundRecord>) {
    let mut values = Vec::new();
    let mut rounds = Vec::new();
    for (proof_idx, preflight) in preflights.iter().enumerate() {
        for claims in preflight
            .gkr
            .chips
            .iter()
            .filter_map(|chip| chip.matrix_reduction_replay.as_ref())
        {
            for (idx, value) in claims.output_point.iter().copied().enumerate() {
                values.push(MatrixValueRecord {
                    proof_idx,
                    air_idx: claims.air_idx,
                    fork_id: claims.fork_id,
                    kind: OUTPUT_POINT,
                    idx,
                    tidx: claims.output_point_tidx + idx * D_EF,
                    is_sample: true,
                    lookup_count: 2,
                    value,
                });
            }
            for (idx, value) in claims.output_evals.iter().copied().enumerate() {
                values.push(MatrixValueRecord {
                    proof_idx,
                    air_idx: claims.air_idx,
                    fork_id: claims.fork_id,
                    kind: OUTPUT_EVAL,
                    idx,
                    tidx: claims.output_eval_tidx + idx * D_EF,
                    is_sample: false,
                    lookup_count: 2,
                    value,
                });
            }
            for round in &claims.rounds {
                values.push(MatrixValueRecord {
                    proof_idx,
                    air_idx: claims.air_idx,
                    fork_id: claims.fork_id,
                    kind: SUMCHECK_CHALLENGE,
                    idx: round.round_idx,
                    tidx: round.challenge_tidx,
                    is_sample: true,
                    lookup_count: 3,
                    value: round.challenge,
                });
                for (eval_idx, value) in round.evaluations.iter().copied().enumerate() {
                    values.push(MatrixValueRecord {
                        proof_idx,
                        air_idx: claims.air_idx,
                        fork_id: claims.fork_id,
                        kind: SUMCHECK_EVAL,
                        idx: round.round_idx * 3 + eval_idx,
                        tidx: round.eval_tidx + eval_idx * D_EF,
                        is_sample: false,
                        lookup_count: 1,
                        value,
                    });
                }
                rounds.push(MatrixRoundRecord {
                    proof_idx,
                    air_idx: claims.air_idx,
                    fork_id: claims.fork_id,
                    log_height: claims.log_height,
                    final_sample_tidx: claims.final_sample_tidx,
                    output_point_tidx: claims.output_point_tidx,
                    output_eval_tidx: claims.output_eval_tidx,
                    final_eval_tidx: claims.final_eval_tidx,
                    round_idx: round.round_idx,
                    num_rounds: claims.rounds.len(),
                    eval_tidx: round.eval_tidx,
                    challenge_tidx: round.challenge_tidx,
                    evaluations: round.evaluations,
                    challenge: round.challenge,
                    claim_in: round.claim_in,
                    claim_out: round.claim_out,
                    eq_target: if round.round_idx == 0 {
                        RecursionField::ZERO
                    } else {
                        claims.output_point[round.round_idx + 1]
                    },
                    eq_in: round.eq_in,
                    eq_out: round.eq_out,
                    output_evals: claims.output_evals,
                    final_evals: claims.final_evals,
                });
            }
            for (idx, value) in claims.final_evals.iter().copied().enumerate() {
                values.push(MatrixValueRecord {
                    proof_idx,
                    air_idx: claims.air_idx,
                    fork_id: claims.fork_id,
                    kind: FINAL_EVAL,
                    idx,
                    tidx: claims.final_eval_tidx + idx * D_EF,
                    is_sample: false,
                    lookup_count: 2,
                    value,
                });
            }
        }
    }
    (values, rounds)
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MatrixValueCols<T> {
    is_enabled: T,
    proof_idx: T,
    air_idx: T,
    fork_id: T,
    kind: T,
    idx: T,
    tidx: T,
    is_sample: T,
    lookup_count: T,
    kind_flags: [T; 5],
    value: [T; D_EF],
}

pub struct MatrixValueAir {
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub value_bus: MatrixReductionValueBus,
}

impl<F: Field> BaseAir<F> for MatrixValueAir {
    fn width(&self) -> usize {
        MatrixValueCols::<F>::width()
    }
}
impl<F: Field> BaseAirWithPublicValues<F> for MatrixValueAir {}
impl<F: Field> PartitionedBaseAir<F> for MatrixValueAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MatrixValueAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("main row exists");
        let local: &MatrixValueCols<AB::Var> = (*row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_sample);
        let mut kind_sum = AB::Expr::ZERO;
        let mut kind = AB::Expr::ZERO;
        let mut lookup_count = AB::Expr::ZERO;
        for (kind_idx, flag) in local.kind_flags.iter().enumerate() {
            builder.assert_bool(*flag);
            kind_sum += *flag;
            kind += *flag * AB::Expr::from_usize(kind_idx);
            lookup_count += *flag
                * AB::Expr::from_usize(match kind_idx {
                    OUTPUT_POINT | OUTPUT_EVAL | FINAL_EVAL => 2,
                    SUMCHECK_CHALLENGE => 3,
                    SUMCHECK_EVAL => 1,
                    _ => unreachable!(),
                });
        }
        builder.assert_eq(local.is_enabled, kind_sum);
        builder.when(local.is_enabled).assert_eq(local.kind, kind);
        builder
            .when(local.is_enabled)
            .assert_eq(local.lookup_count, lookup_count);
        builder.when(local.is_enabled).assert_eq(
            local.is_sample,
            local.kind_flags[OUTPUT_POINT] + local.kind_flags[SUMCHECK_CHALLENGE],
        );
        for limb in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(limb),
                    value: local.value[limb].into(),
                    is_sample: local.is_sample.into(),
                },
                local.is_enabled,
            );
        }
        self.value_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: local.kind.into(),
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MatrixRoundCols<T> {
    is_enabled: T,
    proof_idx: T,
    air_idx: T,
    fork_id: T,
    log_height: T,
    final_sample_tidx: T,
    output_point_tidx: T,
    output_eval_tidx: T,
    final_eval_tidx: T,
    round_idx: T,
    num_rounds: T,
    is_first: T,
    is_last: T,
    eval_tidx: T,
    challenge_tidx: T,
    evaluations: [[T; D_EF]; 3],
    challenge: [T; D_EF],
    claim_in: [T; D_EF],
    claim_out: [T; D_EF],
    eq_target: [T; D_EF],
    eq_in: [T; D_EF],
    eq_out: [T; D_EF],
    output_evals: [[T; D_EF]; 2],
    final_evals: [[T; D_EF]; 2],
}

pub struct MatrixRoundAir {
    pub presence_bus: MatrixReductionPresenceBus,
    pub value_bus: MatrixReductionValueBus,
}
impl<F: Field> BaseAir<F> for MatrixRoundAir {
    fn width(&self) -> usize {
        MatrixRoundCols::<F>::width()
    }
}
impl<F: Field> BaseAirWithPublicValues<F> for MatrixRoundAir {}
impl<F: Field> PartitionedBaseAir<F> for MatrixRoundAir {}

impl<AB> Air<AB> for MatrixRoundAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("row");
        let next_row = main.row_slice(1).expect("next row");
        let local: &MatrixRoundCols<AB::Var> = (*local_row).borrow();
        let next: &MatrixRoundCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder
            .when_transition()
            .when_ne(local.is_enabled, AB::Expr::ONE)
            .assert_zero(next.is_enabled);
        let computed_is_last = local.is_enabled - next.is_enabled + next.is_first;
        builder
            .when(local.is_enabled)
            .assert_eq(local.is_last, computed_is_last);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.round_idx);
        builder
            .when(local.is_enabled * local.is_last)
            .assert_eq(local.round_idx + AB::Expr::ONE, local.num_rounds);
        builder
            .when(local.is_enabled)
            .assert_eq(local.log_height, local.num_rounds + AB::Expr::ONE);
        self.presence_bus.receive(
            builder,
            local.proof_idx,
            MatrixReductionPresenceMessage {
                air_idx: local.air_idx.into(),
                fork_id: local.fork_id.into(),
                log_height: local.log_height.into(),
                final_sample_tidx: local.final_sample_tidx.into(),
            },
            local.is_enabled * local.is_first,
        );
        for i in 0..3 {
            self.value_bus.lookup_key(
                builder,
                local.proof_idx,
                MatrixReductionValueMessage {
                    air_idx: local.air_idx.into(),
                    kind: AB::Expr::from_usize(SUMCHECK_EVAL),
                    idx: local.round_idx * AB::Expr::from_usize(3) + AB::Expr::from_usize(i),
                    tidx: local.eval_tidx + AB::Expr::from_usize(i * D_EF),
                    value: local.evaluations[i].map(Into::into),
                },
                local.is_enabled,
            );
        }
        self.value_bus.lookup_key(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: AB::Expr::from_usize(SUMCHECK_CHALLENGE),
                idx: local.round_idx.into(),
                tidx: local.challenge_tidx.into(),
                value: local.challenge.map(Into::into),
            },
            local.is_enabled,
        );
        self.value_bus.lookup_key(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: AB::Expr::from_usize(OUTPUT_EVAL),
                idx: AB::Expr::ZERO,
                tidx: local.output_eval_tidx.into(),
                value: local.output_evals[0].map(Into::into),
            },
            local.is_enabled * local.is_first,
        );
        self.value_bus.lookup_key(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: AB::Expr::from_usize(OUTPUT_EVAL),
                idx: AB::Expr::ONE,
                tidx: local.output_eval_tidx + AB::Expr::from_usize(D_EF),
                value: local.output_evals[1].map(Into::into),
            },
            local.is_enabled * local.is_first,
        );
        self.value_bus.lookup_key(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: AB::Expr::from_usize(OUTPUT_POINT),
                idx: local.round_idx + AB::Expr::ONE,
                tidx: local.output_point_tidx
                    + (local.round_idx + AB::Expr::ONE) * AB::Expr::from_usize(D_EF),
                value: local.eq_target.map(Into::into),
            },
            local.is_enabled * (AB::Expr::ONE - local.is_first),
        );
        for i in 0..2 {
            self.value_bus.lookup_key(
                builder,
                local.proof_idx,
                MatrixReductionValueMessage {
                    air_idx: local.air_idx.into(),
                    kind: AB::Expr::from_usize(FINAL_EVAL),
                    idx: AB::Expr::from_usize(i),
                    tidx: local.final_eval_tidx + AB::Expr::from_usize(i * D_EF),
                    value: local.final_evals[i].map(Into::into),
                },
                local.is_enabled * local.is_last,
            );
        }
        let eval0: [AB::Expr; D_EF] = ext_field_subtract(local.claim_in, local.evaluations[0]);
        let r: [AB::Expr; D_EF] = local.challenge.map(Into::into);
        let rm1: [AB::Expr; D_EF] = ext_field_subtract(
            r.clone(),
            [
                AB::Expr::ONE,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
        );
        let rm2: [AB::Expr; D_EF] = ext_field_subtract(
            r.clone(),
            [
                AB::Expr::from_usize(2),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
        );
        let rm3: [AB::Expr; D_EF] = ext_field_subtract(
            r.clone(),
            [
                AB::Expr::from_usize(3),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
        );
        let inv2 = AB::F::from_u64(2).inverse();
        let inv6 = AB::F::from_u64(6).inverse();
        let scale = |x: [AB::Expr; D_EF], c: AB::F| x.map(|v| v * c);
        let l0: [AB::Expr; D_EF] = scale(
            ext_field_multiply::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(rm1.clone(), rm2.clone()),
                rm3.clone(),
            ),
            -inv6,
        );
        let l1: [AB::Expr; D_EF] = scale(
            ext_field_multiply::<AB::Expr>(ext_field_multiply::<AB::Expr>(r.clone(), rm2), rm3),
            inv2,
        );
        let l2: [AB::Expr; D_EF] = scale(
            ext_field_multiply::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(r.clone(), rm1.clone()),
                ext_field_subtract::<AB::Expr>(
                    r.clone(),
                    [
                        AB::Expr::from_usize(3),
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                    ],
                ),
            ),
            -inv2,
        );
        let l3: [AB::Expr; D_EF] = scale(
            ext_field_multiply::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(r, rm1),
                ext_field_subtract::<AB::Expr>(
                    local.challenge.map(Into::into),
                    [
                        AB::Expr::from_usize(2),
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                    ],
                ),
            ),
            inv6,
        );
        let folded: [AB::Expr; D_EF] = ext_field_add::<AB::Expr>(
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(eval0, l0),
                ext_field_multiply::<AB::Expr>(local.evaluations[0], l1),
            ),
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.evaluations[1], l2),
                ext_field_multiply::<AB::Expr>(local.evaluations[2], l3),
            ),
        );
        for i in 0..D_EF {
            builder
                .when(local.is_enabled)
                .assert_eq(local.claim_out[i], folded[i].clone());
        }
        let eq_term: [AB::Expr; D_EF] = ext_field_add::<AB::Expr>(
            ext_field_multiply::<AB::Expr>(local.eq_target, local.challenge),
            ext_field_multiply::<AB::Expr>(
                ext_field_one_minus::<AB::Expr>(local.eq_target),
                ext_field_one_minus::<AB::Expr>(local.challenge),
            ),
        );
        let expected_eq: [AB::Expr; D_EF] = ext_field_multiply(local.eq_in, eq_term);
        for i in 0..D_EF {
            builder
                .when(local.is_enabled * local.is_first)
                .assert_eq(local.eq_in[i], AB::Expr::from_bool(i == 0));
            builder
                .when(local.is_enabled * local.is_first)
                .assert_eq(local.eq_out[i], local.eq_in[i]);
            builder
                .when(local.is_enabled * (AB::Expr::ONE - local.is_first))
                .assert_eq(local.eq_out[i], expected_eq[i].clone());
        }
        let first_claim: [AB::Expr; D_EF] = ext_field_add(
            local.output_evals[0].map(|v: AB::Var| {
                Into::<AB::Expr>::into(v) * AB::Expr::from_u64(MATRIX_REDUCTION_SCALE)
            }),
            local.output_evals[1],
        );
        for i in 0..D_EF {
            builder
                .when(local.is_enabled * local.is_first)
                .assert_eq(local.claim_in[i], first_claim[i].clone());
        }
        let final_claim: [AB::Expr; D_EF] = ext_field_multiply(
            ext_field_multiply(local.final_evals[0], local.final_evals[1]),
            local.eq_out,
        );
        for i in 0..D_EF {
            builder
                .when(local.is_enabled * local.is_last)
                .assert_eq(local.claim_out[i], final_claim[i].clone());
        }
        builder.when(local.is_enabled * local.is_first).assert_eq(
            local.output_eval_tidx,
            local.output_point_tidx
                + (local.num_rounds + AB::Expr::ONE) * AB::Expr::from_usize(D_EF),
        );
        builder.when(local.is_enabled * local.is_first).assert_eq(
            local.eval_tidx,
            local.output_eval_tidx + AB::Expr::from_usize(2 * D_EF + 4),
        );
        builder.when(local.is_enabled).assert_eq(
            local.challenge_tidx,
            local.eval_tidx + AB::Expr::from_usize(3 * D_EF + 4),
        );
        builder.when(local.is_enabled * local.is_last).assert_eq(
            local.final_eval_tidx,
            local.challenge_tidx + AB::Expr::from_usize(D_EF),
        );
        builder.when(local.is_enabled * local.is_last).assert_eq(
            local.final_sample_tidx,
            local.final_eval_tidx + AB::Expr::from_usize(2 * D_EF),
        );
        let transition = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder.when(transition.clone()).assert_one(next.is_enabled);
        builder.when(transition.clone()).assert_zero(next.is_first);
        builder
            .when(transition.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when(transition.clone())
            .assert_eq(next.air_idx, local.air_idx);
        builder
            .when(transition.clone())
            .assert_eq(next.fork_id, local.fork_id);
        builder
            .when(transition.clone())
            .assert_eq(next.log_height, local.log_height);
        builder
            .when(transition.clone())
            .assert_eq(next.num_rounds, local.num_rounds);
        builder
            .when(transition.clone())
            .assert_eq(next.final_sample_tidx, local.final_sample_tidx);
        builder
            .when(transition.clone())
            .assert_eq(next.output_point_tidx, local.output_point_tidx);
        builder
            .when(transition.clone())
            .assert_eq(next.output_eval_tidx, local.output_eval_tidx);
        builder
            .when(transition.clone())
            .assert_eq(next.final_eval_tidx, local.final_eval_tidx);
        builder
            .when(transition.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        builder.when(transition.clone()).assert_eq(
            next.eval_tidx,
            local.challenge_tidx + AB::Expr::from_usize(D_EF),
        );
        for i in 0..D_EF {
            builder
                .when(transition.clone())
                .assert_eq(next.claim_in[i], local.claim_out[i]);
            builder
                .when(transition.clone())
                .assert_eq(next.eq_in[i], local.eq_out[i]);
            for eval_idx in 0..2 {
                builder.when(transition.clone()).assert_eq(
                    next.output_evals[eval_idx][i],
                    local.output_evals[eval_idx][i],
                );
                builder.when(transition.clone()).assert_eq(
                    next.final_evals[eval_idx][i],
                    local.final_evals[eval_idx][i],
                );
            }
        }
    }
}

fn trace_height(len: usize, required: Option<usize>) -> Option<usize> {
    let valid = len.max(1);
    required.map_or_else(
        || Some(valid.next_power_of_two()),
        |h| (h >= valid).then_some(h),
    )
}

pub struct MatrixValueTraceGenerator;
impl RowMajorChip<F> for MatrixValueTraceGenerator {
    type Ctx<'a> = &'a [MatrixValueRecord];
    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let w = MatrixValueCols::<F>::width();
        let h = trace_height(records.len(), required)?;
        let mut t = vec![F::ZERO; h * w];
        for (row, r) in t.chunks_exact_mut(w).zip((*records).iter()) {
            let c: &mut MatrixValueCols<F> = row.borrow_mut();
            c.is_enabled = F::ONE;
            c.proof_idx = F::from_usize(r.proof_idx);
            c.air_idx = F::from_usize(r.air_idx);
            c.fork_id = F::from_usize(r.fork_id);
            c.kind = F::from_usize(r.kind);
            c.idx = F::from_usize(r.idx);
            c.tidx = F::from_usize(r.tidx);
            c.is_sample = F::from_bool(r.is_sample);
            c.lookup_count = F::from_usize(r.lookup_count);
            c.kind_flags[r.kind] = F::ONE;
            c.value = r.value.as_bases().try_into().unwrap();
        }
        Some(RowMajorMatrix::new(t, w))
    }
}
pub struct MatrixRoundTraceGenerator;
impl RowMajorChip<F> for MatrixRoundTraceGenerator {
    type Ctx<'a> = &'a [MatrixRoundRecord];
    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let w = MatrixRoundCols::<F>::width();
        let h = trace_height(records.len(), required)?;
        let mut t = vec![F::ZERO; h * w];
        for (row, r) in t.chunks_exact_mut(w).zip((*records).iter()) {
            let c: &mut MatrixRoundCols<F> = row.borrow_mut();
            c.is_enabled = F::ONE;
            c.proof_idx = F::from_usize(r.proof_idx);
            c.air_idx = F::from_usize(r.air_idx);
            c.fork_id = F::from_usize(r.fork_id);
            c.log_height = F::from_usize(r.log_height);
            c.final_sample_tidx = F::from_usize(r.final_sample_tidx);
            c.output_point_tidx = F::from_usize(r.output_point_tidx);
            c.output_eval_tidx = F::from_usize(r.output_eval_tidx);
            c.final_eval_tidx = F::from_usize(r.final_eval_tidx);
            c.round_idx = F::from_usize(r.round_idx);
            c.num_rounds = F::from_usize(r.num_rounds);
            c.is_first = F::from_bool(r.round_idx == 0);
            c.is_last = F::from_bool(r.round_idx + 1 == r.num_rounds);
            c.eval_tidx = F::from_usize(r.eval_tidx);
            c.challenge_tidx = F::from_usize(r.challenge_tidx);
            c.evaluations = r
                .evaluations
                .map(|x: RecursionField| -> [F; D_EF] { x.as_bases().try_into().unwrap() });
            c.challenge = r.challenge.as_bases().try_into().unwrap();
            c.claim_in = r.claim_in.as_bases().try_into().unwrap();
            c.claim_out = r.claim_out.as_bases().try_into().unwrap();
            c.eq_target = r.eq_target.as_bases().try_into().unwrap();
            c.eq_in = r.eq_in.as_bases().try_into().unwrap();
            c.eq_out = r.eq_out.as_bases().try_into().unwrap();
            c.output_evals = r
                .output_evals
                .map(|x: RecursionField| -> [F; D_EF] { x.as_bases().try_into().unwrap() });
            c.final_evals = r
                .final_evals
                .map(|x: RecursionField| -> [F; D_EF] { x.as_bases().try_into().unwrap() });
        }
        Some(RowMajorMatrix::new(t, w))
    }
}
