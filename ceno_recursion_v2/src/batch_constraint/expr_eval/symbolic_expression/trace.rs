use core::cmp::min;
use std::borrow::BorrowMut;

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_backend::{
    air_builders::symbolic::{SymbolicExpressionNode, symbolic_variable::Entry},
    poly_common::{Squarable, eval_eq_uni_at_one},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use strum::EnumCount;

use crate::{
    batch_constraint::expr_eval::symbolic_expression::air::{
        CachedSymbolicExpressionColumns, ENCODER_MAX_DEGREE, NodeKind,
        SingleMainSymbolicExpressionColumns,
    },
    system::{Preflight, RecursionField, RecursionVk, convert_vk_from_zkvm},
    tracegen::RowMajorChip,
    utils::{MultiVecWithBounds, interaction_length},
};
use ceno_zkvm::structs::ComposedConstrainSystem;
use multilinear_extensions::{Expression, Fixed};

pub struct SymbolicExpressionTraceGenerator {
    pub max_num_proofs: usize,
}

pub struct SymbolicExpressionCtx<'a> {
    pub vk: &'a RecursionVk,
    pub preflights: &'a [&'a Preflight],
    pub expr_evals: &'a MultiVecWithBounds<EF, 2>,
}

impl RowMajorChip<F> for SymbolicExpressionTraceGenerator {
    type Ctx<'a> = SymbolicExpressionCtx<'a>;

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let child_vk = convert_vk_from_zkvm(ctx.vk);
        let child_vk = child_vk.as_ref();
        let preflights = ctx.preflights;
        let max_num_proofs = self.max_num_proofs;
        let expr_evals = ctx.expr_evals;
        let l_skip = child_vk.inner.params.l_skip;

        let single_main_width = SingleMainSymbolicExpressionColumns::<F>::width();
        let main_width = single_main_width * max_num_proofs;

        struct Record {
            args: [F; 2 * D_EF],
            sort_idx: usize,
            n_abs: usize,
            is_n_neg: usize,
        }
        let mut records = vec![];

        for (proof_idx, preflight) in preflights.iter().enumerate() {
            let rs = &preflight.batch_constraint.sumcheck_rnd;
            if rs.is_empty() {
                continue;
            }
            let (&rs_0, rs_rest) = rs.split_first().unwrap();
            let mut is_first_uni_by_log_height = vec![];
            let mut is_last_uni_by_log_height = vec![];

            for (log_height, &r_pow) in rs_0
                .exp_powers_of_2()
                .take(l_skip + 1)
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .enumerate()
            {
                is_first_uni_by_log_height.push(eval_eq_uni_at_one(log_height, r_pow));
                is_last_uni_by_log_height.push(eval_eq_uni_at_one(
                    log_height,
                    r_pow * F::two_adic_generator(log_height),
                ));
            }
            let mut is_first_mle_by_n = vec![EF::ONE];
            let mut is_last_mle_by_n = vec![EF::ONE];
            for (i, &r) in rs_rest.iter().enumerate() {
                is_first_mle_by_n.push(is_first_mle_by_n[i] * (EF::ONE - r));
                is_last_mle_by_n.push(is_last_mle_by_n[i] * r);
            }

            for (air_idx, vk) in child_vk.inner.per_air.iter().enumerate() {
                let constraints = &vk.symbolic_constraints.constraints;
                let expr_evals = &expr_evals[[proof_idx, air_idx]];

                if expr_evals.is_empty() {
                    let n = constraints.nodes.len()
                        + vk.symbolic_constraints
                            .interactions
                            .iter()
                            .map(interaction_length)
                            .sum::<usize>()
                        + vk.unused_variables.len();
                    records.resize_with(records.len() + n, || None);
                    continue;
                }

                let (sort_idx, trace_vdata) = preflight
                    .proof_shape
                    .sorted_trace_vdata
                    .iter()
                    .enumerate()
                    .find_map(|(sort_idx, (idx, vdata))| {
                        (*idx == air_idx).then_some((sort_idx, vdata))
                    })
                    .unwrap();

                let log_height = trace_vdata.log_height;
                let (n_abs, is_n_neg) = if log_height < l_skip {
                    (l_skip - log_height, 1)
                } else {
                    (log_height - l_skip, 0)
                };

                for (node_idx, node) in constraints.nodes.iter().enumerate() {
                    let mut record = Record {
                        args: [F::ZERO; 2 * D_EF],
                        sort_idx,
                        n_abs,
                        is_n_neg,
                    };
                    match node {
                        SymbolicExpressionNode::Variable(var) => match var.entry {
                            Entry::Preprocessed { .. } | Entry::Main { .. } | Entry::Public => {
                                record.args[..D_EF].copy_from_slice(
                                    expr_evals[node_idx].as_basis_coefficients_slice(),
                                );
                            }
                            Entry::Permutation { .. } => unreachable!(),
                            Entry::Challenge | Entry::Exposed => unreachable!(),
                        },
                        SymbolicExpressionNode::IsFirstRow => {
                            record.args[..D_EF].copy_from_slice(
                                is_first_uni_by_log_height[min(log_height, l_skip)]
                                    .as_basis_coefficients_slice(),
                            );
                            record.args[D_EF..2 * D_EF].copy_from_slice(
                                is_first_mle_by_n[log_height.saturating_sub(l_skip)]
                                    .as_basis_coefficients_slice(),
                            );
                        }
                        SymbolicExpressionNode::IsLastRow
                        | SymbolicExpressionNode::IsTransition => {
                            record.args[..D_EF].copy_from_slice(
                                is_last_uni_by_log_height[min(log_height, l_skip)]
                                    .as_basis_coefficients_slice(),
                            );
                            record.args[D_EF..2 * D_EF].copy_from_slice(
                                is_last_mle_by_n[log_height.saturating_sub(l_skip)]
                                    .as_basis_coefficients_slice(),
                            );
                        }
                        SymbolicExpressionNode::Constant(_) => {}
                        SymbolicExpressionNode::Add {
                            left_idx,
                            right_idx,
                            ..
                        }
                        | SymbolicExpressionNode::Sub {
                            left_idx,
                            right_idx,
                            ..
                        }
                        | SymbolicExpressionNode::Mul {
                            left_idx,
                            right_idx,
                            ..
                        } => {
                            record.args[..D_EF].copy_from_slice(
                                expr_evals[*left_idx].as_basis_coefficients_slice(),
                            );
                            record.args[D_EF..2 * D_EF].copy_from_slice(
                                expr_evals[*right_idx].as_basis_coefficients_slice(),
                            );
                        }
                        SymbolicExpressionNode::Neg { idx, .. } => {
                            record.args[..D_EF]
                                .copy_from_slice(expr_evals[*idx].as_basis_coefficients_slice());
                        }
                    };
                    records.push(Some(record));
                }
                for interaction in &vk.symbolic_constraints.interactions {
                    let mut args = [F::ZERO; 2 * D_EF];
                    args[..D_EF].copy_from_slice(
                        expr_evals[interaction.count].as_basis_coefficients_slice(),
                    );
                    records.push(Some(Record {
                        args,
                        sort_idx,
                        n_abs,
                        is_n_neg,
                    }));

                    for &node_idx in &interaction.message {
                        let mut args = [F::ZERO; 2 * D_EF];
                        args[..D_EF]
                            .copy_from_slice(expr_evals[node_idx].as_basis_coefficients_slice());
                        records.push(Some(Record {
                            args,
                            sort_idx,
                            n_abs,
                            is_n_neg,
                        }));
                    }

                    args.fill(F::ZERO);
                    args[0] = F::from_u16(interaction.bus_index + 1);
                    records.push(Some(Record {
                        args,
                        sort_idx,
                        n_abs,
                        is_n_neg,
                    }));
                }

                let mut node_idx = constraints.nodes.len();
                for unused_var in &vk.unused_variables {
                    if matches!(
                        unused_var.entry,
                        Entry::Permutation { .. }
                            | Entry::Public
                            | Entry::Challenge
                            | Entry::Exposed
                    ) {
                        continue;
                    }
                    let mut args = [F::ZERO; 2 * D_EF];
                    args[..D_EF]
                        .copy_from_slice(expr_evals[node_idx].as_basis_coefficients_slice());
                    records.push(Some(Record {
                        args,
                        sort_idx,
                        n_abs,
                        is_n_neg,
                    }));
                    node_idx += 1;
                }
            }
        }

        let num_valid_rows = records.len() / preflights.len();
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.max(1).next_power_of_two()
        };
        let mut main_trace = F::zero_vec(main_width * height);
        main_trace
            .par_chunks_exact_mut(main_width)
            .enumerate()
            .for_each(|(row_idx, row)| {
                if row_idx >= num_valid_rows {
                    return;
                }
                for proof_idx in 0..max_num_proofs {
                    if proof_idx >= preflights.len() {
                        continue;
                    }
                    let record_idx = proof_idx * num_valid_rows + row_idx;
                    let Some(record) = records[record_idx].as_ref() else {
                        continue;
                    };
                    let start = proof_idx * single_main_width;
                    let end = start + single_main_width;
                    let cols: &mut SingleMainSymbolicExpressionColumns<_> =
                        row[start..end].borrow_mut();
                    cols.slot_state = F::from_u8(2);
                    cols.args = record.args;
                    cols.sort_idx = F::from_usize(record.sort_idx);
                    cols.n_abs = F::from_usize(record.n_abs);
                    cols.is_n_neg = F::from_usize(record.is_n_neg);
                }
            });

        Some(RowMajorMatrix::new(main_trace, main_width))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CachedRecord {
    pub kind: NodeKind,
    pub air_idx: usize,
    pub node_idx: usize,
    pub attrs: [usize; 3],
    pub is_constraint: bool,
    pub constraint_idx: usize,
    pub fanout: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CachedTraceRecord {
    pub records: Vec<CachedRecord>,
}

pub fn build_cached_trace_record(child_vk: &RecursionVk) -> CachedTraceRecord {
    let mut records = Vec::new();
    for (&air_idx, circuit_name) in &child_vk.circuit_index_to_name {
        let Some(circuit_vk) = child_vk.circuit_vks.get(circuit_name) else {
            continue;
        };
        let Some(gkr) = circuit_vk.cs.gkr_circuit.as_ref() else {
            continue;
        };
        let Some(layer) = gkr.layers.first() else {
            continue;
        };
        let counts = Counts::from_css(&circuit_vk.cs);
        let offsets = Offsets::new(&counts);
        let mut builder = AirBuilder::new(&mut records, air_idx);
        push_base_nodes(&mut builder, &counts, &offsets);
        for (constraint_idx, expr) in layer.exprs.iter().enumerate() {
            let root_idx = build_expression_nodes(expr, &mut builder, &offsets);
            builder.mark_constraint(root_idx, constraint_idx);
        }
    }

    CachedTraceRecord { records }
}

fn push_base_nodes(builder: &mut AirBuilder<'_>, counts: &Counts, offsets: &Offsets) {
    for local in 0..counts.num_witin {
        let global = offsets.witin + local;
        builder.push(NodeKind::WitIn, [global, local, 0]);
    }
    for local in 0..counts.num_structural_witin {
        let global = offsets.structural + local;
        builder.push(NodeKind::StructuralWitIn, [global, local, 0]);
    }
    for local in 0..counts.num_fixed {
        let global = offsets.fixed + local;
        builder.push(NodeKind::Fixed, [global, local, 0]);
    }
    for local in 0..counts.num_instance {
        let global = offsets.instance + local;
        builder.push(NodeKind::Instance, [global, local, 0]);
    }
}

struct Counts {
    num_witin: usize,
    num_structural_witin: usize,
    num_fixed: usize,
    num_instance: usize,
}

impl Counts {
    fn from_css<E: ff_ext::ExtensionField>(cs: &ComposedConstrainSystem<E>) -> Self {
        let css = &cs.zkvm_v1_css;
        Self {
            num_witin: css.num_witin as usize,
            num_structural_witin: css.num_structural_witin as usize,
            num_fixed: css.num_fixed,
            num_instance: css.instance_openings.len(),
        }
    }
}

struct Offsets {
    witin: usize,
    structural: usize,
    fixed: usize,
    instance: usize,
}

impl Offsets {
    fn new(counts: &Counts) -> Self {
        let witin = 0;
        let structural = witin + counts.num_witin;
        let fixed = structural + counts.num_structural_witin;
        let instance = fixed + counts.num_fixed;
        Self {
            witin,
            structural,
            fixed,
            instance,
        }
    }
}

struct AirBuilder<'a> {
    records: &'a mut Vec<CachedRecord>,
    air_idx: usize,
    air_start: usize,
    next_local_idx: usize,
}

impl<'a> AirBuilder<'a> {
    fn new(records: &'a mut Vec<CachedRecord>, air_idx: usize) -> Self {
        let air_start = records.len();
        Self {
            records,
            air_idx,
            air_start,
            next_local_idx: 0,
        }
    }

    fn push(&mut self, kind: NodeKind, attrs: [usize; 3]) -> usize {
        let node_idx = self.next_local_idx;
        self.next_local_idx += 1;
        self.records.push(CachedRecord {
            kind,
            air_idx: self.air_idx,
            node_idx,
            attrs,
            is_constraint: false,
            constraint_idx: 0,
            fanout: 0,
        });
        node_idx
    }

    fn bump_fanout(&mut self, local_idx: usize) {
        let global_idx = self.air_start + local_idx;
        if let Some(record) = self.records.get_mut(global_idx) {
            record.fanout = record.fanout.saturating_add(1);
        }
    }

    fn mark_constraint(&mut self, local_idx: usize, constraint_idx: usize) {
        let global_idx = self.air_start + local_idx;
        if let Some(record) = self.records.get_mut(global_idx) {
            record.is_constraint = true;
            record.constraint_idx = constraint_idx;
        }
    }
}

fn build_expression_nodes(
    expr: &Expression<RecursionField>,
    builder: &mut AirBuilder<'_>,
    offsets: &Offsets,
) -> usize {
    match expr {
        Expression::WitIn(id) => offsets.witin + (*id as usize),
        Expression::StructuralWitIn(id, _) => offsets.structural + (*id as usize),
        Expression::Fixed(Fixed(idx)) => offsets.fixed + *idx,
        Expression::Instance(instance) | Expression::InstanceScalar(instance) => {
            offsets.instance + instance.0
        }
        Expression::Constant(_) => builder.push(NodeKind::Constant, [0, 0, 0]),
        Expression::Challenge(ch_id, pow, _, _) => {
            builder.push(NodeKind::Constant, [*ch_id as usize, *pow, 1])
        }
        Expression::Sum(left, right) => {
            let left_idx = build_expression_nodes(left, builder, offsets);
            let right_idx = build_expression_nodes(right, builder, offsets);
            builder.bump_fanout(left_idx);
            builder.bump_fanout(right_idx);
            builder.push(NodeKind::Add, [left_idx, right_idx, 0])
        }
        Expression::Product(left, right) => {
            let left_idx = build_expression_nodes(left, builder, offsets);
            let right_idx = build_expression_nodes(right, builder, offsets);
            builder.bump_fanout(left_idx);
            builder.bump_fanout(right_idx);
            builder.push(NodeKind::Mul, [left_idx, right_idx, 0])
        }
        Expression::ScaledSum(x, a, b) => {
            let mul_left = build_expression_nodes(a, builder, offsets);
            let mul_right = build_expression_nodes(x, builder, offsets);
            builder.bump_fanout(mul_left);
            builder.bump_fanout(mul_right);
            let mul_idx = builder.push(NodeKind::Mul, [mul_left, mul_right, 0]);
            let b_idx = build_expression_nodes(b, builder, offsets);
            builder.bump_fanout(mul_idx);
            builder.bump_fanout(b_idx);
            builder.push(NodeKind::Add, [mul_idx, b_idx, 0])
        }
    }
}

pub fn generate_symbolic_expr_cached_trace(
    cached_trace_record: &CachedTraceRecord,
) -> RowMajorMatrix<F> {
    let encoder = Encoder::new(NodeKind::COUNT, ENCODER_MAX_DEGREE, true);
    let cached_width = CachedSymbolicExpressionColumns::<F>::width();
    let records = &cached_trace_record.records;

    let height = records.len().next_power_of_two();
    let mut cached_trace = F::zero_vec(cached_width * height);
    cached_trace
        .par_chunks_exact_mut(cached_width)
        .zip(records)
        .for_each(|(row, record)| {
            let cols: &mut CachedSymbolicExpressionColumns<_> = row.borrow_mut();

            for (i, x) in encoder
                .get_flag_pt(record.kind as usize)
                .into_iter()
                .enumerate()
            {
                cols.flags[i] = F::from_u32(x);
            }
            cols.air_idx = F::from_usize(record.air_idx);
            cols.node_or_interaction_idx = F::from_usize(record.node_idx);
            cols.attrs = record.attrs.map(F::from_usize);
            cols.is_constraint = F::from_bool(record.is_constraint);
            cols.constraint_idx = F::from_usize(record.constraint_idx);
            cols.fanout = F::from_usize(record.fanout);
        });

    RowMajorMatrix::new(cached_trace, cached_width)
}
