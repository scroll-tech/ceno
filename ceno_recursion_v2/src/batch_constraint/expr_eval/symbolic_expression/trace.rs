use core::{cmp::min, iter::zip};
use std::borrow::BorrowMut;

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_backend::{
    air_builders::symbolic::{symbolic_variable::Entry, SymbolicExpressionNode},
    keygen::types::MultiStarkVerifyingKey,
    poly_common::{eval_eq_uni_at_one, Squarable},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use strum::EnumCount;

use crate::{
    batch_constraint::expr_eval::symbolic_expression::air::{
        CachedSymbolicExpressionColumns, NodeKind, SingleMainSymbolicExpressionColumns,
        ENCODER_MAX_DEGREE,
    },
    system::Preflight,
    tracegen::RowMajorChip,
    utils::{interaction_length, MultiVecWithBounds},
};

pub struct SymbolicExpressionTraceGenerator {
    pub max_num_proofs: usize,
}

pub struct SymbolicExpressionCtx<'a> {
    pub vk: &'a MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
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
        let child_vk = ctx.vk;
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
                    if matches!(unused_var.entry, Entry::Permutation { .. } | Entry::Public | Entry::Challenge | Entry::Exposed) {
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

pub fn build_cached_trace_record(
    child_vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
) -> CachedTraceRecord {
    let mut fanout_per_air = Vec::with_capacity(child_vk.inner.per_air.len());
    for vk in &child_vk.inner.per_air {
        let nodes = &vk.symbolic_constraints.constraints.nodes;
        let mut fanout = vec![0usize; nodes.len()];
        for node in nodes.iter() {
            match node {
                SymbolicExpressionNode::Add { left_idx, right_idx, .. }
                | SymbolicExpressionNode::Sub { left_idx, right_idx, .. }
                | SymbolicExpressionNode::Mul { left_idx, right_idx, .. } => {
                    fanout[*left_idx] += 1;
                    fanout[*right_idx] += 1;
                }
                SymbolicExpressionNode::Neg { idx, .. } => fanout[*idx] += 1,
                _ => {}
            }
        }
        for interaction in vk.symbolic_constraints.interactions.iter() {
            fanout[interaction.count] += 1;
            for &node_idx in &interaction.message {
                fanout[node_idx] += 1;
            }
        }
        fanout_per_air.push(fanout);
    }

    let mut records = vec![];
    for (air_idx, (vk, fanout_per_node)) in
        zip(child_vk.inner.per_air.iter(), fanout_per_air.into_iter()).enumerate()
    {
        let constraints = &vk.symbolic_constraints.constraints;
        let constraint_idxs = &constraints.constraint_idx;
        let mut j = 0;

        for (node_idx, (node, &fanout)) in
            zip(constraints.nodes.iter(), fanout_per_node.iter()).enumerate()
        {
            if j < constraint_idxs.len() && constraint_idxs[j] < node_idx {
                j += 1;
            }
            let is_constraint = j < constraint_idxs.len() && constraint_idxs[j] == node_idx;
            let mut record = CachedRecord {
                kind: NodeKind::Constant,
                air_idx,
                node_idx,
                attrs: [0; 3],
                is_constraint,
                constraint_idx: if !is_constraint { 0 } else { j },
                fanout,
            };
            match node {
                SymbolicExpressionNode::Variable(var) => {
                    record.attrs[0] = var.index;
                    match var.entry {
                        Entry::Preprocessed { offset } => {
                            record.kind = NodeKind::VarPreprocessed;
                            record.attrs[1] = 1;
                            record.attrs[2] = offset;
                        }
                        Entry::Main { part_index, offset } => {
                            record.kind = NodeKind::VarMain;
                            record.attrs[1] = vk.dag_main_part_index_to_commit_index(part_index);
                            record.attrs[2] = offset;
                        }
                        Entry::Permutation { .. } => unreachable!(),
                        Entry::Public => {
                            record.kind = NodeKind::VarPublicValue;
                        }
                        Entry::Challenge | Entry::Exposed => unreachable!(),
                    }
                }
                SymbolicExpressionNode::IsFirstRow => record.kind = NodeKind::SelIsFirst,
                SymbolicExpressionNode::IsLastRow => record.kind = NodeKind::SelIsLast,
                SymbolicExpressionNode::IsTransition => record.kind = NodeKind::SelIsTransition,
                SymbolicExpressionNode::Constant(val) => {
                    record.kind = NodeKind::Constant;
                    record.attrs[0] = val.as_canonical_u32() as usize;
                }
                SymbolicExpressionNode::Add { left_idx, right_idx, .. } => {
                    record.kind = NodeKind::Add;
                    record.attrs[0] = *left_idx;
                    record.attrs[1] = *right_idx;
                }
                SymbolicExpressionNode::Sub { left_idx, right_idx, .. } => {
                    record.kind = NodeKind::Sub;
                    record.attrs[0] = *left_idx;
                    record.attrs[1] = *right_idx;
                }
                SymbolicExpressionNode::Neg { idx, .. } => {
                    record.kind = NodeKind::Neg;
                    record.attrs[0] = *idx;
                }
                SymbolicExpressionNode::Mul { left_idx, right_idx, .. } => {
                    record.kind = NodeKind::Mul;
                    record.attrs[0] = *left_idx;
                    record.attrs[1] = *right_idx;
                }
            };
            records.push(record);
        }

        for (interaction_idx, interaction) in
            vk.symbolic_constraints.interactions.iter().enumerate()
        {
            records.push(CachedRecord {
                kind: NodeKind::InteractionMult,
                air_idx,
                node_idx: interaction_idx,
                attrs: [interaction.count, 0, 0],
                is_constraint: false,
                constraint_idx: 0,
                fanout: 0,
            });
            for (idx_in_message, &node_idx) in interaction.message.iter().enumerate() {
                records.push(CachedRecord {
                    kind: NodeKind::InteractionMsgComp,
                    air_idx,
                    node_idx: interaction_idx,
                    attrs: [node_idx, idx_in_message, 0],
                    is_constraint: false,
                    constraint_idx: 0,
                    fanout: 0,
                });
            }
            records.push(CachedRecord {
                kind: NodeKind::InteractionBusIndex,
                air_idx,
                node_idx: interaction_idx,
                attrs: [interaction.bus_index as usize, 0, 0],
                is_constraint: false,
                constraint_idx: 0,
                fanout: 0,
            });
        }

        let mut node_idx = constraints.nodes.len();
        for unused_var in &vk.unused_variables {
            let record = match unused_var.entry {
                Entry::Preprocessed { offset } => CachedRecord {
                    kind: NodeKind::VarPreprocessed,
                    air_idx,
                    node_idx,
                    attrs: [unused_var.index, 1, offset],
                    is_constraint: false,
                    constraint_idx: 0,
                    fanout: 0,
                },
                Entry::Main { part_index, offset } => {
                    let part = vk.dag_main_part_index_to_commit_index(part_index);
                    CachedRecord {
                        kind: NodeKind::VarMain,
                        air_idx,
                        node_idx,
                        attrs: [unused_var.index, part, offset],
                        is_constraint: false,
                        constraint_idx: 0,
                        fanout: 0,
                    }
                }
                Entry::Permutation { .. } | Entry::Public | Entry::Challenge | Entry::Exposed => {
                    continue;
                }
            };
            node_idx += 1;
            records.push(record);
        }
    }

    CachedTraceRecord { records }
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
