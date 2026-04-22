use crate::{
    error::ZKVMError,
    scheme::{
        constants::{MIN_PAR_SIZE, SEPTIC_EXTENSION_DEGREE},
        hal::{ProofInput, ProverDevice},
    },
    structs::{ComposedConstrainSystem, EccQuarkProof, PointAndEval},
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    evaluation::EvalExpression,
    gkr::{
        GKRCircuit, GKRCircuitOutput, GKRCircuitWitness,
        layer::{LayerWitness, ROTATION_OPENING_COUNT},
    },
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend},
};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
pub use multilinear_extensions::wit_infer_by_expr;
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    prelude::ParallelSliceMut,
};
use std::{iter, sync::Arc};
use witness::next_pow2_instance_padding;

/// Prover-only routing metadata for first-layer GKR output groups.
///
/// This is group-level metadata describing which downstream proving submodule
/// consumes outputs from a selector group. A group may route to more than one
/// submodule, e.g. `TOWER | ZERO`, when the flat tower-output prefix cuts
/// through the middle of the group.
///
/// This metadata is not part of the proof format and is not used by the
/// verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct GkrOutputStageMask(u8);

impl GkrOutputStageMask {
    pub(crate) const TOWER: Self = Self(1 << 0);
    pub(crate) const ECC: Self = Self(1 << 1);
    pub(crate) const ROTATION: Self = Self(1 << 2);
    pub(crate) const ZERO: Self = Self(1 << 3);

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessBuildStage {
    Tower,
}

pub(crate) fn tower_output_count<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
) -> usize {
    let cs = &composed_cs.zkvm_v1_css;
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let num_lk_num = cs.lk_table_expressions.len();
    let num_lk_den = if !cs.lk_table_expressions.is_empty() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    num_reads + num_writes + num_lk_num + num_lk_den
}

fn build_output_materialization_mask<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    circuit: &GKRCircuit<E>,
    stage: WitnessBuildStage,
) -> Vec<bool> {
    let first_layer = circuit.layers.first().expect("empty gkr circuit layer");
    let group_stage_masks = first_layer_output_group_stage_masks(composed_cs, circuit);
    let total_outputs = first_layer
        .out_sel_and_eval_exprs
        .iter()
        .map(|(_, outputs)| outputs.len())
        .sum::<usize>();
    let mut mask = vec![false; total_outputs];
    match stage {
        WitnessBuildStage::Tower => {
            // Materialization is exact at flattened-entry granularity even though routing metadata
            // is tracked at group granularity. This is what lets mixed `TOWER | ZERO` groups avoid
            // allocating the non-tower suffix during tower prove.
            let mut remaining = tower_output_count(composed_cs);
            let mut offset = 0usize;
            for ((_, outputs), stage_mask) in first_layer
                .out_sel_and_eval_exprs
                .iter()
                .zip(group_stage_masks.iter())
            {
                let len = outputs.len();
                if stage_mask.contains(GkrOutputStageMask::TOWER) && remaining > 0 {
                    let take_len = len.min(remaining);
                    mask[offset..offset + take_len].fill(true);
                    remaining -= take_len;
                }
                offset += len;
            }
            debug_assert_eq!(remaining, 0, "failed to cover all tower outputs");
        }
    }
    mask
}

pub(crate) fn first_layer_output_group_stage_masks<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    circuit: &GKRCircuit<E>,
) -> Vec<GkrOutputStageMask> {
    let first_layer = circuit.layers.first().expect("empty gkr circuit layer");
    let mut group_masks = vec![GkrOutputStageMask::ZERO; first_layer.out_sel_and_eval_exprs.len()];

    if let Some(rotation_groups) = first_layer.rotation_selector_group_indices() {
        for group_idx in rotation_groups {
            group_masks[group_idx] = GkrOutputStageMask::ROTATION;
        }
    }
    if let Some(ecc_groups) = first_layer.ecc_bridge_group_indices() {
        for group_idx in ecc_groups {
            group_masks[group_idx] = GkrOutputStageMask::ECC;
        }
    }

    let tower_outputs = tower_output_count(composed_cs);
    let mut seen_tower_outputs = 0usize;
    for (group_mask, (_, outputs)) in group_masks
        .iter_mut()
        .zip(first_layer.out_sel_and_eval_exprs.iter())
    {
        if seen_tower_outputs >= tower_outputs {
            break;
        }
        *group_mask = group_mask.union(GkrOutputStageMask::TOWER);
        seen_tower_outputs += outputs.len();
    }
    assert!(
        seen_tower_outputs >= tower_outputs,
        "failed to cover all tower outputs: layer={}, seen_tower_outputs={}, tower_outputs={}",
        first_layer.name,
        seen_tower_outputs,
        tower_outputs,
    );

    group_masks
}

pub(crate) struct EccBridgeClaims<E: ExtensionField> {
    pub(crate) xy_point: Point<E>,
    pub(crate) s_point: Point<E>,
    pub(crate) x3y3_point: Point<E>,
    pub(crate) x_evals: Vec<E>,
    pub(crate) y_evals: Vec<E>,
    pub(crate) s_evals: Vec<E>,
    pub(crate) x3_evals: Vec<E>,
    pub(crate) y3_evals: Vec<E>,
}

pub(crate) struct EccQuarkWitnessInputs<'a, PB: ProverBackend> {
    pub(crate) xs: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub(crate) ys: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub(crate) slopes: Vec<Arc<PB::MultilinearPoly<'a>>>,
}

pub(crate) fn extract_ecc_quark_witness_inputs<'a, PB: ProverBackend>(
    cs: &ComposedConstrainSystem<PB::E>,
    input: &ProofInput<'a, PB>,
) -> Option<EccQuarkWitnessInputs<'a, PB>> {
    let cs = &cs.zkvm_v1_css;
    if cs.ec_final_sum.is_empty() {
        return None;
    }

    let ec_point_exprs = &cs.ec_point_exprs;
    assert_eq!(ec_point_exprs.len(), SEPTIC_EXTENSION_DEGREE * 2);
    let mut xs_ys = ec_point_exprs
        .iter()
        .map(|expr| match expr {
            Expression::WitIn(id) => input.witness[*id as usize].clone(),
            _ => unreachable!("ec point's expression must be WitIn"),
        })
        .collect_vec();
    let ys = xs_ys.split_off(SEPTIC_EXTENSION_DEGREE);
    let xs = xs_ys;

    let slopes = cs
        .ec_slope_exprs
        .iter()
        .map(|expr| match expr {
            Expression::WitIn(id) => input.witness[*id as usize].clone(),
            _ => unreachable!("slope's expression must be WitIn"),
        })
        .collect_vec();

    Some(EccQuarkWitnessInputs { xs, ys, slopes })
}

pub(crate) fn derive_ecc_bridge_claims<E: ExtensionField>(
    ecc_proof: &EccQuarkProof<E>,
    sample_r: E,
    num_var_with_rotation: usize,
) -> Result<EccBridgeClaims<E>, ZKVMError> {
    let degree = SEPTIC_EXTENSION_DEGREE;
    if ecc_proof.evals.len() < 3 {
        return Err(ZKVMError::InvalidProof(
            "ecc proof evals shorter than selector prefix".into(),
        ));
    }
    let evals = &ecc_proof.evals[3..];
    if evals.len() != degree * 7 {
        return Err(ZKVMError::InvalidProof(
            format!(
                "invalid ecc proof eval length: expected {}, got {}",
                degree * 7,
                evals.len()
            )
            .into(),
        ));
    }

    let s1 = &evals[0..degree];
    let x0 = &evals[degree..2 * degree];
    let y0 = &evals[2 * degree..3 * degree];
    let x1 = &evals[3 * degree..4 * degree];
    let y1 = &evals[4 * degree..5 * degree];
    let x3 = &evals[5 * degree..6 * degree];
    let y3 = &evals[6 * degree..7 * degree];

    let one_minus_r = E::ONE - sample_r;
    let x_evals = x0
        .iter()
        .zip_eq(x1.iter())
        .map(|(a, b)| *a * one_minus_r + *b * sample_r)
        .collect_vec();
    let y_evals = y0
        .iter()
        .zip_eq(y1.iter())
        .map(|(a, b)| *a * one_minus_r + *b * sample_r)
        .collect_vec();
    let s_evals = s1.iter().map(|v| *v * sample_r).collect_vec();
    let x3_evals = x3.to_vec();
    let y3_evals = y3.to_vec();

    let mut xy_point = vec![sample_r];
    xy_point.extend(ecc_proof.rt.iter().copied());
    if xy_point.len() != num_var_with_rotation {
        return Err(ZKVMError::InvalidProof(
            format!(
                "invalid ecc xy point length: expected {}, got {}",
                num_var_with_rotation,
                xy_point.len()
            )
            .into(),
        ));
    }

    let mut s_point = ecc_proof.rt.clone();
    s_point.push(sample_r);
    if s_point.len() != num_var_with_rotation {
        return Err(ZKVMError::InvalidProof(
            format!(
                "invalid ecc slope point length: expected {}, got {}",
                num_var_with_rotation,
                s_point.len()
            )
            .into(),
        ));
    }

    let mut x3y3_point = ecc_proof.rt.clone();
    x3y3_point.push(E::ONE);
    if x3y3_point.len() != num_var_with_rotation {
        return Err(ZKVMError::InvalidProof(
            format!(
                "invalid ecc x3/y3 point length: expected {}, got {}",
                num_var_with_rotation,
                x3y3_point.len()
            )
            .into(),
        ));
    }

    Ok(EccBridgeClaims {
        xy_point,
        s_point,
        x3y3_point,
        x_evals,
        y_evals,
        s_evals,
        x3_evals,
        y3_evals,
    })
}

pub(crate) fn split_rotation_evals<E: ExtensionField>(evals: &[E]) -> (Vec<E>, Vec<E>, Vec<E>) {
    assert_eq!(
        evals.len() % ROTATION_OPENING_COUNT,
        0,
        "rotation evals length must be a multiple of {}, got {}",
        ROTATION_OPENING_COUNT,
        evals.len()
    );
    let mut left_evals = Vec::new();
    let mut right_evals = Vec::new();
    let mut point_evals = Vec::new();
    for chunk in evals.chunks_exact(ROTATION_OPENING_COUNT) {
        left_evals.push(chunk[0]);
        right_evals.push(chunk[1]);
        point_evals.push(chunk[2]);
    }
    (left_evals, right_evals, point_evals)
}

pub(crate) fn assign_group_evals<E: ExtensionField>(
    out_evals: &mut [PointAndEval<E>],
    eval_exprs: &[EvalExpression<E>],
    evals: &[E],
    point: &Point<E>,
) {
    assert_eq!(eval_exprs.len(), evals.len(), "group eval length mismatch");
    for (eval_expr, eval) in eval_exprs.iter().zip_eq(evals.iter()) {
        let EvalExpression::Single(index) = eval_expr else {
            panic!("group must use EvalExpression::Single");
        };
        out_evals[*index] = PointAndEval::new(point.clone(), *eval);
    }
}

/// Wrapper that asserts a shared reference is safe to send across threads.
///
/// # Safety
/// The caller must guarantee that the referenced data is only **read** (never
/// mutated) while the `SyncRef` is alive. This is typically the case when the
/// reference points to data that is immutable for the duration of a
/// `std::thread::scope` block.
#[cfg(feature = "gpu")]
pub(crate) struct SyncRef<'a, T>(pub(crate) &'a T);

// SAFETY: T is only accessed via a shared reference which is read-only.
// The T: Sync bound ensures &T is safe to share across threads (required for &T: Send).
#[cfg(feature = "gpu")]
unsafe impl<T: Sync> Send for SyncRef<'_, T> {}
#[cfg(feature = "gpu")]
unsafe impl<T: Sync> Sync for SyncRef<'_, T> {}

/// interleaving multiple mles into mles, and num_limbs indicate number of final limbs vector
/// e.g input [[1,2],[3,4],[5,6],[7,8]], num_limbs=2,log2_per_instance_size=3
/// output [[1,3,5,7,0,0,0,0],[2,4,6,8,0,0,0,0]]
#[allow(unused)]
pub(crate) fn interleaving_mles_to_mles<'a, E: ExtensionField>(
    mles: &[ArcMultilinearExtension<E>],
    num_instances: usize,
    num_limbs: usize,
    default: E,
) -> Vec<MultilinearExtension<'a, E>> {
    assert!(num_limbs.is_power_of_two());
    assert!(!mles.is_empty());
    let next_power_of_2 = next_pow2_instance_padding(num_instances);
    assert!(
        mles.iter()
            .all(|mle| mle.evaluations().len() <= next_power_of_2)
    );
    let log2_num_instances = ceil_log2(next_power_of_2);
    let per_fanin_len = (mles[0].evaluations().len() / num_limbs).max(1); // minimal size 1
    let log2_mle_size = ceil_log2(mles.len());
    let log2_num_limbs = ceil_log2(num_limbs);

    (0..num_limbs)
        .into_par_iter()
        .map(|fanin_index| {
            let mut evaluations = vec![
                default;
                1 << (log2_mle_size
                    + log2_num_instances.saturating_sub(log2_num_limbs))
            ];
            let per_instance_size = 1 << log2_mle_size;
            assert!(evaluations.len() >= per_instance_size);
            let start = per_fanin_len * fanin_index;
            if start < num_instances {
                let valid_instances_len = per_fanin_len.min(num_instances - start);
                mles.iter()
                    .enumerate()
                    .for_each(|(i, mle)| match mle.evaluations() {
                        FieldType::Ext(mle) => mle
                            .get(start..(start + valid_instances_len))
                            .unwrap_or(&[])
                            .par_iter()
                            .zip(evaluations.par_chunks_mut(per_instance_size))
                            .with_min_len(MIN_PAR_SIZE)
                            .for_each(|(value, instance)| {
                                assert_eq!(instance.len(), per_instance_size);
                                instance[i] = *value;
                            }),
                        FieldType::Base(mle) => mle
                            .get(start..(start + per_fanin_len))
                            .unwrap_or(&[])
                            .par_iter()
                            .zip(evaluations.par_chunks_mut(per_instance_size))
                            .with_min_len(MIN_PAR_SIZE)
                            .for_each(|(value, instance)| {
                                assert_eq!(instance.len(), per_instance_size);
                                instance[i] = E::from(*value);
                            }),
                        _ => unreachable!(),
                    });
            }
            evaluations.into_mle()
        })
        .collect::<Vec<MultilinearExtension<E>>>()
}

macro_rules! tower_mle_4 {
    ($p1:ident, $p2:ident, $q1:ident, $q2:ident, $start_index:ident, $cur_len:ident) => {{
        let range = $start_index..($start_index + $cur_len);
        $q1[range.clone()]
            .par_iter()
            .zip(&$q2[range.clone()])
            .zip(&$p1[range.clone()])
            .zip(&$p2[range])
            .map(|(((q1, q2), p1), p2)| {
                let p = *q1 * *p2 + *q2 * *p1;
                let q = *q1 * *q2;
                (p, q)
            })
            .unzip()
    }};
}

pub fn log2_strict_usize(n: usize) -> usize {
    assert!(n.is_power_of_two());
    n.trailing_zeros() as usize
}

/// infer logup witness from last layer
/// return is the ([p1,p2], [q1,q2]) for each layer
pub(crate) fn infer_tower_logup_witness<'a, E: ExtensionField>(
    p_mles: Option<Vec<MultilinearExtension<'a, E>>>,
    q_mles: Vec<MultilinearExtension<'a, E>>,
) -> Vec<Vec<MultilinearExtension<'a, E>>> {
    if cfg!(test) {
        assert_eq!(q_mles.len(), 2);
        assert!(q_mles.iter().map(|q| q.evaluations().len()).all_equal());
    }
    let num_vars = ceil_log2(q_mles[0].evaluations().len());
    let mut wit_layers = (0..num_vars).fold(vec![(p_mles, q_mles)], |mut acc, _| {
        let (p, q): &(
            Option<Vec<MultilinearExtension<E>>>,
            Vec<MultilinearExtension<E>>,
        ) = acc.last().unwrap();
        let (q1, q2) = (&q[0], &q[1]);
        let cur_len = q1.evaluations().len() / 2;
        let (next_p, next_q): (Vec<MultilinearExtension<E>>, Vec<MultilinearExtension<E>>) = (0..2)
            .map(|index| {
                let start_index = cur_len * index;
                let (p_evals, q_evals): (Vec<E>, Vec<E>) = if let Some(p) = p {
                    let (p1, p2) = (&p[0], &p[1]);
                    match (
                        p1.evaluations(),
                        p2.evaluations(),
                        q1.evaluations(),
                        q2.evaluations(),
                    ) {
                        (
                            FieldType::Ext(p1),
                            FieldType::Ext(p2),
                            FieldType::Ext(q1),
                            FieldType::Ext(q2),
                        ) => tower_mle_4!(p1, p2, q1, q2, start_index, cur_len),
                        (
                            FieldType::Base(p1),
                            FieldType::Base(p2),
                            FieldType::Ext(q1),
                            FieldType::Ext(q2),
                        ) => tower_mle_4!(p1, p2, q1, q2, start_index, cur_len),
                        _ => unreachable!(),
                    }
                } else {
                    match (q1.evaluations(), q2.evaluations()) {
                        (FieldType::Ext(q1), FieldType::Ext(q2)) => {
                            let range = start_index..(start_index + cur_len);
                            q1[range.clone()]
                                .par_iter()
                                .zip(&q2[range])
                                .map(|(q1, q2)| {
                                    // 1 / q1 + 1 / q2 = (q1+q2) / q1*q2
                                    // p is numerator and q is denominator
                                    let p = *q1 + *q2;
                                    let q = *q1 * *q2;
                                    (p, q)
                                })
                                .unzip()
                        }
                        _ => unreachable!(),
                    }
                };
                (p_evals.into_mle(), q_evals.into_mle())
            })
            .unzip(); // vec[vec[p1, p2], vec[q1, q2]]
        acc.push((Some(next_p), next_q));
        acc
    });
    wit_layers.reverse();
    wit_layers
        .into_iter()
        .map(|(p, q)| {
            // input layer p are all 1
            if let Some(mut p) = p {
                p.extend(q);
                p
            } else {
                let len = q[0].evaluations().len();
                vec![
                    (0..len)
                        .into_par_iter()
                        .map(|_| E::ONE)
                        .collect::<Vec<_>>()
                        .into_mle(),
                    (0..len)
                        .into_par_iter()
                        .map(|_| E::ONE)
                        .collect::<Vec<_>>()
                        .into_mle(),
                ]
                .into_iter()
                .chain(q)
                .collect()
            }
        })
        .collect_vec()
}

/// Infer tower witness from input layer (layer 0 is the output layer and layer n is the input layer).
/// The relation between layer i and layer i+1 is as follows:
///      prod[i][b] = ∏_s prod[i+1][s,b]
/// where 2^s is the fanin of the product gate `num_product_fanin`.
pub fn infer_tower_product_witness<E: ExtensionField>(
    num_vars: usize,
    last_layer: Vec<MultilinearExtension<'_, E>>,
    num_product_fanin: usize,
) -> Vec<Vec<MultilinearExtension<'_, E>>> {
    // sanity check
    assert!(last_layer.len() == num_product_fanin);
    assert!(num_product_fanin.is_power_of_two());

    let log2_num_product_fanin = log2_strict_usize(num_product_fanin);
    assert!(num_vars.is_multiple_of(log2_num_product_fanin));
    assert!(
        last_layer
            .iter()
            .all(|p| p.num_vars() == num_vars - log2_num_product_fanin)
    );

    let num_layers = num_vars / log2_num_product_fanin;

    let mut wit_layers = Vec::with_capacity(num_layers);
    wit_layers.push(last_layer);

    for _ in (0..num_layers - 1).rev() {
        let input_layer = wit_layers.last().unwrap();
        let output_len = input_layer[0].evaluations().len() / num_product_fanin;

        let output_layer: Vec<MultilinearExtension<E>> = (0..num_product_fanin)
            .map(|index| {
                // avoid the overhead of vector initialization
                let mut evaluations: Vec<E> = Vec::with_capacity(output_len);
                let remaining = evaluations.spare_capacity_mut();

                input_layer.chunks_exact(2).enumerate().for_each(|(i, f)| {
                    match (f[0].evaluations(), f[1].evaluations()) {
                        (FieldType::Ext(f1), FieldType::Ext(f2)) => {
                            let start: usize = index * output_len;

                            if i == 0 {
                                (start..(start + output_len))
                                    .into_par_iter()
                                    .zip(remaining.par_iter_mut())
                                    .with_min_len(MIN_PAR_SIZE)
                                    .for_each(|(index, evaluations)| {
                                        evaluations.write(f1[index] * f2[index]);
                                    });
                            } else {
                                (start..(start + output_len))
                                    .into_par_iter()
                                    .zip(remaining.par_iter_mut())
                                    .with_min_len(MIN_PAR_SIZE)
                                    .for_each(|(index, evaluations)| {
                                        evaluations.write(f1[index] * f2[index]);
                                    });
                            }
                        }
                        _ => unreachable!("must be extension field"),
                    }
                });

                unsafe {
                    evaluations.set_len(output_len);
                }
                evaluations.into_mle()
            })
            .collect_vec();
        wit_layers.push(output_layer);
    }

    wit_layers.reverse();

    wit_layers
}

#[tracing::instrument(
    skip_all,
    name = "build_main_witness",
    fields(profiling_2),
    level = "trace"
)]
pub fn build_main_witness<
    'a,
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB>,
>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'a, PB>,
    challenges: &[E; 2],
    stage: WitnessBuildStage,
) -> Vec<Arc<PB::MultilinearPoly<'a>>> {
    let ComposedConstrainSystem {
        zkvm_v1_css: cs,
        gkr_circuit,
    } = composed_cs;
    let log2_num_instances = input.log2_num_instances();
    let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

    // sanity check
    assert_eq!(input.witness.len(), cs.num_witin as usize);

    // structural witness can be empty. In this case they are `eq`, and will be filled later
    assert!(
        input.structural_witness.len() == cs.num_structural_witin as usize
            || input.structural_witness.is_empty(),
    );
    assert_eq!(input.fixed.len(), cs.num_fixed);

    let Some(gkr_circuit) = gkr_circuit else {
        panic!("empty gkr-iop")
    };

    // circuit must have at least one read/write/lookup
    assert!(
        cs.r_expressions.len()
            + cs.w_expressions.len()
            + cs.lk_expressions.len()
            + cs.r_table_expressions.len()
            + cs.w_table_expressions.len()
            + cs.lk_table_expressions.len()
            > 0,
        "assert circuit"
    );

    // check all witness size are power of 2
    assert!(
        input
            .witness
            .iter()
            .chain(&input.structural_witness)
            .chain(&input.fixed)
            .all(|v| { v.evaluations_len() == 1 << num_var_with_rotation })
    );

    // GPU memory estimation
    #[cfg(feature = "gpu")]
    let cuda_hal = gkr_iop::gpu::get_cuda_hal().expect("Failed to get CUDA HAL");
    #[cfg(feature = "gpu")]
    let gpu_mem_tracker = crate::scheme::gpu::init_gpu_mem_tracker(&cuda_hal, "build_main_witness");

    let output_mask = build_output_materialization_mask(composed_cs, gkr_circuit, stage);
    let (_, gkr_circuit_out) = gkr_witness::<E, PCS, PB, PD>(
        gkr_circuit,
        &input.witness,
        &input.structural_witness,
        &input.fixed,
        &[],
        &input.pi,
        challenges,
        Some(output_mask.as_slice()),
    );

    // GPU memory check: validate estimation against actual usage
    #[cfg(feature = "gpu")]
    {
        let estimated_bytes =
            crate::scheme::gpu::estimate_main_witness_bytes(composed_cs, num_var_with_rotation);
        crate::scheme::gpu::check_gpu_mem_estimation(gpu_mem_tracker, estimated_bytes);
    }

    gkr_circuit_out.0.0
}

#[allow(clippy::too_many_arguments)]
pub fn gkr_witness<
    'b,
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB>,
>(
    circuit: &GKRCircuit<E>,
    phase1_witness_group: &[Arc<PB::MultilinearPoly<'b>>],
    structural_witness: &[Arc<PB::MultilinearPoly<'b>>],
    fixed: &[Arc<PB::MultilinearPoly<'b>>],
    _pub_io_mles: &[Arc<PB::MultilinearPoly<'b>>],
    pub_io_evals: &[Either<E::BaseField, E>],
    challenges: &[E],
    output_mask: Option<&[bool]>,
) -> (GKRCircuitWitness<'b, PB>, GKRCircuitOutput<'b, PB>) {
    // layer order from output to input
    let mut layer_wits = Vec::<LayerWitness<PB>>::with_capacity(circuit.layers.len() + 1);

    let mut witness_mle_flatten = vec![None; circuit.n_evaluations];

    // set input to witness_mle_flatten via first layer in_eval_expr
    if let Some(first_layer) = circuit.layers.last() {
        // process witin
        first_layer
            .in_eval_expr
            .iter()
            .take(first_layer.n_witin)
            .zip_eq(phase1_witness_group.iter())
            .for_each(|(index, witin_mle)| {
                witness_mle_flatten[*index] = Some(witin_mle.clone());
            });

        first_layer
            .in_eval_expr
            .iter()
            .skip(first_layer.n_witin)
            .take(first_layer.n_fixed)
            .zip_eq(fixed.iter())
            .for_each(|(index, fixed_mle)| {
                witness_mle_flatten[*index] = Some(fixed_mle.clone());
            });

        // XXX currently fixed poly not support in layers > 1
        // TODO process fixed (and probably short) mle
        //
        // first_layer
        //     .in_eval_expr
        //     .par_iter()
        //     .enumerate()
        //     .skip(phase1_witness_group.len())
        //     .map(|(index, witin)| {
        //         (
        //             *witin,
        //             Some(
        //                 fixed[index - phase1_witness_group.len()]
        //                     .iter()
        //                     .cycle()
        //                     .cloned()
        //                     .take(num_instances_with_rotation)
        //                     .collect_vec()
        //                     .into_mle()
        //                     .into(),
        //             ),
        //         )
        //     })
        //     .collect::<HashMap<_, _>>()
        //     .into_iter()
        //     .for_each(|(witin, optional_mle)| witness_mle_flatten[witin] = optional_mle);
    }

    // generate all layer witness from input to output
    for (i, layer) in circuit.layers.iter().rev().enumerate() {
        tracing::debug!("generating input {i} layer with layer name {}", layer.name);
        // process in_evals to prepare layer witness
        // This should assume the input of the first layer is the phase1 witness of the circuit.
        let current_layer_wits = layer
            .in_eval_expr
            .iter()
            .map(|witin| {
                witness_mle_flatten[*witin]
                    .clone()
                    .expect("witness must exist")
            })
            .chain(if i == 0 {
                // only supply structural witness for first layer
                // TODO figure out how to support > 1 GKR layers
                Either::Left(structural_witness.iter().cloned())
            } else {
                Either::Right(iter::empty())
            })
            .collect_vec();

        assert_eq!(
            current_layer_wits.len(),
            layer.n_witin + layer.n_fixed + if i == 0 { layer.n_structural_witin } else { 0 }
        );

        // infer current layer output
        let layer_output_mask = (i + 1 == circuit.layers.len())
            .then_some(output_mask)
            .flatten();
        let current_layer_output: Vec<Arc<PB::MultilinearPoly<'b>>> =
            <PD as ProtocolWitnessGeneratorProver<PB>>::layer_witness_filtered(
                layer,
                &current_layer_wits,
                pub_io_evals,
                challenges,
                layer_output_mask,
            );
        layer_wits.push(LayerWitness::new(current_layer_wits, vec![]));

        // process out to prepare output witness
        layer
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(_, out_eval)| out_eval)
            .zip_eq(&current_layer_output)
            .for_each(|(out_eval, out_mle)| match out_eval {
                EvalExpression::Single(out) | EvalExpression::Linear(out, _, _) => {
                    witness_mle_flatten[*out] = Some(out_mle.clone());
                }
                EvalExpression::Zero => { // zero expression
                    // do nothing on zero expression
                }
                other => unimplemented!("{:?}", other),
            });
    }
    layer_wits.reverse();

    // initialize a vector to store the final outputs of the GKR circuit.
    let mut gkr_out_well_order = vec![Arc::default(); circuit.final_out_evals.len()];
    circuit
        .final_out_evals
        .iter()
        .for_each(|out| gkr_out_well_order[*out] = witness_mle_flatten[*out].clone().unwrap());

    (
        GKRCircuitWitness { layers: layer_wits },
        GKRCircuitOutput(LayerWitness(gkr_out_well_order)),
    )
}

#[cfg(test)]
mod tests {

    use ff_ext::{FieldInto, GoldilocksExt2};
    use itertools::Itertools;
    use multilinear_extensions::{
        commutative_op_mle_pair,
        mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
        smart_slice::SmartSlice,
        util::ceil_log2,
    };
    use p3::field::FieldAlgebra;

    use crate::scheme::utils::{
        infer_tower_logup_witness, infer_tower_product_witness, interleaving_mles_to_mles,
    };

    #[test]
    fn test_infer_tower_witness() {
        type E = GoldilocksExt2;
        let num_product_fanin = 2;
        let last_layer: Vec<MultilinearExtension<E>> = vec![
            vec![E::ONE, E::from_canonical_u64(2u64)].into_mle(),
            vec![E::from_canonical_u64(3u64), E::from_canonical_u64(4u64)].into_mle(),
        ];
        let num_vars = ceil_log2(last_layer[0].evaluations().len()) + 1;
        let res = infer_tower_product_witness(num_vars, last_layer.clone(), 2);
        let (left, right) = (&res[0][0], &res[0][1]);
        let final_product = commutative_op_mle_pair!(
            |left, right| {
                assert!(left.len() == 1 && right.len() == 1);
                left[0] * right[0]
            },
            |out| out.into()
        );
        let expected_final_product: E = last_layer
            .iter()
            .map(|f| match f.evaluations() {
                FieldType::Ext(e) => e.iter().copied().reduce(|a, b| a * b).unwrap(),
                _ => unreachable!(""),
            })
            .product();
        assert_eq!(res.len(), num_vars);
        assert!(
            res.iter()
                .all(|layer_wit| layer_wit.len() == num_product_fanin)
        );
        assert_eq!(final_product, expected_final_product);
    }

    #[test]
    fn test_interleaving_mles_to_mles() {
        type E = GoldilocksExt2;
        let num_product_fanin = 2;
        // [[1, 2], [3, 4], [5, 6], [7, 8]]
        let input_mles: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::ONE, E::from_canonical_u64(2u64)].into_mle().into(),
            vec![E::from_canonical_u64(3u64), E::from_canonical_u64(4u64)]
                .into_mle()
                .into(),
            vec![E::from_canonical_u64(5u64), E::from_canonical_u64(6u64)]
                .into_mle()
                .into(),
            vec![E::from_canonical_u64(7u64), E::from_canonical_u64(8u64)]
                .into_mle()
                .into(),
        ];
        let res = interleaving_mles_to_mles(&input_mles, 2, num_product_fanin, E::ONE);
        // [[1, 3, 5, 7], [2, 4, 6, 8]]
        assert_eq!(
            res[0].get_ext_field_vec(),
            vec![
                E::ONE,
                E::from_canonical_u64(3u64),
                E::from_canonical_u64(5u64),
                E::from_canonical_u64(7u64)
            ],
        );
        assert_eq!(
            res[1].get_ext_field_vec(),
            vec![
                E::from_canonical_u64(2u64),
                E::from_canonical_u64(4u64),
                E::from_canonical_u64(6u64),
                E::from_canonical_u64(8u64)
            ],
        );
    }

    #[test]
    fn test_interleaving_mles_to_mles_padding() {
        type E = GoldilocksExt2;
        let num_product_fanin = 2;

        // case 1: test limb level padding
        // [[1,2],[3,4],[5,6]]]
        let input_mles: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::ONE, E::from_canonical_u64(2u64)].into_mle().into(),
            vec![E::from_canonical_u64(3u64), E::from_canonical_u64(4u64)]
                .into_mle()
                .into(),
            vec![E::from_canonical_u64(5u64), E::from_canonical_u64(6u64)]
                .into_mle()
                .into(),
        ];
        let res = interleaving_mles_to_mles(&input_mles, 2, num_product_fanin, E::ZERO);
        // [[1, 3, 5, 0], [2, 4, 6, 0]]
        assert_eq!(
            res[0].get_ext_field_vec(),
            vec![
                E::ONE,
                E::from_canonical_u64(3u64),
                E::from_canonical_u64(5u64),
                E::from_canonical_u64(0u64)
            ],
        );
        assert_eq!(
            res[1].get_ext_field_vec(),
            vec![
                E::from_canonical_u64(2u64),
                E::from_canonical_u64(4u64),
                E::from_canonical_u64(6u64),
                E::from_canonical_u64(0u64)
            ],
        );

        // case 2: test instance level padding
        // [[1,0],[3,0],[5,0]]]
        let input_mles: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::ONE, E::from_canonical_u64(0u64)].into_mle().into(),
            vec![E::from_canonical_u64(3u64), E::from_canonical_u64(0u64)]
                .into_mle()
                .into(),
            vec![E::from_canonical_u64(5u64), E::from_canonical_u64(0u64)]
                .into_mle()
                .into(),
        ];
        let res = interleaving_mles_to_mles(&input_mles, 1, num_product_fanin, E::ONE);
        // [[1, 3, 5, 1], [1, 1, 1, 1]]
        assert_eq!(
            res[0].get_ext_field_vec(),
            vec![
                E::ONE,
                E::from_canonical_u64(3u64),
                E::from_canonical_u64(5u64),
                E::ONE
            ],
        );
        assert_eq!(res[1].get_ext_field_vec(), vec![E::ONE; 4],);
    }

    #[test]
    fn test_interleaving_mles_to_mles_edgecases() {
        type E = GoldilocksExt2;
        let num_product_fanin = 2;
        // one instance, 2 mles: [[2], [3]]
        let input_mles: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::from_canonical_u64(2u64)].into_mle().into(),
            vec![E::from_canonical_u64(3u64)].into_mle().into(),
        ];
        let res = interleaving_mles_to_mles(&input_mles, 1, num_product_fanin, E::ONE);
        // [[2, 3], [1, 1]]
        assert_eq!(
            res[0].get_ext_field_vec(),
            vec![E::from_canonical_u64(2u64), E::from_canonical_u64(3u64)],
        );
        assert_eq!(res[1].get_ext_field_vec(), vec![E::ONE, E::ONE],);
    }

    #[test]
    fn test_infer_tower_logup_witness() {
        type E = GoldilocksExt2;
        let num_vars = 2;
        let q: Vec<MultilinearExtension<E>> = vec![
            vec![1, 2, 3, 4]
                .into_iter()
                .map(E::from_canonical_u64)
                .collect_vec()
                .into_mle(),
            vec![5, 6, 7, 8]
                .into_iter()
                .map(E::from_canonical_u64)
                .collect_vec()
                .into_mle(),
        ];
        let mut res = infer_tower_logup_witness(None, q);
        assert_eq!(num_vars + 1, res.len());
        // input layer
        let layer = res.pop().unwrap();
        // input layer p
        assert_eq!(
            layer[0].evaluations().to_owned(),
            FieldType::Ext(SmartSlice::Owned(vec![1.into_f(); 4]))
        );
        assert_eq!(
            layer[1].evaluations().clone(),
            FieldType::Ext(SmartSlice::Owned(vec![1.into_f(); 4]))
        );
        // input layer q is none
        assert_eq!(
            layer[2].evaluations().clone(),
            FieldType::Ext(SmartSlice::Owned(vec![
                1.into_f(),
                2.into_f(),
                3.into_f(),
                4.into_f()
            ]))
        );
        assert_eq!(
            layer[3].evaluations().clone(),
            FieldType::Ext(SmartSlice::Owned(vec![
                5.into_f(),
                6.into_f(),
                7.into_f(),
                8.into_f()
            ]))
        );

        // next layer
        let layer = res.pop().unwrap();
        // next layer p1
        assert_eq!(
            layer[0].evaluations().clone(),
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![1 + 5]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
                vec![2 + 6]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>()
            ]))
        );
        // next layer p2
        assert_eq!(
            layer[1].evaluations().clone(),
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![3 + 7]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
                vec![4 + 8]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>()
            ]))
        );
        // next layer q1
        assert_eq!(
            layer[2].evaluations().clone(),
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![5].into_iter().map(E::from_canonical_u64).sum::<E>(),
                vec![2 * 6]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>()
            ]))
        );
        // next layer q2
        assert_eq!(
            layer[3].evaluations().clone(),
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![3 * 7]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
                vec![4 * 8]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>()
            ]))
        );

        // output layer
        let layer = res.pop().unwrap();
        // p1
        assert_eq!(
            layer[0].evaluations().clone(),
            // p11 * q12 + p12 * q11
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![(1 + 5) * (3 * 7) + (3 + 7) * 5]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
            ]))
        );
        // p2
        assert_eq!(
            layer[1].evaluations().clone(),
            // p21 * q22 + p22 * q21
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![(2 + 6) * (4 * 8) + (4 + 8) * (2 * 6)]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
            ]))
        );
        // q1
        assert_eq!(
            layer[2].evaluations().clone(),
            // q12 * q11
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![(3 * 7) * 5]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
            ]))
        );
        // q2
        assert_eq!(
            layer[3].evaluations().clone(),
            // q22 * q22
            FieldType::<E>::Ext(SmartSlice::Owned(vec![
                vec![(4 * 8) * (2 * 6)]
                    .into_iter()
                    .map(E::from_canonical_u64)
                    .sum::<E>(),
            ]))
        );
    }
}
