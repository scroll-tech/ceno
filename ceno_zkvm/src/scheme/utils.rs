use crate::{
    scheme::{
        constants::MIN_PAR_SIZE,
        hal::{MainSumcheckProver, ProofInput, ProverDevice},
        septic_curve::{SepticExtension, SepticPoint},
    },
    structs::ComposedConstrainSystem,
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    evaluation::EvalExpression,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::LayerWitness},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend},
};
use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
pub use multilinear_extensions::wit_infer_by_expr;
use multilinear_extensions::{
    macros::{entered_span, exit_span},
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
};
use p3::matrix::{Matrix, dense::RowMajorMatrix};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    prelude::ParallelSliceMut,
};
use std::{iter, sync::Arc};
use witness::next_pow2_instance_padding;

// first computes the masked mle'[j] = mle[j] if j < num_instance, else default
// then split it into `num_parts` smaller mles
pub(crate) fn masked_mle_split_to_chunks<'a, 'b, E: ExtensionField>(
    mle: &'a MultilinearExtension<'a, E>,
    num_instance: usize,
    num_chunks: usize,
    default: E,
) -> Vec<MultilinearExtension<'b, E>> {
    assert!(num_chunks.is_power_of_two());
    assert!(
        num_instance <= mle.evaluations().len(),
        "num_instance {num_instance} > {}",
        mle.evaluations().len()
    );

    // TODO: when mle.len() is two's power, we should avoid the clone
    (0..num_chunks)
        .into_par_iter()
        .map(|part_idx| {
            let n = mle.evaluations().len() / num_chunks;

            match mle.evaluations() {
                FieldType::Ext(evals) => (part_idx * n..(part_idx + 1) * n)
                    .into_par_iter()
                    .with_min_len(64)
                    .map(|i| if i < num_instance { evals[i] } else { default })
                    .collect::<Vec<_>>()
                    .into_mle(),
                FieldType::Base(evals) => (part_idx * n..(part_idx + 1) * n)
                    .map(|i| {
                        if i < num_instance {
                            E::from(evals[i])
                        } else {
                            default
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_mle(),
                _ => unreachable!(),
            }
        })
        .collect::<Vec<_>>()
}

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
    assert!(num_vars % log2_num_product_fanin == 0);
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
                unsafe {
                    // will be filled immediately
                    evaluations.set_len(output_len);
                }

                input_layer.chunks_exact(2).enumerate().for_each(|(i, f)| {
                    match (f[0].evaluations(), f[1].evaluations()) {
                        (FieldType::Ext(f1), FieldType::Ext(f2)) => {
                            let start: usize = index * output_len;

                            if i == 0 {
                                (start..(start + output_len))
                                    .into_par_iter()
                                    .zip(evaluations.par_iter_mut())
                                    .with_min_len(MIN_PAR_SIZE)
                                    .for_each(|(index, evaluations)| {
                                        *evaluations = f1[index] * f2[index]
                                    });
                            } else {
                                (start..(start + output_len))
                                    .into_par_iter()
                                    .zip(evaluations.par_iter_mut())
                                    .with_min_len(MIN_PAR_SIZE)
                                    .for_each(|(index, evaluations)| {
                                        *evaluations *= f1[index] * f2[index]
                                    });
                            }
                        }
                        _ => unreachable!("must be extension field"),
                    }
                });
                evaluations.into_mle()
            })
            .collect_vec();
        wit_layers.push(output_layer);
    }

    wit_layers.reverse();

    wit_layers
}

/// Infer from input layer (layer 0) to the output layer (layer n)
/// Note that each layer has 2 * 7 * 2 multilinear polynomials.
///
/// The relation between layer i and layer i+1 is as follows:
///     0 = p[i][b] - (p[i+1][0,b] + p[i+1][1,b])
///
pub fn infer_septic_sum_witness<E: ExtensionField>(
    p_mles: Vec<MultilinearExtension<E>>,
) -> Vec<Vec<MultilinearExtension<E>>> {
    assert_eq!(p_mles.len(), 2 * 7 * 2);
    assert!(p_mles.iter().map(|p| p.num_vars()).all_equal());

    // +1 as the input layer has 2*N points where N = 2^num_vars
    // and the output layer has 2 points
    let num_layers = p_mles[0].num_vars() + 1; 

    let mut layers = Vec::with_capacity(num_layers);
    layers.push(p_mles);

    for _ in (0..num_layers-1).rev() {
        let input_layer = layers.last().unwrap();
        let p = input_layer[0..14]
            .iter()
            .map(|mle| mle.get_base_field_vec())
            .collect_vec();
        let q = input_layer[14..28]
            .iter()
            .map(|mle| mle.get_base_field_vec())
            .collect_vec();

        let output_len = p[0].len() / 2;
        let mut outputs: Vec<E::BaseField> = Vec::with_capacity(28 * output_len);
        unsafe {
            // will be filled immediately
            outputs.set_len(28 * output_len);
        }

        (0..2).into_iter().for_each(|chunk| {
            (0..output_len)
                .into_par_iter()
                .with_min_len(MIN_PAR_SIZE)
                .zip(outputs.par_chunks_mut(28))
                .for_each(|(idx, output)| {
                    let row = chunk * output_len + idx;
                    let offset = chunk * 14;

                    let p1 = SepticPoint {
                        x: SepticExtension(std::array::from_fn(|i| p[offset + i][row])),
                        y: SepticExtension(std::array::from_fn(|i| p[offset + i + 7][row])),
                    };
                    let p2 = SepticPoint {
                        x: SepticExtension(std::array::from_fn(|i| q[offset + i][row])),
                        y: SepticExtension(std::array::from_fn(|i| q[offset + i + 7][row])),
                    };

                    let p3 = p1 + p2;

                    output[offset..]
                        .iter_mut()
                        .take(7)
                        .enumerate()
                        .for_each(|(i, out)| {
                            *out = p3.x.0[i];
                        });
                    output[offset..]
                        .iter_mut()
                        .skip(7)
                        .take(7)
                        .enumerate()
                        .for_each(|(i, out)| {
                            *out = p3.y.0[i];
                        });
                });
        });

        // transpose
        let output_mles = (0..28)
            .map(|i| {
                (0..output_len)
                    .into_par_iter()
                    .map(|j| outputs[j * 28 + i])
                    .collect::<Vec<_>>()
                    .into_mle()
            })
            .collect_vec();
        layers.push(output_mles);
    }

    layers.reverse();
    layers
}

pub fn build_main_witness<
    'a,
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB>,
>(
    device: &PD,
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'a, PB>,
    challenges: &[E; 2],
) -> (Vec<Arc<PB::MultilinearPoly<'a>>>, bool) {
    let (mles, is_padded) = {
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

        // check all witness size are power of 2
        assert!(
            input
                .witness
                .iter()
                .all(|v| { v.evaluations_len() == 1 << num_var_with_rotation })
        );

        if !input.structural_witness.is_empty() {
            assert!(
                input
                    .structural_witness
                    .iter()
                    .all(|v| { v.evaluations_len() == 1 << num_var_with_rotation })
            );
        }

        if let Some(gkr_circuit) = gkr_circuit {
            // opcode must have at least one read/write/lookup
            assert!(
                cs.lk_expressions.is_empty()
                    || !cs.r_expressions.is_empty()
                    || !cs.w_expressions.is_empty(),
                "assert opcode circuit"
            );

            let (_, gkr_circuit_out) = gkr_witness::<E, PCS, PB, PD>(
                gkr_circuit,
                &input.witness,
                &input.structural_witness,
                &input.fixed,
                &input.public_input,
                challenges,
            );
            (gkr_circuit_out.0.0, true)
        } else {
            (
                <PD as MainSumcheckProver<PB>>::table_witness(device, input, cs, challenges),
                false,
            )
        }
    };
    (mles, is_padded)
}

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
    pub_io: &[Arc<PB::MultilinearPoly<'b>>],
    challenges: &[E],
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
            .take(phase1_witness_group.len())
            .enumerate()
            .for_each(|(index, witin)| {
                witness_mle_flatten[*witin] = Some(phase1_witness_group[index].clone());
            });

        // TODO process fixed (and probably short) mle
        assert_eq!(
            first_layer.in_eval_expr.len(),
            phase1_witness_group.len(),
            "TODO process fixed (and probably short) mle"
        );
        // XXX currently fixed poly not support in layers > 1

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
        let span = entered_span!("per_layer_gen_witness", profiling_2 = true);
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
            .chain(fixed.iter().cloned())
            .collect_vec();

        // infer current layer output
        let current_layer_output: Vec<Arc<PB::MultilinearPoly<'b>>> =
            <PD as ProtocolWitnessGeneratorProver<PB>>::layer_witness(
                layer,
                &current_layer_wits,
                pub_io,
                challenges,
            );
        layer_wits.push(LayerWitness::new(current_layer_wits, vec![]));

        // process out to prepare output witness
        layer
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(_, out_eval)| out_eval)
            .zip_eq(&current_layer_output)
            .for_each(|(out_eval, out_mle)| match out_eval {
                // note: Linear (x - b)/a has been done and encode in expression
                EvalExpression::Single(out) | EvalExpression::Linear(out, _, _) => {
                    witness_mle_flatten[*out] = Some(out_mle.clone());
                }
                EvalExpression::Zero => { // zero expression
                    // do nothing on zero expression
                }
                other => unimplemented!("{:?}", other),
            });
        exit_span!(span);
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
