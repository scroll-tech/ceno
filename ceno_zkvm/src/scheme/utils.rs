use ff_ext::ExtensionField;
use itertools::Itertools;
pub use multilinear_extensions::wit_infer_by_expr;
use multilinear_extensions::{
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
use witness::next_pow2_instance_padding;

use crate::scheme::constants::MIN_PAR_SIZE;

// first computes the masked mle'[j] = mle[j] if j < num_instance, else default
// then split it into `num_parts` smaller mles
pub(crate) fn masked_mle_split_to_chunks<'a, 'b, E: ExtensionField>(
    mle: &'a MultilinearExtension<'a, E>,
    num_instance: usize,
    num_chunks: usize,
    default: E,
) -> Vec<MultilinearExtension<'b, E>> {
    assert!(num_chunks.is_power_of_two());
    assert!(num_instance <= mle.evaluations().len());

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

/// infer tower witness from last layer
pub(crate) fn infer_tower_product_witness<E: ExtensionField>(
    num_vars: usize,
    last_layer: Vec<MultilinearExtension<'_, E>>,
    num_product_fanin: usize,
) -> Vec<Vec<MultilinearExtension<'_, E>>> {
    assert!(last_layer.len() == num_product_fanin);
    assert_eq!(num_product_fanin % 2, 0);
    let log2_num_product_fanin = ceil_log2(num_product_fanin);
    let mut wit_layers =
        (0..(num_vars / log2_num_product_fanin) - 1).fold(vec![last_layer], |mut acc, _| {
            let next_layer = acc.last().unwrap();
            let cur_len = next_layer[0].evaluations().len() / num_product_fanin;
            let cur_layer: Vec<MultilinearExtension<E>> = (0..num_product_fanin)
                .map(|index| {
                    let mut evaluations = vec![E::ONE; cur_len];
                    next_layer.chunks_exact(2).for_each(|f| {
                        match (f[0].evaluations(), f[1].evaluations()) {
                            (FieldType::Ext(f1), FieldType::Ext(f2)) => {
                                let start: usize = index * cur_len;
                                (start..(start + cur_len))
                                    .into_par_iter()
                                    .zip(evaluations.par_iter_mut())
                                    .with_min_len(MIN_PAR_SIZE)
                                    .map(|(index, evaluations)| {
                                        *evaluations *= f1[index] * f2[index]
                                    })
                                    .collect()
                            }
                            _ => unreachable!("must be extension field"),
                        }
                    });
                    evaluations.into_mle()
                })
                .collect_vec();
            acc.push(cur_layer);
            acc
        });
    wit_layers.reverse();
    wit_layers
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
