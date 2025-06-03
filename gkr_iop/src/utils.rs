use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
    wit_infer_by_expr,
};
use p3_field::PrimeCharacteristicRing;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
        ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{
    evaluation::EvalExpression,
    gkr::{booleanhypercube::BooleanHypercube, layer::Layer},
};

pub fn infer_layer_witness<'a, E>(
    layer: &Layer<E>,
    layer_wits: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
) -> Vec<ArcMultilinearExtension<'a, E>>
where
    E: ExtensionField,
{
    let out_evals: Vec<_> = layer
        .expr_evals
        .iter()
        .flat_map(|(_, out_eval)| out_eval.iter())
        .collect();
    layer
        .exprs
        .par_iter()
        .zip_eq(layer.expr_names.par_iter())
        .zip_eq(out_evals.par_iter())
        .map(|((expr, expr_name), out_eval)| match out_eval {
            EvalExpression::Single(_) => {
                wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr)
            }
            EvalExpression::Linear(0, _, _) => {
                // sanity check: zero mle
                if cfg!(debug_assertions) {
                    let out_mle = wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr);
                    let all_zero = match out_mle.evaluations() {
                        multilinear_extensions::mle::FieldType::Base(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::BaseField::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Ext(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Unreachable => unreachable!(),
                    };
                    if !all_zero {
                        panic!(
                            "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                            layer.name
                        );
                    }
                }
                MultilinearExtension::default().into()
            }
            _ => unimplemented!(),
        })
        .collect::<Vec<_>>()
}

pub fn rotation_next_base_mle<'a, E: ExtensionField>(
    mle: &ArcMultilinearExtension<'a, E>,
    cyclic_subgroup_size: usize,
    cyclic_group_log2_size: usize,
) -> MultilinearExtension<'a, E> {
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    assert!(cyclic_subgroup_size < cyclic_group_size);
    let bh = BooleanHypercube::new(cyclic_group_log2_size);
    let rotation_index = bh.into_iter().take(cyclic_subgroup_size + 1).collect_vec();
    let mut rotated_mle_evals = Vec::with_capacity(mle.evaluations().len());
    rotated_mle_evals.par_extend(
        (0..mle.evaluations().len())
            .into_par_iter()
            .map(|_| E::BaseField::ZERO),
    );
    rotated_mle_evals
        .par_chunks_mut(cyclic_group_size)
        .zip(mle.get_base_field_vec().par_chunks(cyclic_group_size))
        .for_each(|(rotate_chunk, original_chunk)| {
            let first = rotation_index[0] as usize;
            let last = rotation_index[rotation_index.len() - 1] as usize;

            if first == last {
                rotate_chunk[last] = original_chunk[first]
            }

            for i in (0..rotation_index.len() - 1).rev() {
                let to = rotation_index[i] as usize;
                let from = rotation_index[i + 1] as usize;
                rotate_chunk[to] = original_chunk[from];
            }
        });
    MultilinearExtension::from_evaluation_vec_smart(mle.num_vars(), rotated_mle_evals)
}

pub fn rotation_selector<'a, E: ExtensionField>(
    cyclic_subgroup_size: usize,
    cyclic_group_log2_size: usize,
    total_len: usize,
) -> MultilinearExtension<'a, E> {
    assert!(total_len.is_power_of_two());
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    assert!(cyclic_subgroup_size <= cyclic_group_size);
    let bh = BooleanHypercube::new(cyclic_group_log2_size);
    let rotation_index = bh.into_iter().take(cyclic_subgroup_size).collect_vec();
    let mut rotated_mle_evals = Vec::with_capacity(total_len);
    rotated_mle_evals.par_extend((0..total_len).into_par_iter().map(|_| E::BaseField::ZERO));
    rotated_mle_evals
        .par_chunks_mut(cyclic_group_size)
        .for_each(|rotate_chunk| {
            for i in (0..rotation_index.len()).rev() {
                let to = rotation_index[i] as usize;
                rotate_chunk[to] = E::BaseField::ONE;
            }
        });
    MultilinearExtension::from_evaluation_vec_smart(ceil_log2(total_len), rotated_mle_evals)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ff_ext::GoldilocksExt2;
    use p3_goldilocks::Goldilocks;

    use super::*;

    fn make_mle<'a, E: ExtensionField>(
        values: Vec<E::BaseField>,
    ) -> ArcMultilinearExtension<'a, E> {
        Arc::new(MultilinearExtension::from_evaluation_vec_smart(
            values.len().ilog2() as usize,
            values,
        ))
    }

    #[test]
    fn test_rotation_next_non_cyclic() {
        type E = GoldilocksExt2;
        let mle = make_mle::<E>((0..32u64).map(Goldilocks::from_u64).collect_vec());
        let full_rotated = rotation_next_base_mle(&mle, 31, 5);
        assert_eq!(
            full_rotated
                .get_base_field_vec()
                .iter()
                .filter(|v| **v == Goldilocks::ZERO)
                .count(),
            1 // only position 0 not rotate
        );

        let partial_rotate = rotation_next_base_mle(&mle, 23, 5);
        assert_eq!(
            partial_rotate
                .get_base_field_vec()
                .iter()
                .filter(|v| **v == Goldilocks::ZERO)
                .count(),
            9,
        );
    }

    #[test]
    fn test_rotation_selector() {
        type E = GoldilocksExt2;
        let sel = rotation_selector::<E>(23, 5, 32);
        assert_eq!(
            sel.get_base_field_vec()
                .iter()
                .filter(|v| **v == Goldilocks::ZERO)
                .count(),
            9,
        );
    }
}
