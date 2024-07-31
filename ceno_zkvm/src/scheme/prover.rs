use std::{collections::BTreeMap, sync::Arc};

use ff_ext::ExtensionField;
use gkr::{entered_span, exit_span};
use itertools::Itertools;
use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{DenseMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    op_mle,
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator,
        ParallelIterator,
    },
    prelude::ParallelSliceMut,
};
use simple_frontend::structs::WitnessId;
use singer_utils::{structs_v2::Circuit, util_v2::Expression};
use sumcheck::structs::IOPProverStateV2;
use transcript::Transcript;

use crate::{
    error::ZKVMError,
    scheme::constants::{MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, MIN_PAR_SIZE, PRODUCT_ARGUMENT_SIZE},
    utils::get_challenge_pows,
};

use super::ZKVMProof;

pub struct ZKVMProver<E: ExtensionField> {
    circuit: Circuit<E>,
}

impl<E: ExtensionField> ZKVMProver<E> {
    pub fn new(circuit: Circuit<E>) -> Self {
        ZKVMProver { circuit }
    }
    pub fn create_proof(
        &self,
        witnesses: BTreeMap<WitnessId, DenseMultilinearExtension<E>>,
        num_instances: usize,
        transcript: &mut Transcript<E>,
        challenges: &[E],
    ) -> Result<ZKVMProof<E>, ZKVMError> {
        let circuit = &self.circuit;
        let log2_num_instances = ceil_log2(num_instances);
        let next_pow2_instances = 1 << log2_num_instances;

        // sanity check
        assert_eq!(witnesses.len(), circuit.num_witin as usize);
        witnesses.iter().all(|(_, v)| {
            v.num_vars() == log2_num_instances && v.evaluations().len() == next_pow2_instances
        });

        // main constraint: read/write record witness inference
        let span = entered_span!("wit_inference::record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = circuit
            .r_expressions
            .iter()
            .chain(circuit.w_expressions.iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&witnesses, &challenges, expr)
            })
            .collect();
        let (r_records_wit, w_records_wit) = records_wit.split_at(circuit.r_expressions.len());
        println!("r_records_wit {:?}", r_records_wit,);
        println!("w_records_wit {:?}", w_records_wit);
        exit_span!(span);

        // product constraint: tower witness inference
        let (r_counts_per_instance, w_counts_per_instance) =
            (circuit.r_expressions.len(), circuit.w_expressions.len());
        let (log2_r_count, log2_w_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
        );
        // process last layer by interleaving all the read/write record respectively
        // as last layer is the output of sel stage
        let span = entered_span!("wit_inference::tower_witness_r_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let r_records_last_layer = interleaving_mles_to_mles(
            r_records_wit,
            log2_num_instances,
            log2_r_count,
            PRODUCT_ARGUMENT_SIZE,
        );
        assert_eq!(r_records_last_layer.len(), PRODUCT_ARGUMENT_SIZE);
        exit_span!(span);

        // infer all tower witness after last layer
        let span = entered_span!("wit_inference::tower_witness_r_layers");
        let r_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_r_count,
            r_records_last_layer,
            PRODUCT_ARGUMENT_SIZE,
        );
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let w_records_last_layer = interleaving_mles_to_mles(
            w_records_wit,
            log2_num_instances,
            log2_w_count,
            PRODUCT_ARGUMENT_SIZE,
        );
        assert_eq!(w_records_last_layer.len(), PRODUCT_ARGUMENT_SIZE);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_layers");
        let w_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_w_count,
            w_records_last_layer,
            PRODUCT_ARGUMENT_SIZE,
        );
        exit_span!(span);

        if cfg!(test) {
            // sanity check
            assert_eq!(r_wit_layers.len(), (log2_num_instances + log2_r_count));
            assert_eq!(w_wit_layers.len(), (log2_num_instances + log2_w_count));
            assert!(r_wit_layers.iter().enumerate().all(|(i, r_wit_layer)| {
                let expected_size = 1 << i;
                r_wit_layer.len() == PRODUCT_ARGUMENT_SIZE
                    && r_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
            assert!(w_wit_layers.iter().enumerate().all(|(i, w_wit_layer)| {
                let expected_size = 1 << i;
                w_wit_layer.len() == PRODUCT_ARGUMENT_SIZE
                    && w_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
        }

        // product constraint tower sumcheck
        let span = entered_span!("sumcheck::tower");
        // TODO
        exit_span!(span);

        // main constraints degree > 1 + selector sumcheck
        let span = entered_span!("sumcheck::main_sel");
        // TODO fix rt_r/rt_w to use real
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            (0..(log2_num_instances + log2_r_count))
                .map(|i| E::from(i as u64))
                .collect(),
            (0..(log2_num_instances + log2_w_count))
                .map(|i| E::from(i as u64))
                .collect(),
        );
        // TODO fix record_r_eval, record_w_eval
        let (record_r_eval, record_w_eval) = (E::from(5u64), E::from(7u64));
        let mut virtual_poly = VirtualPolynomialV2::<E>::new(log2_num_instances);
        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);
        println!(
            "prover alpha_read {:?} alpha_write {:?}",
            alpha_read, alpha_write
        );

        assert_eq!(
            &rt_r[log2_r_count..].len(),
            &rt_w[log2_w_count..].len(),
            "instance var didn't match"
        );
        // create selector: all ONE, but padding ZERO to ceil_log2
        let (sel_r, sel_w): (ArcMultilinearExtension<E>, ArcMultilinearExtension<E>) = {
            let mut sel_r = build_eq_x_r_vec(&rt_r[log2_r_count..]);
            if num_instances < sel_r.len() {
                sel_r.splice(num_instances..sel_r.len(), std::iter::repeat(E::ZERO));
            }
            let mut sel_w = build_eq_x_r_vec(&rt_w[log2_w_count..]);
            if num_instances < sel_w.len() {
                sel_w.splice(num_instances..sel_w.len(), std::iter::repeat(E::ZERO));
            }
            (Arc::new(sel_r.into_mle()), Arc::new(sel_w.into_mle()))
        };
        let eq_r = build_eq_x_r_vec(&rt_r[..log2_r_count]);
        let eq_w = build_eq_x_r_vec(&rt_w[..log2_w_count]);

        // read
        // rt_r := rt || rs
        for i in 0..r_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_read * eq(rs, i) * record_r[i] ))
            virtual_poly.add_mle_list(
                vec![sel_r.clone(), r_records_wit[i].clone()],
                eq_r[i] * alpha_read,
            );
        }
        for i in r_counts_per_instance..r_counts_per_instance.next_power_of_two() {
            // \sum_t (sel(rt, t) * (\sum_i alpha_read * (eq(rs, i) - 1)))
            virtual_poly.add_mle_list(vec![sel_r.clone()], *alpha_read * (eq_r[i] - E::ONE));
        }

        // write
        // rt := rt || rs
        for i in 0..w_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_write * eq(rs, i) * record_w[i] ))
            virtual_poly.add_mle_list(
                vec![sel_w.clone(), w_records_wit[i].clone()],
                eq_w[i] * alpha_write,
            );
        }
        for i in w_counts_per_instance..w_counts_per_instance.next_power_of_two() {
            // \sum_t (sel(rt, t) * (\sum_i alpha_write * (eq(rs, i) - 1)))
            virtual_poly.add_mle_list(vec![sel_w.clone()], *alpha_write * (eq_w[i] - E::ONE));
        }
        let (main_sel_sumcheck_proofs, state) =
            IOPProverStateV2::prove_parallel(virtual_poly, transcript);
        let main_sel_evals = state.get_mle_final_evaluations();
        assert_eq!(
            main_sel_evals.len(),
            r_counts_per_instance + w_counts_per_instance + 2
        ); // 2 from [sel_r, sel_w]
        let r_records_in_evals = main_sel_evals.as_slice()[1..][..r_counts_per_instance].to_vec(); // 1 to skip first sel
        let w_records_in_evals = main_sel_evals.as_slice()[2 + r_counts_per_instance..] // 2 to skip read/write sel
            [..w_counts_per_instance]
            .to_vec();
        assert!(
            r_records_in_evals.len() == r_counts_per_instance
                && w_records_in_evals.len() == w_counts_per_instance
        );
        let input_open_point = main_sel_sumcheck_proofs.point.clone();
        assert!(input_open_point.len() == log2_num_instances);
        println!("evals {:?}", main_sel_evals,);
        println!("point {:?}", input_open_point);
        exit_span!(span);

        let span = entered_span!("witin::evals");
        let wits_in_evals = witnesses
            .par_iter()
            .map(|(_, poly)| poly.evaluate(&input_open_point))
            .collect();
        exit_span!(span);

        Ok(ZKVMProof {
            num_instances,
            out_record_r_eval: record_r_eval,
            out_record_w_eval: record_w_eval,
            main_sel_sumcheck_proofs: main_sel_sumcheck_proofs.proofs,
            r_records_in_evals,
            w_records_in_evals,
            wits_in_evals,
        })
    }
}

/// interleaving multiple mles into mles for the product/logup arguments last layer witness
fn interleaving_mles_to_mles<'a, E: ExtensionField>(
    mles: &[ArcMultilinearExtension<E>],
    log2_num_instances: usize,
    log2_per_instance_size: usize,
    product_argument_size: usize,
) -> Vec<ArcMultilinearExtension<'a, E>> {
    assert!(product_argument_size.is_power_of_two());
    let mle_group_len = mles.len() / product_argument_size;
    let log_product_argument_size = ceil_log2(product_argument_size);
    mles.chunks(mle_group_len)
        .map(|records_mle| {
            // interleaving records witness into single vector
            let mut evaluations = vec![
                E::ONE;
                1 << (log2_num_instances + log2_per_instance_size
                    - log_product_argument_size)
            ];
            let per_instance_size = 1 << (log2_per_instance_size - log_product_argument_size);
            records_mle
                .iter()
                .enumerate()
                .for_each(|(record_i, record_mle)| match record_mle.evaluations() {
                    FieldType::Ext(record_mle) => record_mle
                        .par_iter()
                        .zip(evaluations.par_chunks_mut(per_instance_size))
                        .with_min_len(MIN_PAR_SIZE)
                        .for_each(|(value, instance)| {
                            assert_eq!(instance.len(), per_instance_size);
                            instance[record_i] = *value;
                        }),
                    _ => {
                        unreachable!("must be extension field")
                    }
                });
            evaluations.into_mle().into()
        })
        .collect::<Vec<ArcMultilinearExtension<E>>>()
}

/// infer tower witness from last layer
fn infer_tower_product_witness<'a, E: ExtensionField>(
    num_vars: usize,
    last_layer: Vec<ArcMultilinearExtension<'a, E>>,
    product_argument_size: usize,
) -> Vec<Vec<ArcMultilinearExtension<'a, E>>> {
    assert!(last_layer.len() == product_argument_size);
    let mut r_wit_layers = (0..num_vars - 1).fold(vec![last_layer], |mut acc, i| {
        let next_layer = acc.last().unwrap();
        let cur_len = next_layer[0].evaluations().len() / product_argument_size;
        let cur_layer: Vec<ArcMultilinearExtension<E>> = (0..product_argument_size)
            .map(|index| {
                let mut evaluations = vec![E::ONE; cur_len];
                next_layer.iter().for_each(|f| match f.evaluations() {
                    FieldType::Ext(f) => {
                        let start: usize = index * cur_len;
                        f[start..][..cur_len]
                            .par_iter()
                            .zip(evaluations.par_iter_mut())
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|(v, evaluations)| *evaluations *= *v)
                            .collect()
                    }
                    _ => unreachable!("must be extension field"),
                });
                println!("i {} evaluation {:?} ", i, evaluations);
                evaluations.into_mle().into()
            })
            .collect_vec();
        acc.push(cur_layer);
        acc
    });
    r_wit_layers.reverse();
    r_wit_layers
}

fn wit_infer_by_expr<'a, E: ExtensionField>(
    witnesses: &BTreeMap<WitnessId, DenseMultilinearExtension<E>>,
    challenges: &[E],
    expr: &Expression<E>,
) -> ArcMultilinearExtension<'a, E> {
    expr.evaluate::<ArcMultilinearExtension<'_, E>>(
        &|witness_id| {
            let a: ArcMultilinearExtension<E> = Arc::new(
                witnesses
                    .get(&witness_id)
                    .expect("non exist witness")
                    .clone(),
            );
            a
        },
        &|scalar| {
            let scalar: ArcMultilinearExtension<E> = Arc::new(
                DenseMultilinearExtension::from_evaluations_vec(0, vec![scalar]),
            );
            scalar
        },
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be aquire once for each power
            let challenge = challenges[challenge_id as usize];
            let challenge: ArcMultilinearExtension<E> =
                Arc::new(DenseMultilinearExtension::from_evaluations_ext_vec(
                    0,
                    vec![challenge.pow(&[pow as u64]) * scalar + offset],
                ));
            challenge
        },
        &|a, b| {
            commutative_op_mle_pair!(|a, b| {
                match (a.len(), b.len()) {
                    (1, 1) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        0,
                        vec![a[0] + b[0]],
                    )),
                    (1, _) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(b.len()),
                        b.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|b| a[0] + *b)
                            .collect(),
                    )),
                    (_, 1) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|a| *a + b[0])
                            .collect(),
                    )),
                    (_, _) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .zip(b.par_iter())
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|(a, b)| *a + b)
                            .collect(),
                    )),
                }
            })
        },
        &|a, b| {
            commutative_op_mle_pair!(|a, b| {
                match (a.len(), b.len()) {
                    (1, 1) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        0,
                        vec![a[0] * b[0]],
                    )),
                    (1, _) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(b.len()),
                        b.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|b| a[0] * *b)
                            .collect(),
                    )),
                    (_, 1) => Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|a| *a * b[0])
                            .collect(),
                    )),
                    (_, _) => {
                        unimplemented!("r,w only support degree 1 expression")
                    }
                }
            })
        },
        &|a, scalar| {
            op_mle!(|a| {
                Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                    ceil_log2(a.len()),
                    a.par_iter()
                        .with_min_len(MIN_PAR_SIZE)
                        .map(|a| scalar * a)
                        .collect(),
                ))
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use goldilocks::{ExtensionField, GoldilocksExt2};
    use multilinear_extensions::{
        commutative_op_mle_pair,
        mle::{FieldType, IntoMLE},
        op_mle,
        util::ceil_log2,
        virtual_poly_v2::ArcMultilinearExtension,
    };

    use crate::scheme::prover::{infer_tower_product_witness, interleaving_mles_to_mles};

    #[test]
    fn test_infer_tower_witness() {
        type E = GoldilocksExt2;
        let product_argument_size = 2;
        let last_layer: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::ONE, E::from(2u64)].into_mle().into(),
            vec![E::from(3u64), E::from(4u64)].into_mle().into(),
        ];
        let num_vars = ceil_log2(last_layer[0].evaluations().len()) + 1;
        let res = infer_tower_product_witness(num_vars, last_layer.clone(), 2);
        let (left, right) = (&res[0][0], &res[0][1]);
        let final_product = commutative_op_mle_pair!(
            |left, right| {
                assert!(left.len() == 1 && right.len() == 1);
                left[0] * right[0]
            },
            |out| E::from_base(&out)
        );
        let expected_final_product: E = last_layer
            .iter()
            .map(|f| match f.evaluations() {
                FieldType::Ext(e) => e.iter().cloned().reduce(|a, b| a * b).unwrap(),
                _ => unreachable!(""),
            })
            .product();
        assert_eq!(res.len(), num_vars);
        assert!(
            res.iter()
                .all(|layer_wit| layer_wit.len() == product_argument_size)
        );
        assert_eq!(final_product, expected_final_product);
    }

    #[test]
    fn test_interleaving_mles_to_mles() {
        type E = GoldilocksExt2;
        let product_argument_size = 2;
        // [[1, 2], [3, 4]]
        let input_mles: Vec<ArcMultilinearExtension<E>> = vec![
            vec![E::ONE, E::from(2u64)].into_mle().into(),
            vec![E::from(3u64), E::from(4u64)].into_mle().into(),
        ];
        let res = interleaving_mles_to_mles(&input_mles, 1, 2, product_argument_size);
        // [[1, 1, 2, 1], [3, 1, 4, 1]]
        assert!(res[0].get_ext_field_vec() == vec![E::ONE, E::ONE, E::from(2u64), E::ONE],);
        assert!(res[1].get_ext_field_vec() == vec![E::from(3u64), E::ONE, E::from(4u64), E::ONE]);
    }
}
