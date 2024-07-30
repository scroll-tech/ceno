use std::{collections::BTreeMap, sync::Arc};

use ark_std::test_rng;
use ff::Field;
use ff_ext::ExtensionField;
use gkr::{entered_span, exit_span};
use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{DenseMultilinearExtension, IntoMLE, MultilinearExtension},
    op_mle,
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
};
use rayon::iter::{self, IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use simple_frontend::structs::WitnessId;
use singer_utils::structs_v2::Circuit;
use sumcheck::structs::IOPProverStateV2;
use transcript::Transcript;

use crate::{error::ZKVMError, utils::get_challenge_pows};

use super::ZKVMProof;

const MIN_PAR_SIZE: usize = 64;
const MAINCONSTRAIN_SUMCHECK_BATCH_SIZE: usize = 2;

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
        // TODO remove test_rng
        let mut rng = test_rng();

        let circuit = &self.circuit;
        let log2_instances = ceil_log2(num_instances);
        let next_pow2_instances = 1 << log2_instances;

        // sanity check
        assert_eq!(witnesses.len(), circuit.num_witin as usize);
        witnesses.iter().all(|(_, v)| {
            v.num_vars() == log2_instances && v.evaluations().len() == next_pow2_instances
        });

        // main constraint: read/write record witness inference
        let span = entered_span!("wit_inference::record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = circuit
            .r_expressions
            .iter()
            .chain(circuit.w_expressions.iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
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
                                (1, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        0,
                                        vec![a[0] + b[0]],
                                    ))
                                }
                                (1, _) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(b.len()),
                                        b.par_iter()
                                            .with_min_len(MIN_PAR_SIZE)
                                            .map(|b| a[0] + *b)
                                            .collect(),
                                    ))
                                }
                                (_, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter()
                                            .with_min_len(MIN_PAR_SIZE)
                                            .map(|a| *a + b[0])
                                            .collect(),
                                    ))
                                }
                                (_, _) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter()
                                            .zip(b.par_iter())
                                            .with_min_len(MIN_PAR_SIZE)
                                            .map(|(a, b)| *a + b)
                                            .collect(),
                                    ))
                                }
                            }
                        })
                    },
                    &|a, b| {
                        commutative_op_mle_pair!(|a, b| {
                            match (a.len(), b.len()) {
                                (1, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        0,
                                        vec![a[0] * b[0]],
                                    ))
                                }
                                (1, _) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(b.len()),
                                        b.par_iter()
                                            .with_min_len(MIN_PAR_SIZE)
                                            .map(|b| a[0] * *b)
                                            .collect(),
                                    ))
                                }
                                (_, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter()
                                            .with_min_len(MIN_PAR_SIZE)
                                            .map(|a| *a * b[0])
                                            .collect(),
                                    ))
                                }
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
            })
            .collect();
        let (r_records_wit, w_records_wit) = records_wit.split_at(circuit.r_expressions.len());
        println!("r_records_wit {:?}", r_records_wit,);
        println!("w_records_wit {:?}", w_records_wit);
        exit_span!(span);

        // product constraint: tower witness inference
        let span = entered_span!("wit_inference::tower_witness");
        // TODO
        // we dont make the last layer as new vector to save memory
        exit_span!(span);

        // product constraint tower sumcheck
        let span = entered_span!("sumcheck::tower");
        // TODO
        exit_span!(span);

        // main constraints degree > 1 + selector sumcheck
        let span = entered_span!("sumcheck::main_sel");
        let (r_counts_per_instance, w_counts_per_instance) =
            (circuit.r_expressions.len(), circuit.w_expressions.len());
        let (log2_r_count, log2_w_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
        );
        // TODO fix rt_r/rt_w to use real
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            iter::repeat(E::random(&mut rng))
                .take(log2_instances + log2_r_count)
                .collect(),
            iter::repeat(E::random(&mut rng))
                .take(log2_instances + log2_w_count)
                .collect(),
        );
        let mut virtual_poly = VirtualPolynomialV2::<E>::new(log2_instances);
        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);

        assert_eq!(
            &rt_r[log2_r_count..].len(),
            &rt_w[log2_w_count..].len(),
            "instance var didn't match"
        );
        // create selector: all ONE, but padding ZERO to ceil_log2
        let (sel_r, sel_w): (ArcMultilinearExtension<E>, ArcMultilinearExtension<E>) = {
            let mut sel_r = build_eq_x_r_vec(&rt_r[log2_r_count..]);
            println!("num_instances {}, sel_r {}", num_instances, sel_r.len());
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
        for i in 0..r_counts_per_instance {
            // \sum_t (sel(rt_r[log2_r_count..], t) * (\sum_i alpha_read * eq(rt_r[..log2_r_count], i) * record_r[i] ))
            virtual_poly.add_mle_list(
                vec![sel_r.clone(), r_records_wit[i].clone()],
                eq_r[i] * alpha_read,
            );
        }
        for i in r_counts_per_instance..r_counts_per_instance.next_power_of_two() {
            // \sum_t (sel(rt_r[log2_r_count..], t) * (\sum_i alpha_read * eq(rt_r[..log2_r_count], i)))
            virtual_poly.add_mle_list(vec![sel_r.clone()], eq_r[i] * alpha_read - E::ONE);
        }
        // write
        for i in 0..w_counts_per_instance {
            // \sum_t (sel(rt_w[log2_w_count..], t) * (\sum_i alpha_write * eq(rt_w[..log2_w_count], i) * record_w[i] ))
            virtual_poly.add_mle_list(
                vec![sel_w.clone(), w_records_wit[i].clone()],
                eq_w[i] * alpha_write,
            );
        }
        for i in w_counts_per_instance..w_counts_per_instance.next_power_of_two() {
            // \sum_t (sel(rt_w[log2_w_count..], t) * (\sum_i alpha_write * eq(rt_w[..log2_w_count], i) - 1))
            virtual_poly.add_mle_list(vec![sel_w.clone()], eq_w[i] * alpha_write - E::ONE);
        }
        let (proof, state) = IOPProverStateV2::prove_parallel(virtual_poly, transcript);
        let evals = state.get_mle_final_evaluations();
        assert_eq!(
            evals.len(),
            r_counts_per_instance + w_counts_per_instance + 2
        ); // 2 from [sel_r, sel_w]
        let point = proof.point.clone();
        println!("evals {:?}", evals,);
        println!("point {:?}", point);

        exit_span!(span);

        Ok(ZKVMProof {
            input_point_and_evals: vec![],
        })
    }
}
