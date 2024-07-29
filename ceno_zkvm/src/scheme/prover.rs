use std::{collections::BTreeMap, process::Output, sync::Arc};

use ff_ext::ExtensionField;
use gkr::{entered_span, exit_span};
use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension, IntoMLE, MultilinearExtension},
    op_mle,
    util::ceil_log2,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
};
use rayon::iter::{
    self, IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use simple_frontend::structs::WitnessId;
use singer_utils::structs_v2::Circuit;
use transcript::Transcript;

use crate::error::ZKVMError;

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
        _transcript: &mut Transcript<E>,
        challenges: &[E],
    ) -> Result<ZKVMProof, ZKVMError> {
        let circuit = &self.circuit;
        let log2_instances = ceil_log2(num_instances);
        let next_pow2_instances = 1 << log2_instances;

        // sanity check
        assert_eq!(witnesses.len(), circuit.num_witin as usize);
        witnesses.iter().all(|(_, v)| {
            v.num_vars() == log2_instances && v.evaluations().len() == next_pow2_instances
        });

        // main constraint: read record witness inference
        let span = entered_span!("inference::read_record_evaluation");
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
                        // TODO cache challenge power to be aquire once
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
                                        b.par_iter().with_min_len(64).map(|b| a[0] + *b).collect(),
                                    ))
                                }
                                (_, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter().with_min_len(64).map(|a| *a + b[0]).collect(),
                                    ))
                                }
                                (_, _) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter()
                                            .zip(b.par_iter())
                                            .with_min_len(64)
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
                                        b.par_iter().with_min_len(64).map(|b| a[0] * *b).collect(),
                                    ))
                                }
                                (_, 1) => {
                                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                                        ceil_log2(a.len()),
                                        a.par_iter().with_min_len(64).map(|a| *a * b[0]).collect(),
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
                                a.par_iter().with_min_len(64).map(|a| scalar * a).collect(),
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

        // construct main constraint sumcheck virtual polynomial

        // build first part of sumcheck: selector
        // circuit.

        Ok(ZKVMProof {})
    }
}
