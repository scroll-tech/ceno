use std::{cmp::max, collections::BTreeMap, mem, sync::Arc};

use ff_ext::ExtensionField;
use gkr::{entered_span, exit_span, structs::Point};

use itertools::Itertools;
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use simple_frontend::structs::WitnessId;
use sumcheck::structs::{IOPProverMessage, IOPProverStateV2};
use transcript::Transcript;

use crate::{
    circuit_builder::Circuit,
    error::ZKVMError,
    scheme::{
        constants::{MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, NUM_PRODUCT_FANIN},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, interleaving_mles_to_mles,
            wit_infer_by_expr,
        },
    },
    structs::{TowerProofs, TowerProver, TowerProverSpec},
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

    /// create proof giving witness and num_instances
    /// major flow break down into
    /// 1: witness layer inferring from input -> output
    /// 2: proof (sumcheck reduce) from output to input
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
            .par_iter()
            .chain(circuit.w_expressions.par_iter())
            .chain(circuit.lk_expressions.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&witnesses, &challenges, expr)
            })
            .collect();
        let (r_records_wit, w_lk_records_wit) = records_wit.split_at(circuit.r_expressions.len());
        let (w_records_wit, lk_records_wit) =
            w_lk_records_wit.split_at(circuit.w_expressions.len());
        exit_span!(span);

        // product constraint: tower witness inference
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) = (
            circuit.r_expressions.len(),
            circuit.w_expressions.len(),
            circuit.lk_expressions.len(),
        );
        let (log2_r_count, log2_w_count, log2_lk_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
            ceil_log2(lk_counts_per_instance),
        );
        // process last layer by interleaving all the read/write record respectively
        // as last layer is the output of sel stage
        let span = entered_span!("wit_inference::tower_witness_r_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let r_records_last_layer = interleaving_mles_to_mles(
            r_records_wit,
            log2_num_instances,
            log2_r_count,
            NUM_PRODUCT_FANIN,
            E::ONE,
        );
        assert_eq!(r_records_last_layer.len(), NUM_PRODUCT_FANIN);
        exit_span!(span);

        // infer all tower witness after last layer
        let span = entered_span!("wit_inference::tower_witness_r_layers");
        let r_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_r_count,
            r_records_last_layer,
            NUM_PRODUCT_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let w_records_last_layer = interleaving_mles_to_mles(
            w_records_wit,
            log2_num_instances,
            log2_w_count,
            NUM_PRODUCT_FANIN,
            E::ONE,
        );
        assert_eq!(w_records_last_layer.len(), NUM_PRODUCT_FANIN);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_layers");
        let w_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_w_count,
            w_records_last_layer,
            NUM_PRODUCT_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_lk_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let lk_records_last_layer = interleaving_mles_to_mles(
            lk_records_wit,
            log2_num_instances,
            log2_lk_count,
            2,
            E::ZERO,
        );
        assert_eq!(lk_records_last_layer.len(), 1);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_lk_layers");
        let lk_wit_layers =
            infer_tower_logup_witness(log2_num_instances + log2_lk_count, lk_records_last_layer);
        exit_span!(span);

        if cfg!(test) {
            // sanity check
            assert_eq!(r_wit_layers.len(), (log2_num_instances + log2_r_count));
            assert_eq!(w_wit_layers.len(), (log2_num_instances + log2_w_count));
            assert!(r_wit_layers.iter().enumerate().all(|(i, r_wit_layer)| {
                let expected_size = 1 << (ceil_log2(NUM_PRODUCT_FANIN) * i);
                r_wit_layer.len() == NUM_PRODUCT_FANIN
                    && r_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
            assert!(w_wit_layers.iter().enumerate().all(|(i, w_wit_layer)| {
                let expected_size = 1 << (ceil_log2(NUM_PRODUCT_FANIN) * i);
                w_wit_layer.len() == NUM_PRODUCT_FANIN
                    && w_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
        }

        // product constraint tower sumcheck
        let span = entered_span!("sumcheck::tower");
        // final evals for verifier
        let record_r_out_evals: Vec<E> = r_wit_layers[0]
            .iter()
            .map(|w| w.get_ext_field_vec()[0])
            .collect();
        let record_w_out_evals: Vec<E> = w_wit_layers[0]
            .iter()
            .map(|w| w.get_ext_field_vec()[0])
            .collect();
        assert!(
            record_r_out_evals.len() == NUM_PRODUCT_FANIN
                && record_w_out_evals.len() == NUM_PRODUCT_FANIN
        );
        let (rt_tower, tower_proof) = TowerProver::create_proof(
            vec![
                TowerProverSpec {
                    witness: r_wit_layers,
                },
                TowerProverSpec {
                    witness: w_wit_layers,
                },
            ],
            NUM_PRODUCT_FANIN,
            transcript,
        );
        assert_eq!(
            rt_tower.len(),
            log2_num_instances + max(log2_r_count, log2_w_count) // TODO add lookup count
        );
        exit_span!(span);

        // batch sumcheck: selector + main degree > 1 constraints
        let span = entered_span!("sumcheck::main_sel");
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            rt_tower[..log2_num_instances + log2_r_count].to_vec(),
            rt_tower[..log2_num_instances + log2_w_count].to_vec(),
        );

        let mut virtual_poly = VirtualPolynomialV2::<E>::new(log2_num_instances);
        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);
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
            // \sum_t (sel(rt, t) * (\sum_i alpha_read * eq(rs, i) * record_r[t] ))
            virtual_poly.add_mle_list(
                vec![sel_r.clone(), r_records_wit[i].clone()],
                eq_r[i] * alpha_read,
            );
        }
        // \sum_t alpha_read * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_poly.add_mle_list(
            vec![sel_r.clone()],
            *alpha_read * eq_r[r_counts_per_instance..].iter().sum::<E>() - *alpha_read,
        );

        // write
        // rt := rt || rs
        for i in 0..w_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_write * eq(rs, i) * record_w[i] ))
            virtual_poly.add_mle_list(
                vec![sel_w.clone(), w_records_wit[i].clone()],
                eq_w[i] * alpha_write,
            );
        }
        // \sum_t alpha_write * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_poly.add_mle_list(
            vec![sel_w.clone()],
            *alpha_write * eq_w[w_counts_per_instance..].iter().sum::<E>() - *alpha_write,
        );
        let (main_sel_sumcheck_proofs, state) =
            IOPProverStateV2::prove_parallel(virtual_poly, transcript);
        let main_sel_evals = state.get_mle_final_evaluations();
        assert_eq!(
            main_sel_evals.len(),
            r_counts_per_instance + w_counts_per_instance + 2
        ); // 2 from [sel_r, sel_w]
        let r_records_in_evals = main_sel_evals.as_slice()[1..][..r_counts_per_instance].to_vec(); // 1 to skip sel
        let w_records_in_evals = main_sel_evals.as_slice()[2 + r_counts_per_instance..] // 2 to skip read/write sel
            [..w_counts_per_instance]
            .to_vec();
        assert!(
            r_records_in_evals.len() == r_counts_per_instance
                && w_records_in_evals.len() == w_counts_per_instance
        );
        let input_open_point = main_sel_sumcheck_proofs.point.clone();
        assert!(input_open_point.len() == log2_num_instances);
        exit_span!(span);

        let span = entered_span!("witin::evals");
        let wits_in_evals = witnesses
            .par_iter()
            .map(|(_, poly)| poly.evaluate(&input_open_point))
            .collect();
        exit_span!(span);

        Ok(ZKVMProof {
            num_instances,
            record_r_out_evals,
            record_w_out_evals,
            tower_proof,
            main_sel_sumcheck_proofs: main_sel_sumcheck_proofs.proofs,
            r_records_in_evals,
            w_records_in_evals,
            wits_in_evals,
        })
    }
}

/// TowerProofs
impl<E: ExtensionField> TowerProofs<E> {
    pub fn new(spec_size: usize) -> Self {
        TowerProofs {
            proofs: vec![],
            specs_eval: vec![vec![]; spec_size],
        }
    }
    pub fn push_sumcheck_proofs(&mut self, proofs: Vec<IOPProverMessage<E>>) {
        self.proofs.push(proofs);
    }

    pub fn push_evals(&mut self, spec_index: usize, evals: Vec<E>) {
        self.specs_eval[spec_index].push(evals);
    }

    pub fn spec_size(&self) -> usize {
        return self.specs_eval.len();
    }
}

/// Tower Prover
impl TowerProver {
    pub fn create_proof<'a, E: ExtensionField>(
        mut specs: Vec<TowerProverSpec<'a, E>>,
        num_product_fanin: usize,
        transcript: &mut Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        let mut proofs = TowerProofs::new(specs.len());
        assert!(specs.len() > 0);
        let log2_num_product_fanin = ceil_log2(num_product_fanin);
        // -1 for sliding windows size 2: (cur_layer, next_layer) w.r.t total size
        let max_round = specs.iter().map(|m| m.witness.len()).max().unwrap() - 1;

        // TODO soundness question: should we generate new alpha for each layer?
        let alpha_pows = get_challenge_pows(specs.len(), transcript);
        let initial_rt: Point<E> = (0..log2_num_product_fanin)
            .map(|_| transcript.get_and_append_challenge(b"product_sum").elements)
            .collect_vec();

        let next_rt = (0..max_round).fold(initial_rt, |out_rt, round| {
            let mut virtual_poly = VirtualPolynomialV2::<E>::new(out_rt.len());

            let eq: ArcMultilinearExtension<E> = build_eq_x_r_vec(&out_rt).into_mle().into();

            specs.iter_mut().enumerate().for_each(|(i, s)| {
                if (round + 1) < s.witness.len() {
                    let layer_polys = mem::take(&mut s.witness[round + 1]);

                    // sanity check
                    assert_eq!(layer_polys.len(), num_product_fanin);
                    layer_polys
                        .iter()
                        .all(|f| f.evaluations().len() == 1 << (log2_num_product_fanin * round));

                    // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin}[s]])
                    virtual_poly
                        .add_mle_list(vec![vec![eq.clone()], layer_polys].concat(), alpha_pows[i]);
                }
            });
            let (sumcheck_proofs, state) =
                IOPProverStateV2::prove_parallel(virtual_poly, transcript);
            proofs.push_sumcheck_proofs(sumcheck_proofs.proofs);

            // rt' = r_merge || rt
            let r_merge = (0..log2_num_product_fanin)
                .map(|_| transcript.get_and_append_challenge(b"merge").elements)
                .collect_vec();
            let rt_prime = vec![sumcheck_proofs.point, r_merge].concat();

            let evals = state.get_mle_final_evaluations();
            let mut evals_iter = evals.iter();
            evals_iter.next(); // skip first eq
            specs.iter().enumerate().for_each(|(i, s)| {
                if (round + 1) < s.witness.len() {
                    // collect evals belong to current spec
                    proofs.push_evals(
                        i,
                        (0..num_product_fanin)
                            .map(|_| *evals_iter.next().expect("insufficient evals length"))
                            .collect::<Vec<E>>(),
                    );
                }
            });
            assert_eq!(evals_iter.next(), None);
            rt_prime
        });

        (next_rt, proofs)
    }
}
