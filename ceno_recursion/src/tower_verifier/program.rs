use super::binding::{PointAndEvalVariable, PointVariable};
use crate::{
    arithmetics::{UniPolyExtrapolator, challenger_multi_observe, eq_eval, extend, exts_to_felts},
    tower_verifier::binding::IOPProverMessageVecVariable,
    transcript::transcript_observe_label,
    zkvm_verifier::binding::TowerProofInputVariable,
};
use openvm_native_compiler::prelude::*;
use openvm_native_recursion::challenger::{
    CanObserveVariable, FeltChallenger, duplex::DuplexChallengerVariable,
};
use openvm_stark_backend::p3_field::FieldAlgebra;
const NATIVE_SUMCHECK_CTX_LEN: usize = 12;

pub fn iop_verifier_state_verify<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    out_claim: &Ext<C::F, C::EF>,
    prover_messages: &IOPProverMessageVecVariable<C>,
    max_num_variables: Felt<C::F>,
    max_degree: Felt<C::F>,
    unipoly_extrapolator: &UniPolyExtrapolator<C>,
) -> (
    Array<C, Ext<<C as Config>::F, <C as Config>::EF>>,
    Ext<<C as Config>::F, <C as Config>::EF>,
) {
    // TODO: either store it in a global cache or pass them as parameters
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let zero_f: Felt<C::F> = builder.constant(C::F::ZERO);

    let max_num_variables_usize: Usize<C::N> =
        Usize::from(builder.cast_felt_to_var(max_num_variables));
    challenger.observe(builder, max_num_variables);
    challenger.observe(builder, zero_f);
    challenger.observe(builder, max_degree);
    challenger.observe(builder, zero_f);

    builder.assert_var_eq(max_num_variables_usize.get_var(), prover_messages.len());

    let challenges: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(max_num_variables_usize.clone());
    let expected: Ext<C::F, C::EF> = builder.eval(*out_claim + zero);

    builder.cycle_tracker_start("IOPVerifierState::verify_round_and_update_state");
    builder
        .range(0, max_num_variables_usize.clone())
        .for_each(|i_vec, builder| {
            let i = i_vec[0];

            // TODO: this takes 7 cycles, can we optimize it?
            let prover_msg = prover_messages.get(builder, i.variable());

            unsafe {
                let prover_msg_felts = exts_to_felts(builder, &prover_msg);
                challenger_multi_observe(builder, challenger, &prover_msg_felts);
            }

            transcript_observe_label(builder, challenger, b"Internal round");
            let challenge = challenger.sample_ext(builder);

            let e1 = builder.get(&prover_msg, 0);
            let e0 = builder.eval(expected - e1);
            let p_r =
                unipoly_extrapolator.extrapolate_uni_poly(builder, e0, &prover_msg, challenge);

            builder.assign(&expected, p_r + zero);
            builder.set_value(&challenges, i, challenge);
        });
    builder.cycle_tracker_end("IOPVerifierState::verify_round_and_update_state");

    (challenges, expected)
}

pub fn verify_tower_proof<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    num_prod_spec: Usize<C::N>,
    num_logup_spec: Usize<C::N>,
    prod_out_evals: &Array<C, Ext<C::F, C::EF>>,
    logup_out_evals: &Array<C, Ext<C::F, C::EF>>,
    num_variables: Array<C, Usize<C::N>>,
    _num_fanin: Usize<C::N>,

    // TowerProofVariable
    max_num_variables: Usize<C::N>,

    proof: &TowerProofInputVariable<C>,
    unipoly_extrapolator: &UniPolyExtrapolator<C>,
) -> (
    PointVariable<C>,
    Array<C, PointAndEvalVariable<C>>,
    Array<C, PointAndEvalVariable<C>>,
    Array<C, PointAndEvalVariable<C>>,
) {
    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

    builder.assert_usize_eq(proof.prod_specs_eval.len(), num_prod_spec.clone());
    builder.assert_usize_eq(proof.logup_specs_eval.len(), num_logup_spec.clone());
    builder.assert_usize_eq(
        num_variables.len(),
        num_prod_spec.clone() + num_logup_spec.clone(),
    );

    let var_zero: Var<C::N> = builder.constant(C::N::ZERO);
    let num_specs: Var<C::N> = builder.eval(num_prod_spec.get_var() + num_logup_spec.get_var());
    let should_skip: Array<C, Var<C::N>> = builder.dyn_array(num_specs);
    builder.range(0, num_specs).for_each(|i_vec, builder| {
        let i = i_vec[0];

        // all specs should not be skipped initially
        builder.set_value(&should_skip, i, var_zero);
    });

    transcript_observe_label(builder, challenger, b"combine subset evals");
    let alpha = challenger.sample_ext(builder);

    // initial_claim = \sum_j alpha^j * out_j[rt]
    // out_j[rt] := (record_{j}[rt])
    // out_j[rt] := (logup_p{j}[rt])
    // out_j[rt] := (logup_q{j}[rt])
    let log2_num_fanin = 1usize;
    builder.cycle_tracker_start("initial sum");
    let initial_rt: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(log2_num_fanin);
    transcript_observe_label(builder, challenger, b"product_sum");
    builder
        .range(0, initial_rt.len())
        .for_each(|idx_vec, builder| {
            let idx = idx_vec[0];
            let c = challenger.sample_ext(builder);
            builder.set_value(&initial_rt, idx, c);
        });

    let input_ctx: Array<C, Usize<C::N>> = builder.dyn_array(NATIVE_SUMCHECK_CTX_LEN);
    builder.set(&input_ctx, 0, Usize::from(0));
    builder.set(&input_ctx, 1, num_prod_spec.clone());
    builder.set(&input_ctx, 2, num_logup_spec.clone());
    builder.set(&input_ctx, 3, Usize::from(1));
    builder.set(&input_ctx, 4, Usize::from(2));
    builder.set(&input_ctx, 5, Usize::from(1));
    builder.set(&input_ctx, 6, Usize::from(4));
    builder.set(&input_ctx, 7, Usize::from(0));
    builder.set(&input_ctx, 8, Usize::from(999));

    let challenges: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(3);
    builder.set(&challenges, 0, alpha);
    let r = builder.get(&initial_rt, 0);
    let c1: Ext<C::F, C::EF> = builder.eval(one - r);
    builder.set(&challenges, 1, c1);
    builder.set(&challenges, 2, r);

    let sumcheck_out_len: Usize<C::N> = builder
        .eval(Usize::from(1) + num_prod_spec.clone() + Usize::from(2) * num_logup_spec.clone());
    let sumcheck_out: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(sumcheck_out_len.clone());

    builder.sumcheck_layer_eval(
        &input_ctx,
        &challenges,
        prod_out_evals,
        logup_out_evals,
        &sumcheck_out,
    );
    let initial_claim = builder.get(&sumcheck_out, 0);

    let prod_spec_point_n_eval: Array<C, PointAndEvalVariable<C>> =
        builder.dyn_array(num_prod_spec.clone());
    let logup_spec_p_point_n_eval: Array<C, PointAndEvalVariable<C>> =
        builder.dyn_array(num_logup_spec.clone());
    let logup_spec_q_point_n_eval: Array<C, PointAndEvalVariable<C>> =
        builder.dyn_array(num_logup_spec.clone());

    let idx: Usize<C::N> = builder.eval(C::N::ONE);
    builder
        .range(0, num_prod_spec.clone())
        .for_each(|idx_vec, builder| {
            let e = builder.get(&sumcheck_out, idx.clone());
            builder.set(
                &prod_spec_point_n_eval,
                idx_vec[0],
                PointAndEvalVariable {
                    point: PointVariable {
                        fs: initial_rt.clone(),
                    },
                    eval: e,
                },
            );
            builder.assign(&idx, idx.clone() + C::N::ONE);
        });
    let q_idx: Usize<C::N> = builder.eval(idx.clone() + num_logup_spec.clone());
    builder
        .range(0, num_logup_spec.clone())
        .for_each(|idx_vec, builder| {
            let e1 = builder.get(&sumcheck_out, idx.clone());
            let e2 = builder.get(&sumcheck_out, q_idx.clone());
            builder.set(
                &logup_spec_p_point_n_eval,
                idx_vec[0],
                PointAndEvalVariable {
                    point: PointVariable {
                        fs: initial_rt.clone(),
                    },
                    eval: e1,
                },
            );
            builder.set(
                &logup_spec_q_point_n_eval,
                idx_vec[0],
                PointAndEvalVariable {
                    point: PointVariable {
                        fs: initial_rt.clone(),
                    },
                    eval: e2,
                },
            );
            builder.assign(&idx, idx.clone() + C::N::ONE);
            builder.assign(&q_idx, q_idx.clone() + C::N::ONE);
        });
    builder.cycle_tracker_end("initial sum");

    let curr_pt = initial_rt.clone();
    let curr_eval = initial_claim;
    let op_range: RVar<C::N> = builder.eval_expr(max_num_variables - Usize::from(1));
    let round: Felt<C::F> = builder.constant(C::F::ZERO);

    let next_rt = PointAndEvalVariable {
        point: PointVariable { fs: initial_rt },
        eval: initial_claim,
    };
    let next_layer_evals: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(sumcheck_out_len);
    builder.set(
        &input_ctx,
        3,
        Usize::from(proof.prod_specs_eval.inner_length),
    );
    builder.set(
        &input_ctx,
        4,
        Usize::from(proof.prod_specs_eval.inner_inner_length),
    );
    builder.set(
        &input_ctx,
        5,
        Usize::from(proof.logup_specs_eval.inner_length),
    );
    builder.set(
        &input_ctx,
        6,
        Usize::from(proof.logup_specs_eval.inner_inner_length),
    );
    builder.set(&input_ctx, 9, Usize::from(1));
    builder.set(&input_ctx, 10, proof.prod_specs_eval.data.id.get_var());
    builder.set(&input_ctx, 11, proof.logup_specs_eval.data.id.get_var());

    let prod_specs_eval: Array<C, Ext<C::F, C::EF>> =
        builder.dyn_array(proof.prod_specs_eval.data.length.clone());
    let logup_specs_eval: Array<C, Ext<C::F, C::EF>> =
        builder.dyn_array(proof.logup_specs_eval.data.length.clone());

    builder.range(0, op_range).for_each(|i_vec, builder| {
        let round_var = i_vec[0];
        let out_rt = &curr_pt;
        let out_claim = &curr_eval;
        let prover_messages = builder.get(&proof.proofs, round_var);

        let max_num_variables: Felt<C::F> = builder.constant(C::F::ONE);
        builder.assign(&max_num_variables, max_num_variables + round);

        let max_degree = builder.constant(C::F::from_canonical_usize(3));

        builder.cycle_tracker_start("sumcheck verify");
        let (sub_rt, sub_e) = iop_verifier_state_verify(
            builder,
            challenger,
            out_claim,
            &prover_messages,
            max_num_variables,
            max_degree,
            unipoly_extrapolator,
        );
        builder.cycle_tracker_end("sumcheck verify");

        builder.cycle_tracker_start("check expected evaluation");
        let eq_e = eq_eval(builder, out_rt, &sub_rt, one, zero);

        builder.set(&input_ctx, 0, round_var);
        builder.set(&input_ctx, 7, Usize::from(1));
        let n_v = builder.get(&num_variables, 0);
        builder.set(&input_ctx, 8, n_v);

        let challenges: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(3);
        builder.set(&challenges, 0, alpha);

        builder.sumcheck_layer_eval(
            &input_ctx,
            &challenges,
            &prod_specs_eval,
            &logup_specs_eval,
            &next_layer_evals,
        );
        let expected_evaluation = builder.get(&next_layer_evals, 0);

        builder.assign(&expected_evaluation, expected_evaluation * eq_e);
        builder.assert_ext_eq(expected_evaluation, sub_e);
        builder.cycle_tracker_end("check expected evaluation");

        builder.cycle_tracker_start("derive next layer's expected sum");
        // derive single eval
        // rt' = r_merge || rt
        // r_merge.len() == ceil_log2(num_product_fanin)
        transcript_observe_label(builder, challenger, b"merge");

        builder.cycle_tracker_start("derive rt_prime");
        let r_merge = challenger.sample_ext(builder);

        let c1: Ext<<C as Config>::F, <C as Config>::EF> = builder.eval(one - r_merge);
        let c2: Ext<<C as Config>::F, <C as Config>::EF> = builder.eval(r_merge);

        let rt_prime = extend(builder, &sub_rt, &r_merge);
        builder.cycle_tracker_end("derive rt_prime");

        // generate next round challenge
        transcript_observe_label(builder, challenger, b"combine subset evals");
        let new_alpha = challenger.sample_ext(builder);
        builder.assign(&alpha, new_alpha);

        // Use native opcode
        builder.set(&input_ctx, 7, Usize::from(0)); // Turn `in_round` off
        builder.set(&challenges, 0, new_alpha);
        builder.set(&challenges, 1, c1);
        builder.set(&challenges, 2, c2);

        builder.sumcheck_layer_eval(
            &input_ctx,
            &challenges,
            &prod_specs_eval,
            &logup_specs_eval,
            &next_layer_evals,
        );

        // extract next layer's expected sum
        let output_eval = builder.get(&next_layer_evals, 0);
        builder.assign(&curr_pt, rt_prime.clone());
        builder.assign(&curr_eval, output_eval);
        builder.assign(&round, round + C::F::ONE);

        builder.cycle_tracker_end("derive next layer's expected sum");

        builder.assign(
            &next_rt,
            PointAndEvalVariable {
                point: PointVariable {
                    fs: rt_prime.clone(),
                },
                eval: curr_eval,
            },
        );
    });

    builder.if_ne(op_range, Usize::from(0)).then(|builder| {
        // update prod_spec and logup_spec evaluations at next_rt
        let product_evals = {
            let start: Var<C::N> = builder.eval(Usize::from(1));
            let end: Var<C::N> = builder.eval(start + num_prod_spec.clone());
            next_layer_evals.slice(builder, start, end)
        };
        let logup_evals = {
            let start: Var<C::N> = builder.eval(Usize::from(1) + num_prod_spec.clone());
            let end: Var<C::N> = builder.eval(start + Usize::from(2) * num_logup_spec.clone());
            next_layer_evals.slice(builder, start, end)
        };

        builder
            .range(0, num_prod_spec.clone())
            .for_each(|i_vec, builder| {
                let i = i_vec[0];
                let eval = builder.get(&product_evals, i);

                let point_and_eval: PointAndEvalVariable<C> = builder.eval(PointAndEvalVariable {
                    point: next_rt.point.clone(),
                    eval,
                });
                builder.set_value(&prod_spec_point_n_eval, i, point_and_eval);
            });
        builder
            .range(0, num_logup_spec.clone())
            .for_each(|i_vec, builder| {
                let i = i_vec[0];
                let p_idx = i;
                let q_idx: Var<C::N> = builder.eval(num_logup_spec.clone() + i);
                let p_eval = builder.get(&logup_evals, p_idx);
                let q_eval = builder.get(&logup_evals, q_idx);

                let p_eval: PointAndEvalVariable<C> = builder.eval(PointAndEvalVariable {
                    point: next_rt.point.clone(),
                    eval: p_eval,
                });
                let q_eval: PointAndEvalVariable<C> = builder.eval(PointAndEvalVariable {
                    point: next_rt.point.clone(),
                    eval: q_eval,
                });
                builder.set_value(&logup_spec_p_point_n_eval, i, p_eval);
                builder.set_value(&logup_spec_q_point_n_eval, i, q_eval);
            });
    });

    (
        next_rt.point,
        prod_spec_point_n_eval,
        logup_spec_p_point_n_eval,
        logup_spec_q_point_n_eval,
    )
}

// #[cfg(test)]
// mod tests {
// use crate::arithmetics::UniPolyExtrapolator;
// use crate::tower_verifier::binding::IOPProverMessage;
// use crate::tower_verifier::binding::TowerVerifierInput;
// use crate::tower_verifier::program::iop_verifier_state_verify;
// use crate::tower_verifier::program::verify_tower_proof;
// use ceno_mle::mle::ArcMultilinearExtension;
// use ceno_mle::mle::{IntoMLE, MultilinearExtension};
// use ceno_mle::virtual_polys::VirtualPolynomials;
// use ceno_sumcheck::structs::IOPProverState;
// use ceno_transcript::BasicTranscript;
// use ceno_zkvm::scheme::constants::NUM_FANIN;
// use ceno_zkvm::scheme::hal::TowerProver;
// use ceno_zkvm::scheme::hal::TowerProverSpec;
// use ff_ext::BabyBearExt4;
// use ff_ext::FieldFrom;
// use ff_ext::FromUniformBytes;
// use itertools::Itertools;
// use openvm_circuit::arch::SystemConfig;
// use openvm_circuit::arch::VmExecutor;
// use openvm_native_circuit::Native;
// use openvm_native_circuit::NativeConfig;
// use openvm_native_compiler::asm::AsmCompiler;
// use openvm_native_compiler::asm::{AsmBuilder, AsmConfig};
// use openvm_native_compiler::conversion::convert_program;
// use openvm_native_compiler::conversion::CompilerOptions;
// use openvm_native_compiler::ir::Array;
// use openvm_native_compiler::ir::Ext;
// use openvm_native_compiler::prelude::Felt;
// use openvm_native_recursion::challenger::duplex::DuplexChallengerVariable;
// use openvm_native_recursion::hints::Hintable;
// use openvm_stark_sdk::config::setup_tracing_with_log_level;
// use p3_baby_bear::BabyBear;
// use p3_field::extension::BinomialExtensionField;
// use p3_field::Field;
// use p3_field::FieldAlgebra;
// use rand::thread_rng;
//
// type F = BabyBear;
// type E = BabyBearExt4;
// type EF = BinomialExtensionField<BabyBear, 4>;
// type C = AsmConfig<F, EF>;
//
// #[test]
// fn test_simple_sumcheck() {
// setup_tracing_with_log_level(tracing::Level::WARN);
//
// let nv = 5;
// let degree = 3;
//
// let mut builder = AsmBuilder::<F, EF>::default();
//
// let out_claim = EF::read(&mut builder);
// let prover_msgs = Vec::<IOPProverMessage>::read(&mut builder);
//
// let max_num_variables: Felt<F> = builder.constant(F::from_canonical_u32(nv as u32));
// let max_degree: Felt<F> = builder.constant(F::from_canonical_u32(degree as u32));
//
// let mut challenger: DuplexChallengerVariable<C> =
// DuplexChallengerVariable::new(&mut builder);
//
// let mut uni_p = UniPolyExtrapolator::new(&mut builder);
//
// builder.cycle_tracker_start("sumcheck verify");
// iop_verifier_state_verify(
// &mut builder,
// &mut challenger,
// &out_claim,
// &prover_msgs,
// max_num_variables,
// max_degree,
// &mut uni_p,
// );
// builder.cycle_tracker_end("sumcheck verify");
//
// builder.halt();
//
// get the assembly code
// let options = CompilerOptions::default().with_cycle_tracker();
// let mut compiler = AsmCompiler::new(options.word_size);
// compiler.build(builder.operations);
// let asm_code = compiler.code();
// println!("asm code");
// println!("{asm_code}");
//
// run sumcheck prover to get sumcheck proof
// let mut rng = thread_rng();
// let (mles, expected_sum) = MultilinearExtension::<E>::random_mle_list(nv, degree, &mut rng);
// let mles: Vec<ceno_mle::mle::ArcMultilinearExtension<E>> =
// mles.into_iter().map(|mle| mle as _).collect_vec();
// let mut virtual_poly: VirtualPolynomials<'_, E> = VirtualPolynomials::new(1, nv);
// virtual_poly.add_mle_list(mles.iter().collect_vec(), E::from_v(1));
//
// let mut transcript = BasicTranscript::new(&[]);
// let (sumcheck_proof, _) = IOPProverState::prove(virtual_poly, &mut transcript);
// let mut input_stream = Vec::new();
//
// hacky way: convert E to EF but actually they are the same
// let expected_sum: EF = cast_vec(vec![expected_sum])[0];
// input_stream.extend(expected_sum.write());
// input_stream.extend(
// sumcheck_proof
// .proofs
// .into_iter()
// .map(|msg| {
// let evaluations: Vec<EF> = cast_vec(msg.evaluations);
// IOPProverMessage { evaluations }
// })
// .collect_vec()
// .write(),
// );
//
// get execution result
// let program = convert_program(asm_code, options);
// let system_config = SystemConfig::default()
// .with_public_values(4)
// .with_max_segment_len((1 << 25) - 100)
// .with_profiling();
// let config = NativeConfig::new(system_config, Native);
// let executor = VmExecutor::<BabyBear, NativeConfig>::new(config);
//
// let res = executor
// .execute_and_then(program, input_stream, |_, seg| Ok(seg), |err| err)
// .unwrap();
//
// for (i, seg) in res.iter().enumerate() {
// #[cfg(feature = "bench-metrics")]
// {
// println!(
// "=> segment {} metrics.cycle_count: {:?}",
// i, seg.metrics.cycle_count
// );
// for (insn, count) in seg.metrics.counts.iter() {
// println!("insn: {:?}, count: {:?}", insn, count);
// }
// println!(
// "=> segment {} #(insns): {}",
// i,
// seg.metrics
// .counts
// .values()
// .copied()
// .into_iter()
// .sum::<usize>()
// );
// }
// }
// }
//
// #[test]
// fn test_prod_tower() {
// let nv = 5;
// let num_prod_specs = 2;
// let num_logup_specs = 1;
// let mut rng = thread_rng();
//
// setup_tracing_with_log_level(tracing::Level::WARN);
//
// let records: Vec<MultilinearExtension<E>> = (0..num_prod_specs)
// .map(|_| {
// MultilinearExtension::from_evaluations_ext_vec(
// nv - 1,
// E::random_vec(1 << (nv - 1), &mut rng),
// )
// })
// .collect_vec();
// let denom_records = (0..num_logup_specs)
// .map(|_| {
// MultilinearExtension::from_evaluations_ext_vec(nv, E::random_vec(1 << nv, &mut rng))
// })
// .collect_vec();
//
// let prod_specs = records
// .into_iter()
// .map(|record| {
// let (first, second) = record
// .get_ext_field_vec()
// .split_at(record.evaluations().len() / 2);
// let last_layer: Vec<ArcMultilinearExtension<E>> = vec![
// first.to_vec().into_mle().into(),
// second.to_vec().into_mle().into(),
// ];
// assert_eq!(last_layer.len(), NUM_FANIN);
// ceno_zkvm::structs::TowerProverSpec {
// witness: infer_tower_product_witness(nv - 1, last_layer, NUM_FANIN),
// }
// })
// .collect_vec();
//
// let prod_out_evals = prod_specs
// .iter()
// .map(|spec| {
// spec.witness[0]
// .iter()
// .map(|mle| cast_vec(mle.get_ext_field_vec().to_vec())[0])
// .collect_vec()
// })
// .collect_vec();
//
// let logup_specs = denom_records
// .into_iter()
// .map(|record| {
// let (first, second) = record
// .get_ext_field_vec()
// .split_at(record.evaluations().len() / 2);
// let last_layer: Vec<ArcMultilinearExtension<E>> = vec![
// first.to_vec().into_mle().into(),
// second.to_vec().into_mle().into(),
// ];
// TowerProverSpec {
// witness: infer_tower_logup_witness(None, last_layer),
// }
// })
// .collect_vec();
//
// let logup_out_evals = logup_specs
// .iter()
// .map(|spec| {
// spec.witness[0]
// .iter()
// .map(|mle| cast_vec(mle.get_ext_field_vec().to_vec())[0])
// .collect_vec()
// })
// .collect_vec();
//
// let num_variables = prod_specs
// .iter()
// .chain(logup_specs.iter())
// .map(|spec| spec.witness.len())
// .collect_vec();
//
// let mut transcript = BasicTranscript::new(&[]);
// let (_, tower_proof) =
// TowerProver::create_proof(prod_specs, logup_specs, NUM_FANIN, &mut transcript);
//
// build program
// let mut builder = AsmBuilder::<F, EF>::default();
//
// let mut challenger: DuplexChallengerVariable<C> =
// DuplexChallengerVariable::new(&mut builder);
//
// construct extrapolation weights
// let mut uni_p = UniPolyExtrapolator::new(&mut builder);
//
// assert_eq!(tower_proof.proofs.len(), nv - 1);
// let tower_verifier_input_var = TowerVerifierInput::read(&mut builder);
// let tower_verifier_input = TowerVerifierInput {
// prod_out_evals,
// logup_out_evals,
// num_variables,
// num_fanin: NUM_FANIN,
// num_proofs: nv - 1,
// num_prod_specs,
// num_logup_specs,
// _max_num_variables: nv,
// proofs: tower_proof
// .proofs
// .iter()
// .map(|layer| {
// layer
// .iter()
// .map(|round| IOPProverMessage {
// evaluations: cast_vec(round.evaluations.clone()),
// })
// .collect_vec()
// })
// .collect_vec(),
// prod_specs_eval: tower_proof
// .prod_specs_eval
// .iter()
// .map(|spec| {
// spec.iter()
// .map(|layer| cast_vec(layer.clone()))
// .collect_vec()
// })
// .collect_vec(),
// logup_specs_eval: tower_proof
// .logup_specs_eval
// .iter()
// .map(|spec| {
// spec.iter()
// .map(|layer| cast_vec(layer.clone()))
// .collect_vec()
// })
// .collect_vec(),
// };
// verify_tower_proof(
// &mut builder,
// &mut challenger,
// tower_verifier_input_var,
// &mut uni_p,
// );
//
// builder.halt();
//
// prepare input
// let mut input_stream = Vec::new();
// input_stream.extend(tower_verifier_input.write());
//
// get the assembly code
// let options = CompilerOptions::default().with_cycle_tracker();
// let program = builder.compile_isa_with_options(options);
// let system_config = SystemConfig::default()
// .with_public_values(4)
// .with_max_segment_len((1 << 25) - 100)
// .with_profiling();
// let config = NativeConfig::new(system_config, Native);
// let executor = VmExecutor::<BabyBear, NativeConfig>::new(config);
// executor
// .execute_and_then(program, input_stream, |_, seg| Ok(seg), |err| err)
// .unwrap();
// }
//
// fn cast_vec<A, B>(mut vec: Vec<A>) -> Vec<B> {
// let length = vec.len();
// let capacity = vec.capacity();
// let ptr = vec.as_mut_ptr();
// Prevent `vec` from dropping its contents
// std::mem::forget(vec);
//
// Convert the pointer to the new type
// let new_ptr = ptr as *mut B;
//
// Create a new vector with the same length and capacity, but different type
// unsafe { Vec::from_raw_parts(new_ptr, length, capacity) }
// }
// }
