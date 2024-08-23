use std::{array, iter, mem, sync::Arc, time::Instant};

use ark_std::{end_timer, start_timer, test_rng};
use ff_ext::{ff::Field, ExtensionField};
use gkr::structs::Point;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::{chain, izip, Itertools};
use multilinear_extensions::{
    mle::{
        ArcDenseMultilinearExtension, DenseMultilinearExtension, FieldType, MultilinearExtension,
    },
    op_mle,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::structs::{IOPProof, IOPProverState};
use transcript::Transcript;

type ArcMLEVec<E> = Vec<E>;

fn alpha_pows<E: ExtensionField>(size: usize, transcript: &mut Transcript<E>) -> Vec<E> {
    // println!("alpha_pow");
    let alpha = transcript
        .get_and_append_challenge(b"combine subset evals")
        .elements;
    (0..size)
        .scan(E::ONE, |state, _| {
            let res = *state;
            *state *= alpha;
            Some(res)
        })
        .collect_vec()
}

/// r_out(rt) + alpha * w_out(rt)
///     = \sum_s eq(rt, s) * (r_in[0](s) * ... * r_in[2^D - 1](s)
///                           + alpha * w_in[0](s) * ... * w_in[2^D - 1](s))
/// rs' = r_0...r_{D - 1} || rs
/// r_in'(rs') = sum_b eq(rs'[..D], b) r_in[b](rs)
/// w_in'(rs') = sum_b eq(rs'[..D], b) w_in[b](rs)
fn prove_split_and_product<E: ExtensionField, const LOGD: usize>(
    point: Point<E>,
    r_and_w: Vec<ArcMLEVec<E>>,
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, [E; 2]) {
    let timer = start_timer!(|| format!(
        "vars: {}, prod size: {}, prove_split_and_product",
        point.len(),
        1 << LOGD
    ));
    let inner_timer = start_timer!(|| "prove_split_and_product setup");
    println!("prove_split_and_product");
    let num_vars = point.len();

    let eq = build_eq_x_r_vec(&point);
    let inner_inner_timer = start_timer!(|| "after_eq");
    let rc_s = alpha_pows(2, transcript);
    // println!("point len: {}", point.len());
    let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
        num_vars, &eq,
    ));
    let fr_and_w = r_and_w
        .into_iter()
        .map(|rw| {
            Arc::new(DenseMultilinearExtension::from_evaluations_ext_vec(
                num_vars, rw,
            ))
        })
        .collect_vec();

    let d = 1 << LOGD;
    let fr = chain![iter::once(feq.clone()), fr_and_w.iter().take(d).cloned()].collect_vec();
    let fw = chain![iter::once(feq.clone()), fr_and_w.into_iter().skip(d)].collect_vec();
    end_timer!(inner_inner_timer);
    let mut virtual_poly = VirtualPolynomial::new(num_vars);
    virtual_poly.add_mle_list(fr, rc_s[0]);
    virtual_poly.add_mle_list(fw, rc_s[1]);
    end_timer!(inner_timer);

    // Split
    let (proof, state) = IOPProverState::prove_parallel(virtual_poly, transcript);
    let evals = state.get_mle_final_evaluations();
    let mut point = (0..LOGD)
        .map(|_| transcript.get_and_append_challenge(b"merge").elements)
        .collect_vec();
    let coeffs = build_eq_x_r_vec(&point);
    point.extend(proof.point.clone());

    let prod_size = 1 << LOGD;
    let ret_evals = [
        izip!(evals[1..(1 + prod_size)].iter(), coeffs.iter())
            .map(|(a, b)| *a * b)
            .sum::<E>(),
        izip!(
            evals[(1 + prod_size)..(1 + 2 * prod_size)].iter(),
            coeffs.iter()
        )
        .map(|(a, b)| *a * b)
        .sum::<E>(),
    ];

    end_timer!(timer);
    (proof, point, ret_evals)
}

/// alpha^0 r(rt) + alpha w(rt)
/// = \sum_s alpha^0 * eq(rt[..6], 0)(sel(s) * fr[0](s) + (1 - sel(s)))
/// + ...
/// + alpha^0 * eq(rt[..6], 63)(sel(s) * fr[63](s) + (1 - sel(s)))
/// + alpha^1 * eq(rt[..6], 0)(sel(s) * fw[0](s) + (1 - sel(s)))
/// + ...
/// + alpha^1 * eq(rt[..6], 63)(sel(s) * fw[63](s) + (1 - sel(s)))
/// = \sum_s eq(s)*sel(s)*( alpha^0 * eq(rt[..6], 0) * fr[0] + ... + alpha^0 * eq(rt[..6], 63) *
/// fr[63]
///                       + alpha^1 * eq(rt[..6], 0) * fw[0] + ... + alpha^1 * eq(rt[..6], 63) *
///                         fw[63]
///    + (alpha^0 + alpha^1)(1 - sel(rt[6..]))
fn prove_select<E: ExtensionField>(
    inst_num_vars: usize,
    real_inst_size: usize,
    point: &Point<E>,
    r_and_w: Vec<ArcMLEVec<E>>,
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, Vec<E>) {
    let timer = start_timer!(|| format!("vars: {}, prove_select", point.len()));
    let inner_timer = start_timer!(|| "prove select setup");
    println!("prove select");
    let num_vars = inst_num_vars;

    let eq = build_eq_x_r_vec(&point[6..]);
    let mut sel = vec![E::BaseField::ONE; real_inst_size];
    sel.extend(vec![
        E::BaseField::ZERO;
        (1 << inst_num_vars) - real_inst_size
    ]);
    let rc_s = alpha_pows(2, transcript);
    let index_rc_s = build_eq_x_r_vec(&point[..6]);
    let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
        num_vars, &eq,
    ));
    let fsel = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
        num_vars, &sel,
    ));
    let fr_and_w = r_and_w.into_iter().map(|rw| {
        Arc::new(DenseMultilinearExtension::from_evaluations_ext_vec(
            num_vars, rw,
        ))
    });

    let dense_poly_mul_ext = |poly: ArcDenseMultilinearExtension<E>, sc: E| {
        let evaluations = op_mle!(|poly| poly.iter().map(|x| sc * x).collect_vec());
        DenseMultilinearExtension::from_evaluations_ext_vec(poly.num_vars, evaluations)
    };
    let dense_poly_add = |a: DenseMultilinearExtension<E>, b: DenseMultilinearExtension<E>| {
        let evaluations = match (a.evaluations, b.evaluations) {
            (FieldType::Ext(a), FieldType::Ext(b)) => {
                a.iter().zip(b.iter()).map(|(x, y)| *x + y).collect_vec()
            }
            _ => unreachable!(),
        };
        DenseMultilinearExtension::from_evaluations_ext_vec(a.num_vars, evaluations)
    };

    let mut rc = index_rc_s
        .par_iter()
        .map(|x| rc_s[0] * x)
        .collect::<Vec<_>>();
    rc.extend(
        index_rc_s
            .par_iter()
            .map(|x| rc_s[1] * x)
            .collect::<Vec<_>>(),
    );

    let f = fr_and_w
        .enumerate()
        .map(|(i, poly)| dense_poly_mul_ext(poly, rc[i]))
        .reduce(|a, b| dense_poly_add(a, b))
        .unwrap();
    let f = Arc::new(f);
    let mut virtual_poly = VirtualPolynomial::new(num_vars);
    let sel_coeff = rc_s.iter().sum::<E>();
    virtual_poly.add_mle_list(vec![fsel.clone()], -sel_coeff);
    virtual_poly.add_mle_list(vec![feq.clone(), f, fsel], E::ONE);
    end_timer!(inner_timer);

    let (proof, state) = IOPProverState::prove_parallel(virtual_poly, transcript);
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
    end_timer!(timer);
    (proof, point, evals)
}

fn prove_add_opcode<E: ExtensionField>(
    point: &Point<E>,
    polys: &[ArcMLEVec<E::BaseField>; 57], // Uint<64, 32>
) -> [E; 57] {
    array::from_fn(|i| {
        DenseMultilinearExtension::from_evaluations_slice(point.len(), &polys[i]).evaluate(&point)
    })
}

fn main() {
    type E = GoldilocksExt2;
    type F = Goldilocks;
    const LOGD: usize = 1;

    // Multiply D items together in the product subcircuit.
    const D: usize = 1 << LOGD;
    let inst_num_vars: usize = 20;
    let tree_layer = (inst_num_vars + 6) / LOGD;

    let real_inst_size = (1 << inst_num_vars) - 100;

    let input = array::from_fn(|_| {
        (0..(1 << inst_num_vars))
            .map(|_| F::random(test_rng()))
            .collect_vec()
    });
    let mut wit = vec![vec![]; tree_layer + 1];
    (0..tree_layer).for_each(|i| {
        wit[i] = (0..2 * D)
            .map(|_| {
                (0..1 << i * LOGD)
                    .map(|_| E::random(test_rng()))
                    .collect_vec()
            })
            .collect_vec();
    });
    wit[tree_layer] = (0..128)
        .map(|_| {
            (0..(1 << inst_num_vars))
                .map(|_| E::random(test_rng()))
                .collect_vec()
        })
        .collect_vec();

    let mut transcript = &mut Transcript::<E>::new(b"prover");
    let time = Instant::now();
    let w_point = (0..tree_layer).fold(vec![], |last_point, i| {
        let (_, nxt_point, _) =
            prove_split_and_product::<_, LOGD>(last_point, mem::take(&mut wit[i]), &mut transcript);
        println!("prove table read write {}", nxt_point.len());
        nxt_point
    });

    assert_eq!(w_point.len(), tree_layer * LOGD);
    let (_, point, _) = prove_select(
        inst_num_vars,
        real_inst_size,
        &w_point,
        mem::take(&mut wit[tree_layer]),
        &mut transcript,
    );
    prove_add_opcode(&point, &input);
    println!("prove time: {} s", time.elapsed().as_secs_f64());
}
