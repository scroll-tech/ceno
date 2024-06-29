#![feature(generic_const_exprs)]
use std::{array, env, iter, mem, sync::Arc, time::Instant};

use ff_ext::{ff::Field, ExtensionField};
use gkr::structs::Point;
use goldilocks::{Goldilocks, GoldilocksExt2, SmallField};
use itertools::{chain, izip, Itertools};
use multilinear_extensions::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension},
    virtual_poly::{build_eq_x_r_vec, eq_eval, VirtualPolynomial},
};
use paste::paste;
use sumcheck::{structs::IOPProof, util::ceil_log2};
use transcript::Transcript;

const RHO: [usize; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

/// The vector for an MLE.
type MLEVec<F> = Vec<F>;

fn alpha_pows<E: ExtensionField>(size: usize, transcript: &mut Transcript<E>) -> Vec<E> {
    // println!("alpha_pow");
    let alpha = transcript
        .get_and_append_challenge(b"combine subset evals")
        .elements;
    chain![
        iter::once(E::ONE),
        (1..size).scan(E::ONE, |state, _| {
            let res = *state;
            *state *= alpha;
            Some(res)
        })
    ]
    .collect()
}

macro_rules! define_split_eval {
    ($name:ident, [$( $N:ident ),*], [$( $B:ident ),*]) => {
        #[allow(non_snake_case)]
        fn $name<E: ExtensionField, $( const $N: usize, )* const A: usize $(, const $B: usize)*> (
            point: &Point<E>,
            evals: &[&[E; 1 $( * $N )*]],
            transcript: &mut Transcript<E>,
        ) -> (Point<E>, Vec<E>) {
            // println!("split_$N");
            $(
                assert!( $N <= (1 << $B));
            )*
            let split_point = (A..A $(+ $B)*)
                .map(|_| transcript.get_and_append_challenge(b"split_point").elements)
                .collect_vec();
            let eq_vec = build_eq_x_r_vec(&split_point);
            (
                chain![point[..A].to_vec(), split_point, point[A..].to_vec()].collect(),
                evals.iter().map(|evals| {
                    define_split_eval!(@internal evals, eq_vec, i; ($( $N ),*), ($( $B ),*))
                }).collect()
            )
        }
    };

    // Base case: When there are no more dimensions to process
    (@internal $evals:ident, $eq_vec:ident, $i:ident, $prefix1:expr, $prefix2:expr; ($cur_N:expr), ($cur_B:expr)) => {
        (0..$cur_N).map(|$i| {
            $evals[($prefix1) * $cur_N + $i] * $eq_vec[($prefix2) * $cur_N + $i]
        }).sum::<E>()
    };

    // Base case: When there are no more dimensions to process
    (@internal $evals:ident, $eq_vec:ident, $i:ident; ($cur_N:expr), ($cur_B:expr)) => {
        (0..$cur_N).map(|$i| {
            $evals[$i] * $eq_vec[$i]
        }).sum::<E>()
    };

    // Recursive case: When there are more dimensions to process
    (@internal $evals:ident, $eq_vec:ident, $i:ident; ($cur_N:expr, $( $rest_N:expr ),*), ($cur_B:expr, $( $rest_B:expr ),*)) => {
        (0..$cur_N).map(|$i| {
            paste! {
                define_split_eval!(@internal $evals, $eq_vec, [<i $i>], $i, $i; ($( $rest_N ),*), ($( $rest_B ),*))
            }
        }).sum::<E>()
    };

    // Intermediate recursive case
    (@internal $evals:ident, $eq_vec:ident, $i:ident, $prefix1:expr, $prefix2:expr; ($cur_N:expr, $( $rest_N:expr ),*), ($cur_B:expr, $( $rest_B:expr ),*)) => {
        (0..$cur_N).map(|$i| {
            paste! {
                define_split_eval!(@internal $evals, $eq_vec, [<i $i>], (($prefix1) * $cur_N) + $i, (($prefix2) << $cur_B) + $i; ($( $rest_N ),*), ($( $rest_B ),*))
            }
        }).sum::<E>()
    };
}

define_split_eval!(split_eval_1, [N1], [B1]);
define_split_eval!(split_eval_2, [N2, N1], [B2, B1]);
define_split_eval!(split_eval_3, [N3, N2, N1], [B3, B2, B1]);

macro_rules! define_prove_merge {
    ($name:ident, [$( $N:ident ),*], [$( $B:ident ),*]) => {
        fn $name<E: ExtensionField, $( const $N: usize, )* const A: usize $(, const $B: usize)*> (
            b_point: &Point<E>,
            a: &[Arc<MLEVec<E::BaseField>>; 1 $(* $N )*],
        ) -> (Point<E>, [E; 1 $( * $N )*]) {
            // println!("merge_$N");
            $(
                assert!($N <= 1 << $B);
            )*
            let point = chain![&b_point[..A], &b_point[A $(+ $B )*..]].cloned().collect_vec();
            let num_vars = point.len();
            let evals = array::from_fn(|i| {
                DenseMultilinearExtension::from_evaluations_slice(
                    num_vars,
                    &a[i],
                ).evaluate(&point)
            });
            (point, evals)
        }
    };
}

define_prove_merge!(prove_merge_1, [N1], [B1]);
define_prove_merge!(prove_merge_2, [N2, N1], [B2, B1]);
define_prove_merge!(prove_merge_3, [N3, N2, N1], [B3, B2, B1]);

// TODO: PI and RHO should be transposed but I haven't done it.
fn rho_and_pi<T: Copy>(state: &mut [T; 64 * 25]) {
    // println!("rho_and_pi");
    let mut last: [T; 64] = array::from_fn(|k| state[k * 25 + 10]);
    for x in 0..24 {
        let tmp = last;
        for k in 0..64 {
            last[(k + 64 - RHO[x]) % 64] = state[k * 25 + PI[x]];
            state[k * 25 + PI[x]] = tmp[k];
        }
    }
}

/// let mut last = state[1];
/// for x in 0..24 {
///     array[0] = state[PI[x]];
///     state[PI[x]] = last.rotate_left(RHO[x] as usize);
///     last = array[0];
/// }
// TODO: PI and RHO should be transposed but I haven't done it.
fn compute_rho_and_pi<T: Default>(state: &mut [T; 64 * 25]) {
    let mut last: [T; 64] = array::from_fn(|k| mem::take(&mut state[k * 25 + 1]));
    for x in 0..24 {
        let tmp: [T; 64] = array::from_fn(|k| mem::take(&mut state[k * 25 + PI[x]]));
        (0..64).for_each(|k| state[k * 25 + PI[x]] = mem::take(&mut last[(k + RHO[x]) % 64]));
        last = tmp;
    }
}

/// rotate_left([[E; 5 x 5]; 64])
fn rotate<E: ExtensionField>(evals: &[E; 64]) -> [E; 64] {
    // println!("rotate");
    let mut evals = evals.clone();
    evals.rotate_left(1);
    evals
}

/// copy a to be multiple b's
/// alpha^i * b_i(z_i) = \sum_x (alpha^i eq(z_i, x)) b(x)
fn prove_copy<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    b_points: &[Point<E>],
    a: &Arc<MLEVec<E::BaseField>>,
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, E) {
    // println!("prove_copy");
    let b_eqs = b_points
        .iter()
        .map(|b_point| build_eq_x_r_vec(&b_point))
        .collect_vec();
    let num_vars = b_points[0].len();
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = ceil_log2(thread_size);

    let alpha_pows = alpha_pows(b_points.len(), transcript);
    let b_eq = (0..b_eqs[0].len())
        .map(|i| {
            izip!(&b_eqs, &alpha_pows)
                .map(|(b, alpha)| b[i] * alpha)
                .sum::<E>()
        })
        .collect_vec();
    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let fa = Arc::new(DenseMultilinearExtension::<E>::from_evaluations_slice(
                thread_nv,
                &a[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let mut virtual_poly = VirtualPolynomial::new(thread_nv);
            let fb_eq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &b_eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            virtual_poly.add_mle_list(vec![fa.clone(), fb_eq.clone()], E::ONE);
            virtual_poly
        })
        .collect();

    let (proof, state) = sumcheck::structs::IOPProverState::prove_batch_polys(
        max_thread_id,
        virtual_polys,
        transcript,
    );
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
    (proof, point, evals[0])
}

fn wrong_xor3<E: ExtensionField>(
    virtual_poly: &mut VirtualPolynomial<E>,
    feq: &ArcDenseMultilinearExtension<E>,
    fa: ArcDenseMultilinearExtension<E>,
    fb: ArcDenseMultilinearExtension<E>,
    fc: ArcDenseMultilinearExtension<E>,
    rc: E,
) {
    let two = E::BaseField::from(2);
    // (x0 + x1 + x2) - 2x0x2 - 2x1x2 - 2x0x1 + 4x0x1x2
    virtual_poly.add_mle_list(
        vec![feq.clone(), fa.clone(), fb.clone(), fc.clone()],
        rc * (two.double()),
    );
    virtual_poly.add_mle_list(vec![fa.clone(), fc.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fb.clone(), fc.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa.clone(), fb.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa], rc);
    virtual_poly.add_mle_list(vec![fb], rc);
    virtual_poly.add_mle_list(vec![fc], rc);
}

fn wrong_wrong_xor3<E: ExtensionField>(
    virtual_poly: &mut VirtualPolynomial<E>,
    feq: &ArcDenseMultilinearExtension<E>,
    fa: ArcDenseMultilinearExtension<E>,
    fb: ArcDenseMultilinearExtension<E>,
    fc: ArcDenseMultilinearExtension<E>,
    rc: E,
) {
    let two = E::BaseField::from(2);
    // (x0 + x1 + x2) - 2x0x2 - 2x1x2 - 2x0x1 + 4x0x1x2
    virtual_poly.add_mle_list(
        vec![fa.clone(), fb.clone(), fc.clone()],
        rc * (two.double()),
    );
    virtual_poly.add_mle_list(vec![fa.clone(), fc.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fb.clone(), fc.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa.clone(), fb.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa], rc);
    virtual_poly.add_mle_list(vec![fb], rc);
    virtual_poly.add_mle_list(vec![fc], rc);
}

fn wrong_xor2<E: ExtensionField>(
    virtual_poly: &mut VirtualPolynomial<E>,
    feq: &ArcDenseMultilinearExtension<E>,
    fa: ArcDenseMultilinearExtension<E>,
    fb: ArcDenseMultilinearExtension<E>,
    rc: E,
) {
    let two = E::BaseField::from(2);
    // (x0 + x1) - 2x0x1
    virtual_poly.add_mle_list(vec![feq.clone(), fa.clone(), fb.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa], rc);
    virtual_poly.add_mle_list(vec![fb], rc);
}

fn wrong_wrong_xor2<E: ExtensionField>(
    virtual_poly: &mut VirtualPolynomial<E>,
    feq: &ArcDenseMultilinearExtension<E>,
    fa: ArcDenseMultilinearExtension<E>,
    fb: ArcDenseMultilinearExtension<E>,
    rc: E,
) {
    let two = E::BaseField::from(2);
    // (x0 + x1) - 2x0x1
    virtual_poly.add_mle_list(vec![fa.clone(), fb.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fa], rc);
    virtual_poly.add_mle_list(vec![fb], rc);
}

/// This sumcheck including the following equations:
///         2     3     6     ...
///     - d(z0 || z1 || z3 || ...) = \sum_i eq(z1 , i)( \sum_{x3} eq(z3, x3)(
///         + eq(z0, 0) xor3(x_{i + 1}[0](x3), x_{i + 1}[1](x3), x_{i + 1}[2](x3)),
///         + eq(z0, 1) xor3(x_{i + 1}[3](x3), x_{i + 1}[4](x3), x_{i + 4}[0](x3)),
///         + eq(z0, 2) xor2(x_{i + 4}[1](x3), x_{i + 4}[2](x3)),
///         + eq(z0, 3) xor2(x_{i + 4}[3](x3), x_{i + 4}[4](x3)))
///     ),
fn prove_xor3_and_xor2<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    d_point: &Point<E>,
    x: &[Arc<MLEVec<E::BaseField>>; 25],
    x_rot: &[Arc<MLEVec<E::BaseField>>; 25],
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, [E; 25], [E; 25]) {
    // println!("prove_xor3_and_xor2");
    let num_vars = inst_num_vars + 6;
    let point_z3 = &d_point[5..];
    let eq = build_eq_x_r_vec(point_z3);
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = ceil_log2(thread_size);

    // Randomly combine all xor3 equatinos.
    let rc_vec = build_eq_x_r_vec(&d_point[0..5]);
    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let mut virtual_poly = VirtualPolynomial::new(thread_nv);
            let fx: [_; 25] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                    thread_nv,
                    &x[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            let fx_rot: [_; 25] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                    thread_nv,
                    &x_rot[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            for i in 0..5 {
                wrong_xor3(
                    &mut virtual_poly,
                    &feq,
                    fx[0 * 5 + (i + 1) % 5].clone(),
                    fx[1 * 5 + (i + 1) % 5].clone(),
                    fx[2 * 5 + (i + 1) % 5].clone(),
                    rc_vec[i * 4 + 0],
                );
                wrong_wrong_xor3(
                    &mut virtual_poly,
                    &feq,
                    fx[3 * 5 + (i + 1) % 5].clone(),
                    fx[4 * 5 + (i + 1) % 5].clone(),
                    fx_rot[0 * 5 + (i + 4) % 5].clone(),
                    rc_vec[i * 4 + 1],
                );
                wrong_xor2(
                    &mut virtual_poly,
                    &feq,
                    fx_rot[1 * 5 + (i + 4) % 5].clone(),
                    fx_rot[2 * 5 + (i + 4) % 5].clone(),
                    rc_vec[i * 4 + 2],
                );
                wrong_wrong_xor2(
                    &mut virtual_poly,
                    &feq,
                    fx_rot[3 * 5 + (i + 4) % 5].clone(),
                    fx_rot[4 * 5 + (i + 4) % 5].clone(),
                    rc_vec[i * 4 + 3],
                );
            }
            virtual_poly
        })
        .collect_vec();

    let (proof, state) = sumcheck::structs::IOPProverState::prove_batch_polys(
        max_thread_id,
        virtual_polys,
        transcript,
    );
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
    (
        proof,
        point,
        chain![
            // x + 1
            &evals[41..46],
            &evals[1..6],
            &evals[11..16],
            &evals[21..26],
            &evals[31..36]
        ]
        .cloned()
        .collect_vec()
        .try_into()
        .unwrap(),
        chain![
            // x + 4
            &evals[16..21],
            &evals[26..31],
            &evals[36..41],
            &evals[46..51],
            &evals[6..11]
        ]
        .cloned()
        .collect_vec()
        .try_into()
        .unwrap(),
    )
}

/// c(x) = xor(a(x), b(x))
fn prove_xor2<E: ExtensionField>(
    max_thread_id: usize,
    _inst_num_vars: usize,
    c_point: &Point<E>,
    a: &Arc<MLEVec<E::BaseField>>,
    b: &Arc<MLEVec<E::BaseField>>,
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, [E; 2]) {
    // println!("prove_xor2");
    let num_vars = c_point.len();
    let eq = build_eq_x_r_vec(&c_point);
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = ceil_log2(thread_size);

    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fa = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                thread_nv,
                &a[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fb = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                thread_nv,
                &b[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let mut virtual_poly = VirtualPolynomial::new_from_mle(fa.clone(), E::ONE);
            wrong_xor2(&mut virtual_poly, &feq, fa, fb, E::ONE);
            virtual_poly
        })
        .collect_vec();

    let (proof, state) = sumcheck::structs::IOPProverState::prove_batch_polys(
        max_thread_id,
        virtual_polys,
        transcript,
    );
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
    (proof, point, [evals[1], evals[2]])
}

/// d[y, x](z0 || z1 || z2 || ...)
///     = \sum_{x0 || x2} eq(z0 || z2, x0 || x2) xor3(a(x0 || z1 || x2 || ...),
///                                     b(x0 || x2 || ...), c(x0 || x2 || ...))
fn prove_xor3<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    d_point: &Point<E>,
    a: &Arc<MLEVec<E::BaseField>>,
    b: &Arc<MLEVec<E::BaseField>>,
    c: &Arc<MLEVec<E::BaseField>>,
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, Point<E>, [E; 3]) {
    // println!("prove_xor3");
    let num_vars = d_point.len() - 3;
    let point = chain![&d_point[0..3], &d_point[6..]] // x || word || inst
        .cloned()
        .collect_vec();
    let eq = build_eq_x_r_vec(&point);
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = ceil_log2(thread_size);

    // Compute (a(x0 || z1 || x2))_{x0 || x2}
    let a = {
        let rc = build_eq_x_r_vec(&d_point[3..6]);
        (0..(1 << inst_num_vars + 6))
            .flat_map(|k| {
                (0..8)
                    .map(|i| {
                        if i < 5 {
                            (0..5).map(|j| rc[j] * a[((k * 8) + j) * 8 + i]).sum::<E>()
                        } else {
                            E::ZERO
                        }
                    })
                    .collect_vec()
            })
            .collect_vec()
    };

    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fa = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &a[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fb = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                thread_nv,
                &b[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fc = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                thread_nv,
                &c[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let mut virtual_poly = VirtualPolynomial::new_from_mle(fa.clone(), E::ONE);
            wrong_xor3(&mut virtual_poly, &feq, fa, fb, fc, E::ONE);
            virtual_poly
        })
        .collect_vec();

    let (proof, state) = sumcheck::structs::IOPProverState::prove_batch_polys(
        max_thread_id,
        virtual_polys,
        transcript,
    );
    let evals = state.get_mle_final_evaluations();
    let point_1 = proof.point.clone();
    let point_0 = chain![&point_1[..3], &d_point[3..6], &point_1[3..]]
        .cloned()
        .collect_vec();
    (proof, point_0, point_1, [evals[1], evals[2], evals[3]])
}

/// chi truth table
/// | x0 | x1 | x2 | x0 ^ ((not x1) & x2) |
/// |----|----|----|----------------------|
/// | 0  | 0  | 0  | 0                    |
/// | 0  | 0  | 1  | 1                    |
/// | 0  | 1  | 0  | 0                    |
/// | 0  | 1  | 1  | 0                    |
/// | 1  | 0  | 0  | 1                    |
/// | 1  | 0  | 1  | 0                    |
/// | 1  | 1  | 0  | 1                    |
/// | 1  | 1  | 1  | 1                    |
/// (1-x0)*(1-x1)*(x2) + x0(1-x1)(1-x2) + x0x1(1-x2) + x0x1x2
/// = x2 - x0x2 - x1x2 + x0x1x2 + x0 - x0x1 - x0x2 + x0x1x2 + x0x1 - x0x1x2 + x0x1x2
/// = (x0 + x2) - 2x0x2 - x1x2 + 2x0x1x2
fn wrong_chi<E: ExtensionField>(
    virtual_poly: &mut VirtualPolynomial<E>,
    feq: &ArcDenseMultilinearExtension<E>,
    fa: ArcDenseMultilinearExtension<E>,
    fb: ArcDenseMultilinearExtension<E>,
    fc: ArcDenseMultilinearExtension<E>,
    rc: E,
) {
    let two = E::BaseField::from(2);
    // (x0 + x2) - 2x0x2 - x1x2 + 2x0x1x2
    virtual_poly.add_mle_list(
        vec![feq.clone(), fa.clone(), fb.clone(), fc.clone()],
        rc * two,
    );
    virtual_poly.add_mle_list(vec![fa.clone(), fc.clone()], -rc * two);
    virtual_poly.add_mle_list(vec![fb, fc.clone()], -rc);
    virtual_poly.add_mle_list(vec![fa], rc);
    virtual_poly.add_mle_list(vec![fc], rc);
}

/// Compute chi and merge the result from [_; 5] to _.
///     d(z1 || z2 || z3 || ...) = \sum_{x2 || x3} eq(x2 || x3)(
///         + eq(z1, 0) chi(x[0](x2 || x3), x[1](x2 || x3), x[2](x2 || x3)),
///         + eq(z1, 1) chi(x[1](x2 || x3), x[2](x2 || x3), x[3](x2 || x3)),
///         + eq(z1, 2) chi(x[2](x2 || x3), x[3](x2 || x3), x[4](x2 || x3)),
///         + eq(z1, 3) chi(x[3](x2 || x3), x[4](x2 || x3), x[0](x2 || x3)),
///         + eq(z1, 4) chi(x[4](x2 || x3), x[0](x2 || x3), x[1](x2 || x3)),
///     )
fn prove_chi<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    d_point: &Point<E>,
    x: &[Arc<MLEVec<E::BaseField>>; 5],
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, [E; 5]) {
    // println!("prove_chi");
    let num_vars = d_point.len() - 3;
    let point = d_point[3..].to_vec();
    let eq = build_eq_x_r_vec(&point);
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = ceil_log2(thread_size);

    let rc_s = build_eq_x_r_vec(&d_point[..3]);
    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fx_s: [_; 5] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                    thread_nv,
                    &x[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            let mut virtual_poly = VirtualPolynomial::new(thread_nv);
            izip!((0..5), &rc_s).for_each(|(i, rc)| {
                wrong_chi(
                    &mut virtual_poly,
                    &feq,
                    fx_s[i].clone(),
                    fx_s[(i + 1) % 5].clone(),
                    fx_s[(i + 2) % 5].clone(),
                    *rc,
                );
            });
            virtual_poly
        })
        .collect_vec();

    let (proof, state) = sumcheck::structs::IOPProverState::prove_batch_polys(
        max_thread_id,
        virtual_polys,
        transcript,
    );
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
    (
        proof,
        point,
        [evals[1], evals[2], evals[3], evals[4], evals[5]],
    )
}

fn xor_const<E: ExtensionField>(d_point: &Point<E>, d_evals: E, constant: E::BaseField) -> E {
    // println!("xor_const");
    d_evals - eq_eval(&d_point[..3], &[E::ZERO; 3]) * constant
}

fn eval<E: ExtensionField>(point: &Point<E>, a: &MLEVec<E::BaseField>) -> E {
    DenseMultilinearExtension::from_evaluations_slice(point.len(), a).evaluate(point)
}

fn prove_keccak_f<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    point: &Point<E>,
    wit: Vec<Vec<Arc<MLEVec<E::BaseField>>>>,
    round: usize,
    transcript: &mut Transcript<E>,
) -> Point<E> {
    let xor_eval = xor_const(
        &point,
        eval(&point, &wit[0][0]),
        E::BaseField::from(RC[round]),
    );

    // sumcheck
    let (chi_proof, chi_point, chi_evals) = {
        let x: [_; 5] = wit[1][0..5].to_vec().try_into().unwrap();
        prove_chi(max_thread_id, inst_num_vars, &point, &x, transcript)
    };

    let (chi_point_2, chip_evals_2) =
        split_eval_1::<_, 5, 0, 3>(&chi_point, &[&chi_evals], transcript);

    let x: &[_; 64 * 25] = wit[2][..25 * 64].try_into().unwrap();
    let (rho_and_pi_point, mut rho_and_pi_evals) =
        prove_merge_3::<_, 64, 5, 5, 0, 6, 3, 3>(&chi_point_2, &x);

    rho_and_pi(&mut rho_and_pi_evals);

    let (split_point, split_eval) = split_eval_3::<_, 64, 5, 5, 0, 6, 3, 3>(
        &rho_and_pi_point,
        &[&rho_and_pi_evals],
        transcript,
    );

    let xor3_a = &wit[3][0];
    let xor3_b = &wit[3][1];
    let xor3_c = &wit[3][2];
    // sumcheck
    let (xor3_proof, xor3_point_0, xor3_point_1, xor3_evals) = prove_xor3(
        max_thread_id,
        inst_num_vars,
        &split_point,
        xor3_a,
        xor3_b,
        xor3_c,
        transcript,
    );

    let (split2_point, split2_eval) = split_eval_1::<_, 2, 0, 1>(
        &xor3_point_1,
        &[&[xor3_evals[1], xor3_evals[2]]],
        transcript,
    );

    let xor2p_a = &wit[4][0];
    let xor2p_b = &wit[4][1];
    // sumcheck
    let (xor2p_proof, xor2p_point, xor2p_evals) = prove_xor2(
        max_thread_id,
        inst_num_vars,
        &split2_point,
        xor2p_a,
        xor2p_b,
        transcript,
    );

    let (split2p_point, split2p_eval) =
        split_eval_1::<_, 2, 0, 1>(&xor2p_point, &[&xor2p_evals], transcript);

    let x: &[_; 25] = wit[5][0..25].try_into().unwrap();
    let x_rot: &[_; 25] = wit[5][25..50].try_into().unwrap();
    // sumcheck
    let (xor32_proof, xor32_point, x_evals, x_rot_evals) = prove_xor3_and_xor2(
        max_thread_id,
        inst_num_vars,
        &split2p_point,
        x,
        x_rot,
        transcript,
    );
    let (x_rot_point, x_split_evals) =
        split_eval_2::<_, 5, 5, 0, 3, 3>(&xor32_point, &[&x_evals, &x_rot_evals], transcript);

    let x_rot: &[_; 64] = wit[6][0..64].try_into().unwrap();
    let (after_rot_point, after_rot_evals) = prove_merge_1::<_, 64, 6, 6>(&split_point, &x_rot);
    // sumcheck: prove_rotate
    let before_rot_evals = rotate(&after_rot_evals);
    let (before_rot_point, before_rot_eval) =
        split_eval_1::<_, 64, 6, 6>(&after_rot_point, &[&before_rot_evals], transcript);

    // sumcheck: prove_copy
    // println!("A.len: {}", xor3_point_0.len());
    // println!("B.len: {}", before_rot_point.len());
    // println!("C.len: {}", x_rot_point.len());
    let a = &wit[7][0];
    prove_copy(
        max_thread_id,
        inst_num_vars,
        &[xor3_point_0, before_rot_point, x_rot_point],
        a,
        transcript,
    )
    .1
}

fn witness_generation<F: SmallField>(inst_num_vars: usize) -> Vec<Vec<Arc<MLEVec<F>>>> {
    let mut wit = vec![vec![vec![]]; 8];
    let inst_size = 1 << inst_num_vars;
    // initial state [MLEVec<E> indexed by (3, 3, 6, inst_num_vars); 1]
    wit[7] = vec![(0..inst_size * 64 * 8 * 8)
        .map(|id| {
            let i = id & 7;
            let j = (id >> 3) & 7;
            if i < 5 && j < 5 {
                rand::random::<u8>() % 2
            } else {
                0u8
            }
        })
        .collect()];
    // rotated state [MLEVec<E> indexed by (3, 3, inst_num_vars); 64]
    wit[6] = (0..64)
        .map(|k| {
            (0..inst_size)
                .flat_map(|z| {
                    (0..64)
                        .map(|x| wit[7][0][(z << 12) ^ (((k + 1) & 63) << 6) ^ x])
                        .collect_vec()
                })
                .collect_vec()
        })
        .collect_vec();
    // initial_date || rotated_state [MLEVec<E> indexed by (6, inst_num_vars); 25 + 25]
    wit[5] = chain![
        (0..25).map(|x| {
            let i = x % 5;
            let j = x / 5;
            wit[7][0]
                [(j << 3 ^ i) << (inst_num_vars + 6)..((j << 3 ^ i) + 1) << (inst_num_vars + 6)]
                .to_vec()
        }),
        (0..25).map(|x| {
            let i = x % 5;
            let j = x / 5;
            (0..inst_size)
                .flat_map(|z| {
                    (0..64)
                        .map(|k| wit[6][k][(z << 6) ^ (j << 3) ^ i])
                        .collect_vec()
                })
                .collect()
        })
    ]
    .collect();
    // result of xor3, xor2 [MLEVec<E> indexed by (1, 3, 6, inst_num_vars); 2]
    wit[4] = vec![
        (0..inst_size * 64)
            .flat_map(|k| {
                (0..8)
                    .flat_map(|i| {
                        if i < 5 {
                            vec![
                                wit[5][0 * 5 + (i + 1) % 5][k]
                                    ^ wit[5][1 * 5 + (i + 1) % 5][k]
                                    ^ wit[5][2 * 5 + (i + 1) % 5][k],
                                wit[5][1 * 5 + (i + 4) % 5][k] ^ wit[5][2 * 5 + (i + 4) % 5][k],
                            ]
                        } else {
                            vec![0, 0]
                        }
                    })
                    .collect_vec()
            })
            .collect_vec(),
        (0..inst_size * 64)
            .flat_map(|k| {
                (0..8)
                    .flat_map(|i| {
                        if i < 5 {
                            vec![
                                wit[5][3 * 5 + (i + 1) % 5][k]
                                    ^ wit[5][4 * 5 + (i + 1) % 5][k]
                                    ^ wit[5][0 * 5 + (i + 4) % 5][k],
                                wit[5][3 * 5 + (i + 4) % 5][k] ^ wit[5][4 * 5 + (i + 4) % 5][k],
                            ]
                        } else {
                            vec![0, 0]
                        }
                    })
                    .collect_vec()
            })
            .collect_vec(),
    ];
    // initial_state || result of xor2 [MLEVec<E> indexed by (3, 3, 6, inst_num_vars), MLEVec<E>
    // indexed by (3, 6, inst_num_vars), indexed by (3, 6, inst_num_vars)]
    wit[3] = vec![
        wit[7][0].clone(),
        (0..wit[4][0].len())
            .step_by(2)
            .map(|i| wit[4][0][i] ^ wit[4][1][i])
            .collect(),
        (0..wit[4][0].len())
            .skip(1)
            .step_by(2)
            .map(|i| wit[4][0][i] ^ wit[4][1][i])
            .collect(),
    ];
    // result of xor3 [MLEVec<E> indexed by (inst_num_vars); 64 * 25]
    wit[2] = (0..64 * 25)
        .map(|x| {
            let i = x % 5;
            let j = x % 25 / 5;
            let k = x / 25;
            (0..inst_size)
                .map(|z| {
                    let id1 = (z << 12) ^ (k << 6) ^ (j << 3) + i;
                    let id2 = (z << 9) ^ (k << 3) + i;
                    wit[3][0][id1] ^ wit[3][1][id2] ^ wit[3][2][id2]
                })
                .collect()
        })
        .collect_vec();
    let mut tmp: [MLEVec<u8>; 64 * 25] = wit[2].clone().try_into().unwrap();
    compute_rho_and_pi(&mut tmp);
    // input chi [MLEVec<E> indexed by (3, 6, inst_num_vars); 5]
    wit[1] = (0..5)
        .map(|i| {
            (0..64)
                .flat_map(|k| {
                    (0..8)
                        .flat_map(|j| {
                            if j < 5 {
                                mem::take(&mut tmp[k * 25 + j * 5 + i])
                            } else {
                                vec![0; inst_size]
                            }
                        })
                        .collect_vec()
                })
                .collect_vec()
        })
        .collect();
    // result chi [MLEVec<E> indexed by (3, 3, 6, inst_num_vars)]
    wit[0] = vec![(0..inst_size * 64 * 8 * 8)
        .map(|id| {
            let i = id & 7;
            let k = id >> 3;
            if i < 5 {
                wit[1][i][k] ^ ((!wit[1][(i + 1) % 5][k]) & wit[1][(i + 2) % 5][k])
            } else {
                0
            }
        })
        .collect_vec()];
    wit.into_iter()
        .map(|v| {
            v.into_iter()
                .map(|v| Arc::new(v.into_iter().map(|v| F::from(v as u64)).collect()))
                .collect_vec()
        })
        .collect_vec()
}

fn main() {
    type E = GoldilocksExt2;
    type F = Goldilocks;
    let max_thread_id: usize = env::var("RAYON_NUM_THREADS")
        .map(|v| str::parse::<usize>(&v).unwrap_or(1))
        .unwrap();

    let inst_num_vars = 12;
    let wit = witness_generation::<Goldilocks>(inst_num_vars);

    let mut transcript = Transcript::<GoldilocksExt2>::new(b"prover");
    let mut point = (0..12 + inst_num_vars)
        .map(|_| transcript.get_and_append_challenge(b"init point").elements)
        .collect_vec();
    let now = Instant::now();
    for round in 0..24 {
        point = prove_keccak_f(
            max_thread_id,
            inst_num_vars,
            &point,
            wit.clone(),
            round,
            &mut transcript,
        )
    }
    println!("Prove time: {} s", now.elapsed().as_secs_f64());
}
