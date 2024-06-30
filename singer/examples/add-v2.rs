#![feature(generic_const_exprs)]
use paste::paste;
use std::{array, sync::Arc, time::Instant};

use ark_std::test_rng;
use ff_ext::{ff::Field, ExtensionField};
use gkr::structs::Point;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::{chain, Itertools};
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use sumcheck::structs::{IOPProof, IOPProverState};
use transcript::Transcript;

type ArcMLEVec<E> = Arc<Vec<E>>;

fn log2(x: usize) -> usize {
    (std::mem::size_of::<usize>() * 8 - 1) - x.leading_zeros() as usize
}

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

/// read_records: 4, write_record: 2, lookup_records: 32
/// layer 1:    read, write, lookup
/// layer 2:    read, lookup
/// layer 3~5:  lookup
fn prove_table_read_write_lookup<E: ExtensionField, const L: usize>(
    max_thread_id: usize,
    point: Point<E>,
    ld: &[ArcMLEVec<E>],
    ln: &[ArcMLEVec<E>],
    r: &[ArcMLEVec<E>],
    w: &[ArcMLEVec<E>],
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, Vec<[E; 2]>) {
    println!("prove_table_read_write_lookup");
    let num_vars = point.len();
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = log2(thread_size);

    let eq = build_eq_x_r_vec(&point);
    let rc_s = alpha_pows(4, transcript);
    println!("point len: {}", point.len());
    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let feq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fld = ld
                .iter()
                .map(|ld| {
                    Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                        thread_nv,
                        &ld[thread_id * thread_size..(thread_id + 1) * thread_size],
                    ))
                })
                .collect_vec();
            let fln = ln
                .iter()
                .map(|ln| {
                    Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                        thread_nv,
                        &ln[thread_id * thread_size..(thread_id + 1) * thread_size],
                    ))
                })
                .collect_vec();
            let fr = r
                .iter()
                .map(|r| {
                    Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                        thread_nv,
                        &r[thread_id * thread_size..(thread_id + 1) * thread_size],
                    ))
                })
                .collect_vec();
            let fw = w
                .iter()
                .map(|w| {
                    Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                        thread_nv,
                        &w[thread_id * thread_size..(thread_id + 1) * thread_size],
                    ))
                })
                .collect_vec();

            let mut virtual_poly = VirtualPolynomial::new(thread_nv);
            virtual_poly.add_mle_list(vec![feq.clone(), fld[0].clone(), fld[1].clone()], rc_s[0]);
            virtual_poly.add_mle_list(vec![feq.clone(), fld[1].clone(), fln[0].clone()], rc_s[1]);
            virtual_poly.add_mle_list(vec![feq.clone(), fld[0].clone(), fln[1].clone()], rc_s[1]);
            match L {
                1 => {
                    virtual_poly
                        .add_mle_list(vec![feq.clone(), fr[0].clone(), fr[1].clone()], rc_s[2]);
                    virtual_poly
                        .add_mle_list(vec![feq.clone(), fw[0].clone(), fw[1].clone()], rc_s[3]);
                }
                2 => {
                    virtual_poly
                        .add_mle_list(vec![feq.clone(), fr[0].clone(), fr[1].clone()], rc_s[2]);
                }
                _ => {}
            }
            virtual_poly
        })
        .collect_vec();

    let (proof, state) =
        IOPProverState::prove_batch_polys(max_thread_id, virtual_polys, transcript);
    let evals = state.get_mle_final_evaluations();
    let mut point = proof.point.clone();
    println!("point: {:?}", point);
    let r = transcript.get_and_append_challenge(b"merge").elements;
    point.push(r);
    println!("point: {:?}", point);
    (
        proof,
        point,
        evals[1..].chunks(2).map(|c| [c[0], c[1]]).collect(),
    )
}

fn prove_select<E: ExtensionField>(
    max_thread_id: usize,
    inst_num_vars: usize,
    real_inst_size: usize,
    l_point: &Point<E>,
    r_point: &Point<E>,
    w_point: &Point<E>,
    ld: &[ArcMLEVec<E>; 32],
    ln: &[ArcMLEVec<E>; 32],
    r: &[ArcMLEVec<E>; 4],
    w: &[ArcMLEVec<E>; 2],
    transcript: &mut Transcript<E>,
) -> (IOPProof<E>, Point<E>, Vec<E>) {
    println!("prove select");
    let num_vars = inst_num_vars;
    let max_thread_id = max_thread_id.min(1 << num_vars);
    let thread_size = (1 << num_vars) / max_thread_id;
    let thread_nv = log2(thread_size);

    let l_eq = build_eq_x_r_vec(&l_point[5..]);
    let r_eq = build_eq_x_r_vec(&r_point[2..]);
    let w_eq = build_eq_x_r_vec(&w_point[1..]);
    let mut sel = vec![E::BaseField::ONE; real_inst_size];
    sel.extend(vec![
        E::BaseField::ZERO;
        (1 << inst_num_vars) - real_inst_size
    ]);
    let rc_s = alpha_pows(4, transcript);
    let lrc_s = build_eq_x_r_vec(&l_point[..5]);
    let rrc_s = build_eq_x_r_vec(&r_point[..2]);
    let wrc_s = build_eq_x_r_vec(&w_point[..1]);
    let virtual_polys = (0..max_thread_id)
        .map(|thread_id| {
            let fl_eq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &l_eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fr_eq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &r_eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fw_eq = Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                thread_nv,
                &w_eq[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fsel = Arc::new(DenseMultilinearExtension::from_evaluations_slice(
                thread_nv,
                &sel[thread_id * thread_size..(thread_id + 1) * thread_size],
            ));
            let fld: [_; 32] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                    thread_nv,
                    &ld[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            let fln: [_; 32] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                    thread_nv,
                    &ln[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            let fr: [_; 4] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                    thread_nv,
                    &r[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });
            let fw: [_; 2] = array::from_fn(|i| {
                Arc::new(DenseMultilinearExtension::from_evaluations_ext_slice(
                    thread_nv,
                    &w[i][thread_id * thread_size..(thread_id + 1) * thread_size],
                ))
            });

            let mut virtual_poly = VirtualPolynomial::new(thread_nv);
            // alpha^0 * (sel * (fld[i] - 1) * lrc[i] + lrc[i]), poly is alpha^0 * lrc[i] * sel *
            // fld - alpha^0 * lrc[i] * sel
            let mut sel_coeff = E::ZERO;
            (0..32).for_each(|i| {
                virtual_poly.add_mle_list(
                    vec![fl_eq.clone(), fld[i].clone(), fsel.clone()],
                    rc_s[0] * lrc_s[i],
                );
                sel_coeff += rc_s[0] * lrc_s[i];
            });
            // alpha^1 * (sel * fln[i] * lrc[i]), poly is alpha^1 * lrc[i] * sel * fln
            (0..32).for_each(|i| {
                virtual_poly.add_mle_list(
                    vec![fl_eq.clone(), fln[i].clone(), fsel.clone()],
                    rc_s[1] * lrc_s[i],
                );
            });
            // alpha^2 * (sel * (fr[i] - 1) * rrc[i] + rrc[i]), poly is alpha^2 * rrc[i] * sel *
            // fr - alpha^2 * rrc[i] * sel
            (0..4).for_each(|i| {
                virtual_poly.add_mle_list(
                    vec![fr_eq.clone(), fr[i].clone(), fsel.clone()],
                    rc_s[2] * rrc_s[i],
                );
                sel_coeff += rc_s[2] * rrc_s[i];
            });
            // alpha^3 * (sel * (fw[i] - 1) * rrc[i] + rrc[i]), poly is alpha^3 * wrc[i] * sel *
            // fw - alpha^2 * wrc[i] * sel
            (0..2).for_each(|i| {
                virtual_poly.add_mle_list(
                    vec![fw_eq.clone(), fw[i].clone(), fsel.clone()],
                    rc_s[3] * wrc_s[i],
                );
                sel_coeff += rc_s[3] * wrc_s[i];
            });
            virtual_poly.add_mle_list(vec![fsel], -sel_coeff);
            virtual_poly
        })
        .collect_vec();

    let (proof, state) =
        IOPProverState::prove_batch_polys(max_thread_id, virtual_polys, transcript);
    let evals = state.get_mle_final_evaluations();
    let point = proof.point.clone();
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
    let max_thread_id = 2;
    let inst_num_vars = 15;
    let tree_layer = inst_num_vars + 5;

    let real_inst_size = 1000;

    let input = array::from_fn(|_| {
        Arc::new(
            (0..(1 << inst_num_vars))
                .map(|_| F::random(test_rng()))
                .collect_vec(),
        )
    });
    let mut wit = vec![vec![]; tree_layer + 1];
    (0..inst_num_vars + 1).for_each(|i| {
        wit[i] = vec![
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
        ];
    });
    (inst_num_vars + 1..inst_num_vars + 2).for_each(|i| {
        wit[i] = vec![
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
        ];
    });
    (inst_num_vars + 2..tree_layer).for_each(|i| {
        wit[i] = vec![
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
            Arc::new((0..1 << i).map(|_| E::random(test_rng())).collect_vec()),
        ];
    });
    wit[tree_layer] = (0..70)
        .map(|_| {
            Arc::new(
                (0..(1 << inst_num_vars))
                    .map(|_| E::random(test_rng()))
                    .collect_vec(),
            )
        })
        .collect_vec();

    let mut transcript = &mut Transcript::<E>::new(b"prover");
    let time = Instant::now();
    let w_point = (0..inst_num_vars + 1).fold(vec![], |last_point, i| {
        let (_, nxt_point, _) = prove_table_read_write_lookup::<_, 1>(
            max_thread_id,
            last_point,
            &wit[i][0..2],
            &wit[i][2..4],
            &wit[i][4..6],
            &wit[i][6..8],
            &mut transcript,
        );
        nxt_point
    });
    let r_point = (inst_num_vars + 1..inst_num_vars + 2).fold(w_point.clone(), |last_point, i| {
        let (_, nxt_point, _) = prove_table_read_write_lookup::<_, 2>(
            max_thread_id,
            last_point,
            &wit[i][0..2],
            &wit[i][2..4],
            &wit[i][4..6],
            &[],
            &mut transcript,
        );
        nxt_point
    });
    let l_point = (inst_num_vars + 2..tree_layer).fold(r_point.clone(), |last_point, i| {
        let (_, nxt_point, _) = prove_table_read_write_lookup::<_, 3>(
            max_thread_id,
            last_point,
            &wit[i][0..2],
            &wit[i][2..4],
            &[],
            &[],
            &mut transcript,
        );
        nxt_point
    });

    assert_eq!(l_point.len(), inst_num_vars + 5);
    assert_eq!(r_point.len(), inst_num_vars + 2);
    assert_eq!(w_point.len(), inst_num_vars + 1);

    let ld: &[_; 32] = wit[tree_layer][..32].try_into().unwrap();
    let ln: &[_; 32] = wit[tree_layer][32..64].try_into().unwrap();
    let r: &[_; 4] = wit[tree_layer][64..68].try_into().unwrap();
    let w: &[_; 2] = wit[tree_layer][68..70].try_into().unwrap();
    let (_, point, _) = prove_select(
        max_thread_id,
        inst_num_vars,
        real_inst_size,
        &l_point,
        &r_point,
        &w_point,
        &ld,
        &ln,
        &r,
        &w,
        &mut transcript,
    );
    prove_add_opcode(&point, &input);
    println!("prove time: {} s", time.elapsed().as_secs_f64());
}
