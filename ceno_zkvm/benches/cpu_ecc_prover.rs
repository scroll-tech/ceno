use ceno_zkvm::scheme::{
    cpu::CpuEccProver,
    septic_curve::{SepticExtension, SepticPoint},
};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ff_ext::BabyBearExt4;
use itertools::Itertools;
use multilinear_extensions::mle::{IntoMLE, MultilinearExtension};
use p3::babybear::BabyBear;
use std::{iter::repeat_n, sync::Arc};
use transcript::BasicTranscript;
use witness::next_pow2_instance_padding;

fn bench_cpu_ecc_prover(c: &mut Criterion) {
    type E = BabyBearExt4;
    type F = BabyBear;
    let mut group = c.benchmark_group("cpu_ecc_prover");
    for &n_points in &[8, 64, 256, 1024, 4096] {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_points),
            &n_points,
            |b, &n_points| {
                let log2_n = next_pow2_instance_padding(n_points).ilog2();
                let mut rng = rand::thread_rng();
                let final_sum;
                let ecc_spec: Vec<_> = {
                    let mut points = (0..n_points)
                        .map(|_| SepticPoint::<F>::random(&mut rng))
                        .collect_vec();
                    let mut s = Vec::with_capacity(1 << (log2_n + 1));
                    for layer in (1..=log2_n).rev() {
                        let num_inputs = 1 << layer;
                        let inputs = &points[points.len() - num_inputs..];
                        s.extend(inputs.chunks_exact(2).map(|chunk| {
                            let p = &chunk[0];
                            let q = &chunk[1];
                            (&p.y - &q.y) * (&p.x - &q.x).inverse().unwrap()
                        }));
                        points.extend(
                            inputs
                                .chunks_exact(2)
                                .map(|chunk| {
                                    let p = chunk[0].clone();
                                    let q = chunk[1].clone();
                                    p + q
                                })
                                .collect_vec(),
                        );
                    }
                    final_sum = points.last().cloned().unwrap();
                    s.extend(repeat_n(
                        SepticExtension::zero(),
                        (1 << (log2_n + 1)) - s.len(),
                    ));
                    points.push(SepticPoint::point_at_infinity());
                    let trace = points
                        .iter()
                        .zip_eq(s.iter())
                        .map(|(p, s)| {
                            p.x.iter()
                                .chain(p.y.iter())
                                .chain(s.iter())
                                .copied()
                                .collect_vec()
                        })
                        .collect_vec();
                    multilinear_extensions::util::transpose(trace)
                        .into_iter()
                        .map(|v| v.into_mle())
                        .collect_vec()
                };
                let (xs, rest) = ecc_spec.split_at(7);
                let (ys, s) = rest.split_at(7);
                let xs = xs
                    .iter()
                    .map(|x: &MultilinearExtension<'_, E>| Arc::new(x.clone()))
                    .collect_vec();
                let ys = ys.iter().map(|y| Arc::new(y.clone())).collect_vec();
                let s = s.iter().map(|s| Arc::new(s.clone())).collect_vec();
                let mut transcript = BasicTranscript::new(b"bench");
                let prover = CpuEccProver::new();
                b.iter(|| {
                    let proof = prover.create_ecc_proof(
                        n_points,
                        xs.clone(),
                        ys.clone(),
                        s.clone(),
                        &mut transcript,
                    );
                    black_box(proof.sum);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_cpu_ecc_prover);
criterion_main!(benches);
