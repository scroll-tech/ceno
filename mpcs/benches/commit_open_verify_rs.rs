use std::time::Duration;

use criterion::*;
use ff::Field;
use goldilocks::GoldilocksExt2;

use itertools::{chain, Itertools};
use mpcs::{
    util::plonky2_util::log2_ceil, Basefold, BasefoldRSParams, Evaluation,
    PolynomialCommitmentScheme,
};

use multilinear_extensions::mle::{DenseMultilinearExtension, MultilinearExtension};
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use transcript::Transcript;

type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams, ChaCha8Rng>;
type T = Transcript<GoldilocksExt2>;
type E = GoldilocksExt2;

const NUM_SAMPLES: usize = 10;
const NUM_VARS_START: usize = 20;
const NUM_VARS_END: usize = 20;
const BATCH_SIZE_LOG_START: usize = 6;
const BATCH_SIZE_LOG_END: usize = 6;

fn bench_commit_open_verify_goldilocks(c: &mut Criterion, is_base: bool) {
    let mut group = c.benchmark_group(format!(
        "commit_open_verify_goldilocks_rs_{}",
        if is_base { "base" } else { "ext2" }
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        let (pp, vp) = {
            let poly_size = 1 << num_vars;
            let param = Pcs::setup(poly_size).unwrap();

            group.bench_function(BenchmarkId::new("setup", format!("{}", num_vars)), |b| {
                b.iter(|| {
                    Pcs::setup(poly_size).unwrap();
                })
            });
            Pcs::trim(&param, poly_size).unwrap()
        };

        let mut transcript = T::new(b"BaseFold");
        let poly = if is_base {
            DenseMultilinearExtension::random(num_vars, &mut OsRng)
        } else {
            DenseMultilinearExtension::from_evaluations_ext_vec(
                num_vars,
                (0..1 << num_vars)
                    .into_par_iter()
                    .map(|_| E::random(&mut OsRng))
                    .collect(),
            )
        };

        let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("commit", format!("{}", num_vars)), |b| {
            b.iter(|| {
                Pcs::commit(&pp, &poly).unwrap();
            })
        });

        let point = (0..num_vars)
            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
            .collect::<Vec<_>>();
        let eval = poly.evaluate(point.as_slice());
        transcript.append_field_element_ext(&eval);
        let transcript_for_bench = transcript.clone();
        let proof = Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("open", format!("{}", num_vars)), |b| {
            b.iter_batched(
                || transcript_for_bench.clone(),
                |mut transcript| {
                    Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        // Verify
        let comm = Pcs::get_pure_commitment(&comm);
        let mut transcript = T::new(b"BaseFold");
        Pcs::write_commitment(&comm, &mut transcript).unwrap();
        let point = (0..num_vars)
            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
            .collect::<Vec<_>>();
        transcript.append_field_element_ext(&eval);
        let transcript_for_bench = transcript.clone();
        Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();
        group.bench_function(BenchmarkId::new("verify", format!("{}", num_vars)), |b| {
            b.iter_batched(
                || transcript_for_bench.clone(),
                |mut transcript| {
                    Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn bench_batch_commit_open_verify_goldilocks(c: &mut Criterion, is_base: bool) {
    let mut group = c.benchmark_group(format!(
        "batch_commit_open_verify_goldilocks_rs_{}",
        if is_base { "base" } else { "ext2" }
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let num_points = batch_size >> 1;
            let rng = ChaCha8Rng::from_seed([0u8; 32]);
            // Setup
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size).unwrap();
                Pcs::trim(&param, poly_size).unwrap()
            };
            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let mut transcript = T::new(b"BaseFold");
            let polys = (0..batch_size)
                .map(|i| {
                    if is_base {
                        DenseMultilinearExtension::random(
                            num_vars - log2_ceil((i >> 1) + 1),
                            &mut rng.clone(),
                        )
                    } else {
                        DenseMultilinearExtension::from_evaluations_ext_vec(
                            num_vars - log2_ceil((i >> 1) + 1),
                            (0..1 << (num_vars - log2_ceil((i >> 1) + 1)))
                                .into_par_iter()
                                .map(|_| E::random(&mut OsRng))
                                .collect(),
                        )
                    }
                })
                .collect_vec();
            let comms = polys
                .iter()
                .map(|poly| Pcs::commit_and_write(&pp, poly, &mut transcript).unwrap())
                .collect_vec();

            let points = (0..num_points)
                .map(|i| {
                    (0..num_vars - i)
                        .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                        .collect::<Vec<_>>()
                })
                .take(num_points)
                .collect_vec();

            let evals = evals
                .iter()
                .copied()
                .map(|(poly, point)| {
                    Evaluation::new(poly, point, polys[poly].evaluate(&points[point]))
                })
                .collect_vec();
            let values: Vec<E> = evals
                .iter()
                .map(Evaluation::value)
                .map(|x| *x)
                .collect::<Vec<E>>();
            transcript.append_field_element_exts(values.as_slice());
            let transcript_for_bench = transcript.clone();
            let proof =
                Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_open", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || transcript_for_bench.clone(),
                        |mut transcript| {
                            Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript)
                                .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
            // Batch verify
            let mut transcript = T::new(b"BaseFold");
            let comms = comms
                .iter()
                .map(|comm| {
                    let comm = Pcs::get_pure_commitment(comm);
                    Pcs::write_commitment(&comm, &mut transcript).unwrap();
                    comm
                })
                .collect_vec();
            let points = (0..num_points)
                .map(|i| {
                    (0..num_vars - i)
                        .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                        .collect::<Vec<_>>()
                })
                .take(num_points)
                .collect_vec();

            let values: Vec<E> = evals
                .iter()
                .map(Evaluation::value)
                .map(|x| *x)
                .collect::<Vec<E>>();
            transcript.append_field_element_exts(values.as_slice());

            let backup_transcript = transcript.clone();

            Pcs::batch_verify(&vp, &comms, &points, &evals, &proof, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_verify", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || backup_transcript.clone(),
                        |mut transcript| {
                            Pcs::batch_verify(
                                &vp,
                                &comms,
                                &points,
                                &evals,
                                &proof,
                                &mut transcript,
                            )
                            .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_simple_batch_commit_open_verify_goldilocks(c: &mut Criterion, is_base: bool) {
    let mut group = c.benchmark_group(format!(
        "simple_batch_commit_open_verify_goldilocks_rs_{}",
        if is_base { "base" } else { "extension" }
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let rng = ChaCha8Rng::from_seed([0u8; 32]);
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size).unwrap();
                Pcs::trim(&param, poly_size).unwrap()
            };
            let mut transcript = T::new(b"BaseFold");
            let polys = (0..batch_size)
                .map(|_| {
                    if is_base {
                        DenseMultilinearExtension::random(num_vars, &mut rng.clone())
                    } else {
                        DenseMultilinearExtension::from_evaluations_ext_vec(
                            num_vars,
                            (0..1 << num_vars)
                                .into_par_iter()
                                .map(|_| E::random(&mut OsRng))
                                .collect(),
                        )
                    }
                })
                .collect_vec();
            let comm = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_commit", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter(|| {
                        Pcs::batch_commit(&pp, &polys).unwrap();
                    })
                },
            );

            let point = (0..num_vars)
                .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                .collect::<Vec<_>>();

            let evals = (0..batch_size)
                .map(|i| polys[i].evaluate(&point))
                .collect_vec();

            transcript.append_field_element_exts(&evals);
            let transcript_for_bench = transcript.clone();
            let proof = Pcs::simple_batch_open(&pp, &polys, &comm, &point, &evals, &mut transcript)
                .unwrap();

            group.bench_function(
                BenchmarkId::new("batch_open", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || transcript_for_bench.clone(),
                        |mut transcript| {
                            Pcs::simple_batch_open(
                                &pp,
                                &polys,
                                &comm,
                                &point,
                                &evals,
                                &mut transcript,
                            )
                            .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
            let comm = Pcs::get_pure_commitment(&comm);

            // Batch verify
            let mut transcript = Transcript::new(b"BaseFold");
            Pcs::write_commitment(&comm, &mut transcript).unwrap();

            let point = (0..num_vars)
                .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                .collect::<Vec<_>>();
            transcript.append_field_element_exts(&evals);
            let backup_transcript = transcript.clone();

            Pcs::simple_batch_verify(&vp, &comm, &point, &evals, &proof, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_verify", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || backup_transcript.clone(),
                        |mut transcript| {
                            Pcs::simple_batch_verify(
                                &vp,
                                &comm,
                                &point,
                                &evals,
                                &proof,
                                &mut transcript,
                            )
                            .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_commit_open_verify_goldilocks_2(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks(c, false);
}

fn bench_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks(c, true);
}

fn bench_batch_commit_open_verify_goldilocks_2(c: &mut Criterion) {
    bench_batch_commit_open_verify_goldilocks(c, false);
}

fn bench_batch_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    bench_batch_commit_open_verify_goldilocks(c, true);
}

fn bench_simple_batch_commit_open_verify_goldilocks_2(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks(c, false);
}

fn bench_simple_batch_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks(c, true);
}

criterion_group! {
  name = bench_basefold;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets = bench_simple_batch_commit_open_verify_goldilocks_base, bench_simple_batch_commit_open_verify_goldilocks_2, bench_batch_commit_open_verify_goldilocks_base, bench_batch_commit_open_verify_goldilocks_2, bench_commit_open_verify_goldilocks_base, bench_commit_open_verify_goldilocks_2,
}

criterion_main!(bench_basefold);
