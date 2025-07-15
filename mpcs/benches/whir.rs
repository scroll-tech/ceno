use std::time::Duration;

use criterion::*;
use ff_ext::GoldilocksExt2;

use itertools::Itertools;
use mpcs::{
    PolynomialCommitmentScheme, SecurityLevel, WhirDefault,
    test_util::{get_point_from_challenge, setup_pcs},
};

use multilinear_extensions::mle::ArcMultilinearExtension;
use rand::rngs::OsRng;
use transcript::{BasicTranscript, Transcript};
use witness::RowMajorMatrix;

type T = BasicTranscript<GoldilocksExt2>;
type E = GoldilocksExt2;
type PcsGoldilocks = WhirDefault<E>;

const NUM_SAMPLES: usize = 10;
const NUM_VARS_START: usize = 20;
const NUM_VARS_END: usize = 20;
const BATCH_SIZE_LOG_START: usize = 6;
const BATCH_SIZE_LOG_END: usize = 6;

fn bench_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_open_verify_goldilocks".to_string());
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        let (pp, vp) = {
            let poly_size = 1 << num_vars;
            let param = Pcs::setup(poly_size, SecurityLevel::default()).unwrap();

            group.bench_function(BenchmarkId::new("setup", format!("{}", num_vars)), |b| {
                b.iter(|| {
                    Pcs::setup(poly_size, SecurityLevel::default()).unwrap();
                })
            });
            Pcs::trim(param, poly_size).unwrap()
        };

        let mut transcript = T::new(b"BaseFold");
        let rmm = RowMajorMatrix::rand(&mut OsRng, 1 << num_vars, 1);
        let poly: ArcMultilinearExtension<_> = rmm.to_mles().remove(0).into();
        let comm = Pcs::commit_and_write(&pp, rmm, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("commit", format!("{}", num_vars)), |b| {
            b.iter_custom(|iters| {
                let mut time = Duration::new(0, 0);
                for _ in 0..iters {
                    let rmm = RowMajorMatrix::rand(&mut OsRng, 1 << num_vars, 1);
                    let instant = std::time::Instant::now();
                    Pcs::commit(&pp, rmm).unwrap();
                    let elapsed = instant.elapsed();
                    time += elapsed;
                }
                time
            })
        });

        let point = get_point_from_challenge(num_vars, &mut transcript);
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
        let point = get_point_from_challenge(num_vars, &mut transcript);
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

fn bench_simple_batch_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(
    c: &mut Criterion,
) {
    let mut group = c.benchmark_group("simple_batch_commit_open_verify_goldilocks".to_string());
    group.sample_size(NUM_SAMPLES);
    let mut rng = rand::thread_rng();
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let rmms = vec![RowMajorMatrix::rand(&mut rng, 1 << num_vars, batch_size)];

            group.bench_function(
                BenchmarkId::new("batch_commit", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_custom(|iters| {
                        let mut time = Duration::new(0, 0);
                        for _ in 0..iters {
                            let mut transcript = T::new(b"BaseFold");
                            let rmms = rmms.clone();
                            let instant = std::time::Instant::now();
                            Pcs::batch_commit_and_write(&pp, rmms, &mut transcript).unwrap();
                            let elapsed = instant.elapsed();
                            time += elapsed;
                        }
                        time
                    })
                },
            );

            let mut transcript = T::new(b"BaseFold");
            let polys = rmms[0].to_mles();
            let comm = Pcs::batch_commit_and_write(&pp, rmms, &mut transcript).unwrap();
            let point = get_point_from_challenge(num_vars, &mut transcript);
            let evals = polys.iter().map(|poly| poly.evaluate(&point)).collect_vec();
            transcript.append_field_element_exts(&evals);
            let transcript_for_bench = transcript.clone();
            let polys = polys
                .iter()
                .map(|poly| ArcMultilinearExtension::from(poly.clone()))
                .collect::<Vec<_>>();
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
            let mut transcript = BasicTranscript::new(b"BaseFold");
            Pcs::write_commitment(&comm, &mut transcript).unwrap();

            let point = get_point_from_challenge(num_vars, &mut transcript);
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

fn bench_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocks>(c);
}

fn bench_simple_batch_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocks>(c);
}

criterion_group! {
  name = bench_whir;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets =
  bench_simple_batch_commit_open_verify_goldilocks_base,
  bench_commit_open_verify_goldilocks_base,
}

criterion_main!(bench_whir);
