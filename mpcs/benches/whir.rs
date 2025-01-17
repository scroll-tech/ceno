use std::time::Duration;

use criterion::*;
use ff_ext::ExtensionField;
use goldilocks::GoldilocksExt2;

use itertools::{Itertools, chain};
use mpcs::{
    Evaluation, PolynomialCommitmentScheme, Whir, WhirDefault,
    test_util::{
        commit_polys_individually, gen_rand_poly_base, gen_rand_poly_ext, gen_rand_polys,
        get_point_from_challenge, get_points_from_challenge, setup_pcs,
    },
    util::plonky2_util::log2_ceil,
};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::ArcMultilinearExtension,
};
use transcript::{BasicTranscript, Transcript};

type T = BasicTranscript<GoldilocksExt2>;
type E = GoldilocksExt2;
type PcsGoldilocks = WhirDefault<E>;

const NUM_SAMPLES: usize = 10;
const NUM_VARS_START: usize = 20;
const NUM_VARS_END: usize = 20;
const BATCH_SIZE_LOG_START: usize = 6;
const BATCH_SIZE_LOG_END: usize = 6;

fn bench_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("commit_open_verify_goldilocks",));
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
            Pcs::trim(param, poly_size).unwrap()
        };

        let mut transcript = T::new(b"BaseFold");
        let poly = gen_rand_poly_base(num_vars);
        let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("commit", format!("{}", num_vars)), |b| {
            b.iter(|| {
                Pcs::commit(&pp, &poly).unwrap();
            })
        });

        let point = get_point_from_challenge(num_vars, &mut transcript);
        let eval = poly.evaluate(point.as_slice());
        transcript.append_field_element_ext(&eval);
        let transcript_for_bench = transcript;
        let proof = Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("open", format!("{}", num_vars)), |b| {
            b.iter_batched(
                || transcript_for_bench,
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
        let transcript_for_bench = transcript;
        Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();
        group.bench_function(BenchmarkId::new("verify", format!("{}", num_vars)), |b| {
            b.iter_batched(
                || transcript_for_bench,
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
    let mut group = c.benchmark_group(format!("simple_batch_commit_open_verify_goldilocks",));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);
            let mut transcript = T::new(b"BaseFold");
            let polys = gen_rand_polys(|_| num_vars, batch_size, gen_rand_poly_base);
            let comm = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_commit", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter(|| {
                        Pcs::batch_commit(&pp, &polys).unwrap();
                    })
                },
            );
            let point = get_point_from_challenge(num_vars, &mut transcript);
            let evals = polys.iter().map(|poly| poly.evaluate(&point)).collect_vec();
            transcript.append_field_element_exts(&evals);
            let transcript_for_bench = transcript;
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
                        || transcript_for_bench,
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
            let backup_transcript = transcript;

            Pcs::simple_batch_verify(&vp, &comm, &point, &evals, &proof, &mut transcript).unwrap();

            group.bench_function(
                BenchmarkId::new("batch_verify", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || backup_transcript,
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
