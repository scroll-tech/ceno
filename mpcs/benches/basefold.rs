use std::time::Duration;

use criterion::*;
use goldilocks::GoldilocksExt2;

use itertools::{Itertools, chain};
use mpcs::{
    Basefold, BasefoldBasecodeKeccakParams, BasefoldBasecodePoseidonParams, BasefoldRSKeccakParams,
    BasefoldRSPoseidonParams, Evaluation, PolynomialCommitmentScheme,
    test_util::{
        commit_polys_individually, gen_rand_poly, gen_rand_polys, get_point_from_challenge,
        get_points_from_challenge, setup_pcs, vecs_as_slices,
    },
    util::plonky2_util::log2_ceil,
};

use multilinear_extensions::{mle::MultilinearExtension, virtual_poly_v2::ArcMultilinearExtension};
use transcript::Transcript;

type PcsGoldilocksRSCodePoseidon = Basefold<GoldilocksExt2, BasefoldRSPoseidonParams>;
type PcsGoldilocksBasecodePoseidon = Basefold<GoldilocksExt2, BasefoldBasecodePoseidonParams>;
type PcsGoldilocksRSCodeKeccak = Basefold<GoldilocksExt2, BasefoldRSKeccakParams>;
type PcsGoldilocksBasecodeKeccak = Basefold<GoldilocksExt2, BasefoldBasecodeKeccakParams>;
type T = Transcript<GoldilocksExt2>;
type E = GoldilocksExt2;

const NUM_SAMPLES: usize = 10;
const NUM_VARS_START: usize = 20;
const NUM_VARS_END: usize = 20;
const BATCH_SIZE_LOG_START: usize = 6;
const BATCH_SIZE_LOG_END: usize = 6;

fn bench_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(
    c: &mut Criterion,
    is_base: bool,
    id: &str,
) {
    let mut group = c.benchmark_group(format!(
        "commit_open_verify_goldilocks_{}_{}",
        id,
        if is_base { "base" } else { "ext2" },
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
        let poly = gen_rand_poly(num_vars, is_base);
        let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();

        group.bench_function(BenchmarkId::new("commit", format!("{}", num_vars)), |b| {
            b.iter(|| {
                Pcs::commit(&pp, &poly).unwrap();
            })
        });

        let point = get_point_from_challenge(num_vars, &mut transcript);
        let eval = poly.evaluate(point.as_slice());
        transcript.append_field_element_ext(&eval);
        let transcript_for_bench = transcript.clone();
        let poly = ArcMultilinearExtension::from(poly);
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

fn bench_batch_vlmp_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(
    c: &mut Criterion,
    is_base: bool,
    id: &str,
) {
    let mut group = c.benchmark_group(format!(
        "batch_commit_open_verify_goldilocks_{}_{}",
        id,
        if is_base { "base" } else { "ext2" },
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let num_points = batch_size >> 1;
            // Setup
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);
            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let mut transcript = T::new(b"BaseFold");
            let polys = gen_rand_polys(|i| num_vars - log2_ceil((i >> 1) + 1), batch_size, is_base);
            let comms = commit_polys_individually::<E, Pcs>(&pp, &polys, &mut transcript);

            let points = get_points_from_challenge(
                |i| num_vars - log2_ceil(i + 1),
                num_points,
                &mut transcript,
            );

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
                .copied()
                .collect::<Vec<E>>();
            transcript.append_field_element_exts(values.as_slice());
            let transcript_for_bench = transcript.clone();
            let polys = polys
                .iter()
                .map(|poly| ArcMultilinearExtension::from(poly.clone()))
                .collect::<Vec<_>>();
            let proof = Pcs::batch_open_vlmp(
                &pp,
                &polys,
                &comms,
                &vecs_as_slices(&points),
                &evals,
                &mut transcript,
            )
            .unwrap();

            group.bench_function(
                BenchmarkId::new("batch_open", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || transcript_for_bench.clone(),
                        |mut transcript| {
                            Pcs::batch_open_vlmp(
                                &pp,
                                &polys,
                                &comms,
                                &vecs_as_slices(&points),
                                &evals,
                                &mut transcript,
                            )
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
            let points = get_points_from_challenge(
                |i| num_vars - log2_ceil(i + 1),
                num_points,
                &mut transcript,
            );

            let values: Vec<E> = evals
                .iter()
                .map(Evaluation::value)
                .copied()
                .collect::<Vec<E>>();
            transcript.append_field_element_exts(values.as_slice());

            let backup_transcript = transcript.clone();

            Pcs::batch_verify_vlmp(
                &vp,
                &comms,
                &vecs_as_slices(&points),
                &evals,
                &proof,
                &mut transcript,
            )
            .unwrap();

            group.bench_function(
                BenchmarkId::new("batch_verify", format!("{}-{}", num_vars, batch_size)),
                |b| {
                    b.iter_batched(
                        || backup_transcript.clone(),
                        |mut transcript| {
                            Pcs::batch_verify_vlmp(
                                &vp,
                                &comms,
                                &vecs_as_slices(&points),
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

fn bench_simple_batch_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(
    c: &mut Criterion,
    is_base: bool,
    id: &str,
) {
    let mut group = c.benchmark_group(format!(
        "simple_batch_commit_open_verify_goldilocks_{}_{}",
        id,
        if is_base { "base" } else { "extension" },
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);
            let mut transcript = T::new(b"BaseFold");
            let polys = gen_rand_polys(|_| num_vars, batch_size, is_base);
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
            let mut transcript = Transcript::new(b"BaseFold");
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

fn bench_batch_vlop_commit_open_verify_goldilocks<Pcs: PolynomialCommitmentScheme<E>>(
    c: &mut Criterion,
    is_base: bool,
    id: &str,
) {
    let mut group = c.benchmark_group(format!(
        "batch_vlop_commit_open_verify_goldilocks_{}_{}",
        id,
        if is_base { "base" } else { "extension" },
    ));
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size_outer_log = batch_size_log / 2;
            let batch_size_inner_log = batch_size_log - batch_size_outer_log;
            let batch_size_outer = 1 << batch_size_outer_log;
            let batch_size_inner = 1 << batch_size_inner_log;

            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let mut transcript = Transcript::new(b"BaseFold");
            let (polys, comms) = (0..batch_size_outer)
                .map(|i| {
                    let polys = gen_rand_polys(|_| num_vars - i, batch_size_inner, is_base);
                    let comm = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();
                    (polys, comm)
                })
                .collect::<(Vec<_>, Vec<_>)>();

            let point = get_point_from_challenge(num_vars, &mut transcript);
            let evals = polys
                .iter()
                .map(|polys| {
                    let evals = polys
                        .iter()
                        .map(|poly| poly.evaluate(&point[..poly.num_vars()]))
                        .collect_vec();
                    transcript.append_field_element_exts(&evals);
                    evals
                })
                .collect_vec();
            let transcript_for_bench = transcript.clone();
            let polys = polys
                .iter()
                .map(|polys| {
                    polys
                        .iter()
                        .map(|poly| ArcMultilinearExtension::from(poly.clone()))
                        .collect_vec()
                })
                .collect_vec();

            let proof = Pcs::batch_open_vlop(
                &pp,
                &vecs_as_slices(&polys),
                &comms,
                &point,
                &vecs_as_slices(&evals),
                &mut transcript,
            )
            .unwrap();

            group.bench_function(
                BenchmarkId::new(
                    "batch_open",
                    format!("{}-{}-{}", num_vars, batch_size_outer, batch_size_inner),
                ),
                |b| {
                    b.iter_batched(
                        || transcript_for_bench.clone(),
                        |mut transcript| {
                            Pcs::batch_open_vlop(
                                &pp,
                                &vecs_as_slices(&polys),
                                &comms,
                                &point,
                                &vecs_as_slices(&evals),
                                &mut transcript,
                            )
                            .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            // Batch verify

            let mut transcript = Transcript::new(b"BaseFold");
            let comms = comms
                .iter()
                .map(|comm| {
                    let comm = Pcs::get_pure_commitment(comm);
                    Pcs::write_commitment(&comm, &mut transcript).unwrap();
                    comm
                })
                .collect_vec();

            let point = get_point_from_challenge(num_vars, &mut transcript);
            evals.iter().for_each(|evals| {
                transcript.append_field_element_exts(evals);
            });
            let backup_transcript = transcript.clone();

            Pcs::batch_verify_vlop(
                &vp,
                &comms,
                &point,
                num_vars,
                &vecs_as_slices(&evals),
                &proof,
                &mut transcript,
            )
            .unwrap();

            group.bench_function(
                BenchmarkId::new(
                    "batch_verify",
                    format!("{}-{}-{}", num_vars, batch_size_outer, batch_size_inner),
                ),
                |b| {
                    b.iter_batched(
                        || backup_transcript.clone(),
                        |mut transcript| {
                            Pcs::batch_verify_vlop(
                                &vp,
                                &comms,
                                &point,
                                num_vars,
                                &vecs_as_slices(&evals),
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

fn bench_commit_open_verify_goldilocks_ext_rs(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, false, "rs");
}

fn bench_commit_open_verify_goldilocks_ext_basecode(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(c, false, "basecode");
}

fn bench_commit_open_verify_goldilocks_base_rs(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, true, "rs");
}

fn bench_commit_open_verify_goldilocks_base_basecode(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(c, true, "basecode");
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_ext_rs(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, false, "rs");
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_ext_basecode(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, false, "basecode",
    );
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_base_rs(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, true, "rs");
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_base_basecode(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, true, "basecode",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_ext_rs(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, false, "rs");
}

fn bench_simple_batch_commit_open_verify_goldilocks_ext_basecode(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, false, "basecode",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_base_rs(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, true, "rs");
}

fn bench_simple_batch_commit_open_verify_goldilocks_base_basecode(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, true, "basecode",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_ext_rs(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, false, "rs");
}

fn bench_batch_vlop_commit_open_verify_goldilocks_ext_basecode(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, false, "basecode",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_base_rs(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksRSCodePoseidon>(c, true, "rs");
}

fn bench_batch_vlop_commit_open_verify_goldilocks_base_basecode(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksBasecodePoseidon>(
        c, true, "basecode",
    );
}

fn bench_commit_open_verify_goldilocks_ext_rs_keccak(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(c, false, "rs_keccak");
}

fn bench_commit_open_verify_goldilocks_ext_basecode_keccak(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(c, false, "basecode_keccak");
}

fn bench_commit_open_verify_goldilocks_base_rs_keccak(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(c, true, "rs_keccak");
}

fn bench_commit_open_verify_goldilocks_base_basecode_keccak(c: &mut Criterion) {
    bench_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(c, true, "basecode_keccak");
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_ext_rs_keccak(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        false,
        "rs_keccak",
    );
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_ext_basecode_keccak(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        false,
        "basecode_keccak",
    );
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_base_rs_keccak(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        true,
        "rs_keccak",
    );
}

fn bench_batch_vlmp_commit_open_verify_goldilocks_base_basecode_keccak(c: &mut Criterion) {
    bench_batch_vlmp_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        true,
        "basecode_keccak",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_ext_rs_keccak(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        false,
        "rs_keccak",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_ext_basecode_keccak(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        false,
        "basecode_keccak",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_base_rs_keccak(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        true,
        "rs_keccak",
    );
}

fn bench_simple_batch_commit_open_verify_goldilocks_base_basecode_keccak(c: &mut Criterion) {
    bench_simple_batch_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        true,
        "basecode_keccak",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_ext_rs_keccak(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        false,
        "rs_keccak",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_ext_basecode_keccak(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        false,
        "basecode_keccak",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_base_rs_keccak(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksRSCodeKeccak>(
        c,
        true,
        "rs_keccak",
    );
}

fn bench_batch_vlop_commit_open_verify_goldilocks_base_basecode_keccak(c: &mut Criterion) {
    bench_batch_vlop_commit_open_verify_goldilocks::<PcsGoldilocksBasecodeKeccak>(
        c,
        true,
        "basecode_keccak",
    );
}

criterion_group! {
  name = bench_basefold;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets =
  bench_simple_batch_commit_open_verify_goldilocks_base_rs_keccak, bench_simple_batch_commit_open_verify_goldilocks_ext_rs_keccak,
  bench_batch_vlop_commit_open_verify_goldilocks_base_rs_keccak, bench_batch_vlop_commit_open_verify_goldilocks_ext_rs_keccak,
  bench_batch_vlmp_commit_open_verify_goldilocks_base_rs_keccak, bench_batch_vlmp_commit_open_verify_goldilocks_ext_rs_keccak, bench_commit_open_verify_goldilocks_base_rs_keccak, bench_commit_open_verify_goldilocks_ext_rs_keccak,bench_batch_vlop_commit_open_verify_goldilocks_base_basecode_keccak, bench_batch_vlop_commit_open_verify_goldilocks_ext_basecode_keccak,
  bench_simple_batch_commit_open_verify_goldilocks_base_basecode_keccak, bench_simple_batch_commit_open_verify_goldilocks_ext_basecode_keccak, bench_batch_vlmp_commit_open_verify_goldilocks_base_basecode_keccak, bench_batch_vlmp_commit_open_verify_goldilocks_ext_basecode_keccak, bench_commit_open_verify_goldilocks_base_basecode_keccak, bench_commit_open_verify_goldilocks_ext_basecode_keccak,

  bench_simple_batch_commit_open_verify_goldilocks_base_rs, bench_simple_batch_commit_open_verify_goldilocks_ext_rs,
  bench_batch_vlop_commit_open_verify_goldilocks_base_rs, bench_batch_vlop_commit_open_verify_goldilocks_ext_rs,
  bench_batch_vlmp_commit_open_verify_goldilocks_base_rs, bench_batch_vlmp_commit_open_verify_goldilocks_ext_rs, bench_commit_open_verify_goldilocks_base_rs, bench_commit_open_verify_goldilocks_ext_rs,bench_batch_vlop_commit_open_verify_goldilocks_base_basecode, bench_batch_vlop_commit_open_verify_goldilocks_ext_basecode,
  bench_simple_batch_commit_open_verify_goldilocks_base_basecode, bench_simple_batch_commit_open_verify_goldilocks_ext_basecode, bench_batch_vlmp_commit_open_verify_goldilocks_base_basecode, bench_batch_vlmp_commit_open_verify_goldilocks_ext_basecode, bench_commit_open_verify_goldilocks_base_basecode, bench_commit_open_verify_goldilocks_ext_basecode,
}

criterion_main!(bench_basefold);
