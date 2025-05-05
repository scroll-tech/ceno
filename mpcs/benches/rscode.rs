use std::time::Duration;

use criterion::*;

use ff_ext::GoldilocksExt2;
use mpcs::{
    self, Basefold, BasefoldRSParams, BasefoldSpec, EncodingScheme, PolynomialCommitmentScheme,
    SecurityLevel,
};

use rand::rngs::OsRng;
use witness::RowMajorMatrix;

type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;
type E = GoldilocksExt2;

const NUM_SAMPLES: usize = 10;
const NUM_VARS_START: usize = 15;
const NUM_VARS_END: usize = 20;
const BATCH_SIZE_LOG_START: usize = 3;
const BATCH_SIZE_LOG_END: usize = 5;

fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding_rscode");
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in NUM_VARS_START..=NUM_VARS_END {
        for batch_size_log in BATCH_SIZE_LOG_START..=BATCH_SIZE_LOG_END {
            let batch_size = 1 << batch_size_log;
            let (pp, _) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size, SecurityLevel::default()).unwrap();
                Pcs::trim(param, poly_size).unwrap()
            };

            group.bench_function(
                BenchmarkId::new("batch_encode", format!("{}-{}", num_vars, batch_size)),
                |b| {

                    b.iter_custom(|iters| {
                        let mut time = Duration::new(0, 0);
                        for _ in 0..iters {
                            let rmm = RowMajorMatrix::rand(&mut OsRng, 1 << num_vars, batch_size);
                            let instant = std::time::Instant::now();
                            <<BasefoldRSParams as BasefoldSpec<E>>::EncodingScheme as EncodingScheme<E,>>::encode(&pp.encoding_params, rmm).expect("encode error");
                            let elapsed = instant.elapsed();
                            time += elapsed;
                        }
                        time
                    });
                },
            );
        }
    }
}

fn bench_encoding_base(c: &mut Criterion) {
    bench_encoding(c);
}

criterion_group! {
  name = bench_basefold;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets = bench_encoding_base,
}

criterion_main!(bench_basefold);
