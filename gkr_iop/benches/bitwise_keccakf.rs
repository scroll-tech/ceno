use std::time::Duration;

use criterion::*;
use gkr_iop::precompiles::run_keccakf;
use rand::{Rng, SeedableRng};
criterion_group!(benches, keccak_f_fn);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;

fn keccak_f_fn(c: &mut Criterion) {
    // expand more input size once runtime is acceptable
    let mut group = c.benchmark_group("keccak_f".to_string());
    group.sample_size(NUM_SAMPLES);

    // Benchmark the proving time
    group.bench_function(BenchmarkId::new("keccak_f", "keccak_f"), |b| {
        b.iter_custom(|iters| {
            let mut time = Duration::new(0, 0);
            for _ in 0..iters {
                // Use seeded rng for debugging convenience
                let mut rng = rand::rngs::StdRng::seed_from_u64(42);
                let state: [u64; 25] = std::array::from_fn(|_| rng.gen());

                let instant = std::time::Instant::now();
                #[allow(clippy::unit_arg)]
                black_box(run_keccakf(state, false, false));
                let elapsed = instant.elapsed();
                time += elapsed;
            }

            time
        });
    });

    group.finish();
}
