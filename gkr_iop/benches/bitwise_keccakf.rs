use std::time::Duration;

use criterion::*;
use ff_ext::GoldilocksExt2;
use gkr_iop::precompiles::{run_keccakf, setup_keccak_bitwise_circuit};
use itertools::Itertools;
use rand::{Rng, SeedableRng};
mod alloc;
criterion_group!(benches, keccak_f_fn);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;

fn keccak_f_fn(c: &mut Criterion) {
    // Benchmark the proving time
    for log_instances in 10..12 {
        let num_instance = 1 << log_instances;
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("keccak_f_{}", num_instance));
        group.sample_size(NUM_SAMPLES);
        group.bench_function(
            BenchmarkId::new("keccak_f", format!("prove_keccek_f_{}", num_instance)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        // Use seeded rng for debugging convenience
                        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

                        let states: Vec<[u64; 25]> = (0..num_instance)
                            .map(|_| std::array::from_fn(|_| rng.gen()))
                            .collect_vec();

                        let instant = std::time::Instant::now();

                        let circuit = setup_keccak_bitwise_circuit();
                        #[allow(clippy::unit_arg)]
                        run_keccakf::<GoldilocksExt2>(circuit, black_box(states), false, false);
                        let elapsed = instant.elapsed();
                        println!(
                            "keccak_f::create_proof, instances = {}, time = {}",
                            num_instance,
                            elapsed.as_secs_f64()
                        );
                        time += elapsed;
                    }

                    time
                });
            },
        );
        group.finish();
    }
}
