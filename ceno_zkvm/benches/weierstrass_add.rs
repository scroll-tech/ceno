use std::time::Duration;

use ceno_zkvm::precompiles::{run_weierstrass_add, setup_weierstrass_add_circuit};
use criterion::*;
use ff_ext::BabyBearExt4;

use itertools::Itertools;
use mpcs::BasefoldDefault;
use rand::{RngCore, SeedableRng};
use sp1_curves::{
    EllipticCurve,
    weierstrass::{
        SwCurve, WeierstrassParameters, bls12_381::Bls12381, bn254::Bn254, secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    },
};
mod alloc;

criterion_group!(
    benches,
    weierstrass_add_fn_bn254,
    weierstrass_add_fn_bls12_381,
    weierstrass_add_fn_secp256k1,
    weierstrass_add_fn_secp256r1
);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;

fn weierstrass_add_fn_helper<EC: EllipticCurve>(c: &mut Criterion) {
    // Benchmark the proving time
    for log_instances in 12..14 {
        let num_instances = 1 << log_instances;
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("weierstrass_add_{}", num_instances));
        group.sample_size(NUM_SAMPLES);
        group.bench_function(
            BenchmarkId::new(
                "weierstrass_add",
                format!("prove_weierstrass_add_{}", num_instances),
            ),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        // Use seeded rng for debugging convenience
                        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

                        let states: Vec<[u64; 25]> = (0..num_instances)
                            .map(|_| std::array::from_fn(|_| rng.next_u64()))
                            .collect_vec();

                        let instant = std::time::Instant::now();

                        let circuit =
                            setup_weierstrass_add_circuit::<_, EC>().expect("setup circuit error");
                        #[allow(clippy::unit_arg)]
                        let _ = run_weierstrass_add::<
                            BabyBearExt4,
                            BasefoldDefault<BabyBearExt4>,
                            EC,
                        >(circuit, black_box(states), false, false)
                        .expect("unable to get proof");
                        let elapsed = instant.elapsed();
                        println!(
                            "weierstrass_add::create_proof, instances = {}, time = {}",
                            num_instances,
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

fn weierstrass_add_fn_bn254(c: &mut Criterion) {
    weierstrass_add_fn_helper::<Bn254>(c);
}

fn weierstrass_add_fn_bls12_381(c: &mut Criterion) {
    weierstrass_add_fn_helper::<Bls12381>(c);
}

fn weierstrass_add_fn_secp256k1(c: &mut Criterion) {
    weierstrass_add_fn_helper::<Secp256k1>(c);
}

fn weierstrass_add_fn_secp256r1(c: &mut Criterion) {
    weierstrass_add_fn_helper::<Secp256r1>(c);
}
