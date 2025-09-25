use std::time::Duration;

use ceno_zkvm::precompiles::{
    random_points, run_weierstrass_double, setup_weierstrass_double_circuit,
};
use criterion::*;
use ff_ext::BabyBearExt4;
use mpcs::BasefoldDefault;
use sp1_curves::weierstrass::{
    SwCurve, WeierstrassParameters, bls12_381::Bls12381, bn254::Bn254, secp256k1::Secp256k1,
    secp256r1::Secp256r1,
};
mod alloc;

criterion_group!(
    benches,
    weierstrass_double_fn_bn254,
    weierstrass_double_fn_bls12_381,
    weierstrass_double_fn_secp256k1,
    weierstrass_double_fn_secp256r1
);

fn real_main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
}

fn main() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32MB
        .spawn(real_main)
        .unwrap()
        .join()
        .unwrap();
}

const NUM_SAMPLES: usize = 10;

fn weierstrass_double_fn_helper<WP: WeierstrassParameters>(c: &mut Criterion) {
    // Benchmark the proving time
    for log_instances in 12..14 {
        let num_instances = 1 << log_instances;
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("weierstrass_double_{}", num_instances));
        group.sample_size(NUM_SAMPLES);
        group.bench_function(
            BenchmarkId::new(
                "weierstrass_double",
                format!("prove_weierstrass_double_{}", num_instances),
            ),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let points = random_points::<WP>(5);
                        let instant = std::time::Instant::now();

                        let circuit = setup_weierstrass_double_circuit::<_, SwCurve<WP>>()
                            .expect("setup circuit error");
                        #[allow(clippy::unit_arg)]
                        let _ = run_weierstrass_double::<
                            BabyBearExt4,
                            BasefoldDefault<BabyBearExt4>,
                            SwCurve<WP>,
                        >(circuit, black_box(points), false, false)
                        .expect("unable to get proof");
                        let elapsed = instant.elapsed();
                        println!(
                            "weierstrass_double::create_proof, instances = {}, time = {}",
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

fn weierstrass_double_fn_bn254(c: &mut Criterion) {
    weierstrass_double_fn_helper::<Bn254>(c);
}

fn weierstrass_double_fn_bls12_381(c: &mut Criterion) {
    weierstrass_double_fn_helper::<Bls12381>(c);
}

fn weierstrass_double_fn_secp256k1(c: &mut Criterion) {
    weierstrass_double_fn_helper::<Secp256k1>(c);
}

fn weierstrass_double_fn_secp256r1(c: &mut Criterion) {
    weierstrass_double_fn_helper::<Secp256r1>(c);
}
