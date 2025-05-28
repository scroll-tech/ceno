use std::time::Duration;

use criterion::*;
use ff_ext::{FromUniformBytes, GoldilocksExt2};
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, build_eq_x_r_vec_sequential};
use rand::thread_rng;

criterion_group!(benches, build_eq_fn,);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;
const NV: std::ops::Range<i32> = 20..24;

fn build_eq_fn(c: &mut Criterion) {
    for nv in NV {
        let mut group = c.benchmark_group(format!("build_eq_{}", nv));
        group.sample_size(NUM_SAMPLES);

        let mut rng = thread_rng();
        let r = (0..nv)
            .map(|_| GoldilocksExt2::random(&mut rng))
            .collect::<Vec<GoldilocksExt2>>();

        group.bench_function(
            BenchmarkId::new("build_eq", format!("par_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let instant = std::time::Instant::now();
                        let _ = build_eq_x_r_vec(&r);
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }
                    time
                });
            },
        );

        group.bench_function(
            BenchmarkId::new("build_eq", format!("seq_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let instant = std::time::Instant::now();
                        let _ = build_eq_x_r_vec_sequential(&r);
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }
                    time
                });
            },
        );
        group.finish();
    }
}
