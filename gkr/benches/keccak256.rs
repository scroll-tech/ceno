#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::time::Duration;

use criterion::*;

use gkr::gadgets::keccak256::{keccak256_circuit, prove_keccak256, verify_keccak256};
use goldilocks::GoldilocksExt2;

// cargo bench --bench keccak256 --features parallel --features flamegraph --package gkr -- --profile-time <secs>
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
      name = keccak256;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
      targets = bench_keccak256
    }
  } else {
    criterion_group! {
      name = keccak256;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000));
      targets = bench_keccak256
    }
  }
}

criterion_main!(keccak256);

const NUM_SAMPLES: usize = 10;

fn bench_keccak256(c: &mut Criterion) {
    println!(
        "#layers: {}",
        keccak256_circuit::<GoldilocksExt2>().layers.len()
    );

    let circuit = keccak256_circuit::<GoldilocksExt2>();

    let Some((proof, output_mle)) = prove_keccak256::<GoldilocksExt2>(1, &circuit) else {
        return;
    };
    assert!(verify_keccak256(1, output_mle, proof, &circuit).is_ok());

    for log2_n in 1..6 {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("keccak256_log2_{}", log2_n));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_keccak256", format!("keccak256_log2_{}", log2_n)),
            |b| {
                b.iter(|| {
                    assert!(prove_keccak256::<GoldilocksExt2>(log2_n, &circuit).is_some());
                });
            },
        );

        group.finish();
    }
}
