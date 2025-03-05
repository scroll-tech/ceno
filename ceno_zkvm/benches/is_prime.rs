use std::time::Duration;

use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
};
use criterion::*;

use goldilocks::GoldilocksExt2;
use mpcs::BasefoldDefault;

criterion_group! {
  name = is_prime;
  config = Criterion::default().warm_up_time(Duration::from_millis(5000));
  targets = is_prime_1
}

criterion_main!(is_prime);

const NUM_SAMPLES: usize = 10;
type Pcs = BasefoldDefault<E>;
type E = GoldilocksExt2;

// Relevant init data for fibonacci run
fn setup() -> (Program, Platform) {
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    let program = Program::load_elf(ceno_examples::is_prime, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn is_prime_1(c: &mut Criterion) {
    let (program, platform) = setup();

    for n in [100u32, 10000u32, 50000u32] {
        let max_steps = usize::MAX;
        let mut hints = CenoStdin::default();
        _ = hints.write(&n);
        let hints: Vec<u32> = (&hints).into();

        let mut group = c.benchmark_group(format!("is_prime_{}", max_steps));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("is_prime", format!("is_prime_n={}", n)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);

                    for _ in 0..iters {
                        let (_, prove) = run_e2e_with_checkpoint::<E, Pcs>(
                            program.clone(),
                            platform.clone(),
                            hints.clone(),
                            max_steps,
                            Checkpoint::PrepE2EProving,
                        );
                        let instant = std::time::Instant::now();
                        prove();
                        time += instant.elapsed();
                    }
                    time
                });
            },
        );

        group.finish();
    }

    type E = GoldilocksExt2;
}
