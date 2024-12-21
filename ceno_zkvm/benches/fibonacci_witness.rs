use std::{fs, path::PathBuf, time::Duration};

use ceno_emul::{Platform, Program};
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
};
use criterion::*;

use goldilocks::GoldilocksExt2;
use mpcs::BasefoldDefault;

criterion_group! {
  name = fibonacci;
  config = Criterion::default().warm_up_time(Duration::from_millis(20000));
  targets = fibonacci_witness
}

criterion_main!(fibonacci);

const NUM_SAMPLES: usize = 10;
type Pcs = BasefoldDefault<E>;
type E = GoldilocksExt2;

// Relevant init data for fibonacci run
fn setup() -> (Program, Platform) {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("examples/fibonacci.elf");
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    let elf_bytes = fs::read(&file_path).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Sp1, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn fibonacci_witness(c: &mut Criterion) {
    let (program, platform) = setup();

    let max_steps = usize::MAX;
    let mut group = c.benchmark_group(format!("fib_wit_max_steps_{}", max_steps));
    group.sample_size(NUM_SAMPLES);

    // Benchmark the proving time
    group.bench_function(
        BenchmarkId::new(
            "fibonacci_witness",
            format!("fib_wit_max_steps_{}", max_steps),
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut time = Duration::new(0, 0);
                for _ in 0..iters {
                    let (_, generate_witness) = run_e2e_with_checkpoint::<E, Pcs>(
                        program.clone(),
                        platform.clone(),
                        vec![],
                        max_steps,
                        Checkpoint::PrepWitnessGen,
                    );
                    let instant = std::time::Instant::now();
                    generate_witness();
                    let elapsed = instant.elapsed();
                    time += elapsed;
                }
                time
            });
        },
    );

    group.finish();

    type E = GoldilocksExt2;
}
