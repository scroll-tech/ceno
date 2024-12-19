use std::{fs, path::PathBuf, time::Duration};

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
  name = sorting;
  config = Criterion::default().warm_up_time(Duration::from_millis(200));
  targets = sorting_small
}

criterion_main!(sorting);

const NUM_SAMPLES: usize = 10;
type Pcs = BasefoldDefault<E>;
type E = GoldilocksExt2;

// Relevant init data for fibonacci run
fn setup() -> (Program, Platform, Vec<u32>) {
    // let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // file_path.push("examples/fibonacci.elf");
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    // let elf_bytes = fs::read(&file_path).expect("read elf file");

    let mut hints = CenoStdin::default();
    // let mut rng = rand::thread_rng();

    // Provide some random numbers to sort.
    _ = hints.write(&(0..10).map(|i| 1000 - i).collect::<Vec<_>>());

    let program = Program::load_elf(ceno_examples::sorting, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Sp1, &program, stack_size, heap_size, pub_io_size);
    (program, platform, (&hints).into())
}

fn sorting_small(c: &mut Criterion) {
    let (program, platform, hints) = setup();

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
            b.iter_with_setup(
                || {
                    run_e2e_with_checkpoint::<E, Pcs>(
                        program.clone(),
                        platform.clone(),
                        hints.clone(),
                        max_steps,
                        Checkpoint::PrepWitnessGen,
                    )
                },
                |(_, generate_witness)| {
                    generate_witness();
                },
            );
        },
    );

    group.finish();

    type E = GoldilocksExt2;
}
