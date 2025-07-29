use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
};
use std::{fs, path::PathBuf, rc::Rc, time::Duration};
mod alloc;
use criterion::*;
use ff_ext::GoldilocksExt2;
use gkr_iop::cpu::{CpuBackend, CpuProver};
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
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn fibonacci_witness(c: &mut Criterion) {
    let (program, platform) = setup();
    let backend: Rc<_> = CpuBackend::<E, Pcs>::default().into();

    let max_steps = usize::MAX;
    let mut group = c.benchmark_group(format!("fib_wit_max_steps_{}", max_steps));
    group.sample_size(NUM_SAMPLES);

    // retrive 1 << 20th fibonacci element >> max_steps
    let mut hints = CenoStdin::default();
    let _ = hints.write(&20);

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
                    let result = run_e2e_with_checkpoint::<E, Pcs, _, _>(
                        CpuProver::new(backend.clone()),
                        program.clone(),
                        platform.clone(),
                        &Vec::from(&hints),
                        &[],
                        max_steps,
                        Checkpoint::PrepWitnessGen,
                    );
                    let instant = std::time::Instant::now();
                    result.next_step();
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
