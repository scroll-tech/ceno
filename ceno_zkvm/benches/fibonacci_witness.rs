use std::{fs, path::PathBuf, time::Duration};

use ceno_emul::{CENO_PLATFORM, Platform, Program, WORD_SIZE};
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, run_e2e_with_checkpoint},
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
fn setup() -> (Program, Platform, u32, u32) {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("examples/fibonacci.elf");
    let stack_size = 32768;
    let heap_size = 2097152;
    let elf_bytes = fs::read(&file_path).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();

    let platform = Platform {
        // The stack section is not mentioned in ELF headers, so we repeat the constant STACK_TOP here.
        stack_top: 0x0020_0400,
        rom: program.base_address
            ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
        ram: 0x0010_0000..0xFFFF_0000,
        unsafe_ecall_nop: true,
        ..CENO_PLATFORM
    };

    (program, platform, stack_size, heap_size)
}

fn fibonacci_witness(c: &mut Criterion) {
    let (program, platform, stack_size, heap_size) = setup();

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
                        stack_size,
                        heap_size,
                        vec![],
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
