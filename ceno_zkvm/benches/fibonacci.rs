use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use ceno_emul::{CENO_PLATFORM, Platform, Program, WORD_SIZE};
use ceno_zkvm::{
    self,
    e2e::{run_e2e_gen_witness, run_e2e_proof},
};
use criterion::*;

use goldilocks::GoldilocksExt2;
use mpcs::BasefoldDefault;

criterion_group! {
  name = fibonacci;
  config = Criterion::default().warm_up_time(Duration::from_millis(20000));
  targets = bench_e2e
}

criterion_main!(fibonacci);

const NUM_SAMPLES: usize = 10;

fn bench_e2e(c: &mut Criterion) {
    type Pcs = BasefoldDefault<E>;
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("examples/fibonacci.elf");
    let stack_size = 32768;
    let heap_size = 2097152;
    let elf_bytes = fs::read(&file_path).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();

    // use sp1 platform
    let platform = Platform {
        // The stack section is not mentioned in ELF headers, so we repeat the constant STACK_TOP here.
        stack_top: 0x0020_0400,
        rom: program.base_address
            ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
        ram: 0x0010_0000..0xFFFF_0000,
        unsafe_ecall_nop: true,
        ..CENO_PLATFORM
    };

    for max_steps in [1usize << 20, 1usize << 21, 1usize << 22] {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("fibonacci_max_steps_{}", max_steps));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new(
                "prove_fibonacci",
                format!("fibonacci_max_steps_{}", max_steps),
            ),
            |b| {
                b.iter_with_setup(
                    || {
                        run_e2e_gen_witness::<E, Pcs>(
                            program.clone(),
                            platform.clone(),
                            stack_size,
                            heap_size,
                            vec![],
                            max_steps,
                        )
                    },
                    |(prover, _, zkvm_witness, pi, _, _, _)| {
                        let timer = Instant::now();
                        let _ = run_e2e_proof(prover, zkvm_witness, pi);
                        println!(
                            "Fibonacci::create_proof, max_steps = {}, time = {}",
                            max_steps,
                            timer.elapsed().as_secs_f64()
                        );
                    },
                );
            },
        );

        group.finish();
    }

    type E = GoldilocksExt2;
}
