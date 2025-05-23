use std::time::Duration;

use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
    scheme::{constants::MAX_NUM_VARIABLES, verifier::ZKVMVerifier},
};
mod alloc;
use criterion::*;

use ff_ext::GoldilocksExt2;
use mpcs::{BasefoldDefault, SecurityLevel};
use transcript::BasicTranscript;

criterion_group! {
  name = fibonacci_prove_group;
  config = Criterion::default().warm_up_time(Duration::from_millis(20000));
  targets = fibonacci_prove,
}

criterion_main!(fibonacci_prove_group);

const NUM_SAMPLES: usize = 10;

type Pcs = BasefoldDefault<E>;
type E = GoldilocksExt2;

// Relevant init data for fibonacci run
fn setup() -> (Program, Platform) {
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    let program = Program::load_elf(ceno_examples::fibonacci, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn fibonacci_prove(c: &mut Criterion) {
    let (program, platform) = setup();
    for max_steps in [1usize << 20, 1usize << 21, 1usize << 22] {
        // retrive 1 << 20th fibonacci element >> max_steps
        let mut hints = CenoStdin::default();
        let _ = hints.write(&20);
        // estimate proof size data first
        let result = run_e2e_with_checkpoint::<E, Pcs>(
            program.clone(),
            platform.clone(),
            &Vec::from(&hints),
            &[],
            max_steps,
            MAX_NUM_VARIABLES,
            SecurityLevel::default(),
            Checkpoint::Complete,
        );
        let proof = result.proof.expect("PrepSanityCheck do not provide proof");
        let vk = result.vk.expect("PrepSanityCheck do not provide verifier");

        println!("e2e proof {}", proof);
        let transcript = BasicTranscript::new(b"riscv");
        let verifier = ZKVMVerifier::<E, Pcs>::new(vk);
        assert!(
            verifier
                .verify_proof_halt(proof, transcript, false)
                .expect("verify proof return with error"),
        );
        println!();
        println!("max_steps = {}", max_steps);

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
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let result = run_e2e_with_checkpoint::<E, Pcs>(
                            program.clone(),
                            platform.clone(),
                            &Vec::from(&hints),
                            &[],
                            max_steps,
                            MAX_NUM_VARIABLES,
                            SecurityLevel::default(),
                            Checkpoint::PrepE2EProving,
                        );
                        let instant = std::time::Instant::now();
                        result.next_step();
                        let elapsed = instant.elapsed();
                        println!(
                            "Fibonacci::create_proof, max_steps = {}, time = {}",
                            max_steps,
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
