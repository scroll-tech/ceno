use std::time::Duration;

use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
    scheme::{create_backend, create_prover},
};
mod alloc;
use ceno_zkvm::{
    e2e::MultiProver,
    scheme::verifier::{RiscvMemStateConfig, ZKVMVerifier},
};
use criterion::*;
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use transcript::BasicTranscript;

criterion_group! {
  name = keccak_prove_group;
  config = Criterion::default().warm_up_time(Duration::from_millis(20000));
  targets = keccak_prove,
}

criterion_main!(keccak_prove_group);

const NUM_SAMPLES: usize = 10;

type Pcs = BasefoldDefault<E>;
type E = BabyBearExt4;

// Relevant init data for keccak run
fn setup() -> (Program, Platform) {
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    let program = Program::load_elf(ceno_examples::keccak_syscall, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn keccak_prove(c: &mut Criterion) {
    let (program, platform) = setup();
    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    // retrive 1 << 20th keccak element >> max_steps
    let mut hints = CenoStdin::default();
    let _ = hints.write(&vec![1, 2, 3]);
    let max_steps = usize::MAX;
    // estimate proof size data first
    let result = run_e2e_with_checkpoint::<E, Pcs, _, _, RiscvMemStateConfig>(
        create_prover(backend.clone()),
        program.clone(),
        platform.clone(),
        MultiProver::default(),
        &Vec::from(&hints),
        &[],
        max_steps,
        Checkpoint::Complete,
        None,
    );
    let proof = result
        .proofs
        .expect("PrepSanityCheck do not provide proof")
        .remove(0);
    let vk = result.vk.expect("PrepSanityCheck do not provide verifier");

    println!("e2e proof {}", proof);
    let transcript = BasicTranscript::new(b"riscv");
    let verifier = ZKVMVerifier::<E, Pcs, RiscvMemStateConfig>::new(vk);
    assert!(
        verifier
            .verify_proof_halt(proof, transcript, true)
            .expect("verify proof return with error"),
    );
    println!();
    println!("max_steps = {}", max_steps);

    // expand more input size once runtime is acceptable
    let mut group = c.benchmark_group(format!("keccak_max_steps_{}", max_steps));
    group.sample_size(NUM_SAMPLES);

    // Benchmark the proving time
    group.bench_function(
        BenchmarkId::new("prove_keccak", format!("keccak_max_steps_{}", max_steps)),
        |b| {
            b.iter_custom(|iters| {
                let mut time = Duration::new(0, 0);
                for _ in 0..iters {
                    let result = run_e2e_with_checkpoint::<E, Pcs, _, _, RiscvMemStateConfig>(
                        create_prover(backend.clone()),
                        program.clone(),
                        platform.clone(),
                        MultiProver::default(),
                        &Vec::from(&hints),
                        &[],
                        max_steps,
                        Checkpoint::PrepE2EProving,
                        None,
                    );
                    let instant = std::time::Instant::now();
                    result.next_step();
                    let elapsed = instant.elapsed();
                    println!(
                        "Keccak::create_proof, max_steps = {}, time = {}",
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
