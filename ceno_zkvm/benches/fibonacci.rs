use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use ceno_emul::{Platform, Program};
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
};
use criterion::*;
use transcript::{BasicTranscriptWithStat, StatisticRecorder};

use goldilocks::GoldilocksExt2;
use mpcs::BasefoldDefault;

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

fn fibonacci_prove(c: &mut Criterion) {
    let (program, platform) = setup();
    for max_steps in [1usize << 20, 1usize << 21, 1usize << 22] {
        // estimate proof size data first
        let (proof, verifier) = run_e2e_with_checkpoint::<E, Pcs>(
            program.clone(),
            platform.clone(),
            vec![],
            max_steps,
            Checkpoint::PrepSanityCheck,
        )
        .0
        .expect("PrepSanityCheck do not provide proof and verifier");

        let serialize_size = bincode::serialize(&proof).unwrap().len();
        let stat_recorder = StatisticRecorder::default();
        let transcript = BasicTranscriptWithStat::new(&stat_recorder, b"riscv");
        assert!(
            verifier
                .verify_proof_halt(proof, transcript, false)
                .expect("verify proof return with error"),
        );
        println!();
        println!(
            "max_steps = {}, proof size = {}, hashes count = {}",
            max_steps,
            serialize_size,
            stat_recorder.into_inner().field_appended_num
        );

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
                        run_e2e_with_checkpoint::<E, Pcs>(
                            program.clone(),
                            platform.clone(),
                            vec![],
                            max_steps,
                            Checkpoint::PrepE2EProving,
                        )
                    },
                    |(_, run_e2e_proof)| {
                        let timer = Instant::now();

                        run_e2e_proof();
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
}
