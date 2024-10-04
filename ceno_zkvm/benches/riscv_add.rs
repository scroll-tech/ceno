use std::time::{Duration, Instant};

use ark_std::test_rng;
use ceno_zkvm::{
    self,
    instructions::{riscv::arith::AddInstruction, Instruction},
    scheme::prover::ZKVMProver,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces},
};
use const_env::from_env;
use criterion::*;

use ceno_zkvm::scheme::constants::MAX_NUM_VARIABLES;
use ff_ext::ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme};
use multilinear_extensions::mle::IntoMLE;
use transcript::Transcript;

cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
      name = op_add;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
      targets = bench_add
    }
  } else {
    criterion_group! {
      name = op_add;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000));
      targets = bench_add
    }
  }
}

criterion_main!(op_add);

const NUM_SAMPLES: usize = 10;
#[from_env]
const RAYON_NUM_THREADS: usize = 8;

fn bench_add(c: &mut Criterion) {
    type Pcs = BasefoldDefault<E>;
    let max_threads = {
        if !RAYON_NUM_THREADS.is_power_of_two() {
            #[cfg(not(feature = "non_pow2_rayon_thread"))]
            {
                panic!(
                    "add --features non_pow2_rayon_thread to enable unsafe feature which support non pow of 2 rayon thread pool"
                );
            }

            #[cfg(feature = "non_pow2_rayon_thread")]
            {
                use sumcheck::{local_thread_pool::create_local_pool_once, util::ceil_log2};
                let max_thread_id = 1 << ceil_log2(RAYON_NUM_THREADS);
                create_local_pool_once(1 << ceil_log2(RAYON_NUM_THREADS), true);
                max_thread_id
            }
        } else {
            RAYON_NUM_THREADS
        }
    };
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let _ = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs);

    let param = Pcs::setup(1 << MAX_NUM_VARIABLES).unwrap();
    let (pp, vp) = Pcs::trim(&param, 1 << MAX_NUM_VARIABLES).unwrap();

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, zkvm_fixed_traces)
        .expect("keygen failed");

    let circuit_pk = pk
        .circuit_pks
        .get(&AddInstruction::<E>::name())
        .unwrap()
        .clone();
    let num_witin = circuit_pk.get_cs().num_witin;

    let prover = ZKVMProver::new(pk);

    for instance_num_vars in 20..22 {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("add_op_{}", instance_num_vars));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_add", format!("prove_add_log2_{}", instance_num_vars)),
            |b| {
                b.iter_with_setup(
                    || {
                        // generate mock witness
                        let mut rng = test_rng();
                        let num_instances = 1 << instance_num_vars;
                        (0..num_witin as usize)
                            .map(|_| {
                                (0..num_instances)
                                    .map(|_| Goldilocks::random(&mut rng))
                                    .collect::<Vec<Goldilocks>>()
                                    .into_mle()
                            })
                            .collect_vec()
                    },
                    |wits_in| {
                        let timer = Instant::now();
                        let num_instances = 1 << instance_num_vars;
                        let mut transcript = Transcript::new(b"riscv");
                        let commit =
                            Pcs::batch_commit_and_write(&prover.pk.pp, &wits_in, &mut transcript)
                                .unwrap();
                        let challenges = [
                            transcript.read_challenge().elements,
                            transcript.read_challenge().elements,
                        ];

                        let _ = prover
                            .create_opcode_proof(
                                "ADD",
                                &prover.pk.pp,
                                &circuit_pk,
                                wits_in.into_iter().map(|mle| mle.into()).collect_vec(),
                                commit,
                                num_instances,
                                max_threads,
                                &mut transcript,
                                &challenges,
                            )
                            .expect("create_proof failed");
                        println!(
                            "AddInstruction::create_proof, instance_num_vars = {}, time = {}",
                            instance_num_vars,
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
