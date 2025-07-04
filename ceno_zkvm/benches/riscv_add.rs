use std::{collections::BTreeMap, time::Duration};

use ceno_zkvm::{
    self,
    instructions::{Instruction, riscv::arith::AddInstruction},
    scheme::{hal::ProofInput, prover::ZKVMProver},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces},
};
mod alloc;
use criterion::*;

use ceno_zkvm::scheme::constants::MAX_NUM_VARIABLES;
use ff_ext::GoldilocksExt2;
use gkr_iop::cpu::{CpuBackend, CpuProver};
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme, SecurityLevel};

use rand::rngs::OsRng;
use transcript::{BasicTranscript, Transcript};
use witness::RowMajorMatrix;

cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
      name = op_add;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof2::criterion::PProfProfiler::new(100, pprof2::criterion::Output::Flamegraph(None)));
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

fn bench_add(c: &mut Criterion) {
    type Pcs = BasefoldDefault<E>;
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let _ = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs);

    let param = Pcs::setup(1 << MAX_NUM_VARIABLES, SecurityLevel::default()).unwrap();
    let (pp, vp) = Pcs::trim(param, 1 << MAX_NUM_VARIABLES).unwrap();

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, zkvm_fixed_traces)
        .expect("keygen failed");

    let backend = CpuBackend::<E, Pcs>::new();
    let device = CpuProver::new(backend);
    let prover = ZKVMProver::new(pk, device);
    let circuit_pk = prover
        .pk
        .circuit_pks
        .get(&AddInstruction::<E>::name())
        .unwrap();
    let num_witin = circuit_pk.get_cs().num_witin();

    for instance_num_vars in 20..22 {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("add_op_{}", instance_num_vars));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_add", format!("prove_add_log2_{}", instance_num_vars)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        // generate mock witness
                        let num_instances = 1 << instance_num_vars;
                        let rmms = BTreeMap::from([(
                            0,
                            RowMajorMatrix::rand(&mut OsRng, num_instances, num_witin),
                        )]);

                        let instant = std::time::Instant::now();
                        let num_instances = 1 << instance_num_vars;
                        let mut transcript = BasicTranscript::new(b"riscv");
                        let commit =
                            Pcs::batch_commit_and_write(&prover.pk.pp, rmms, &mut transcript)
                                .unwrap();
                        let polys = Pcs::get_arc_mle_witness_from_commitment(&commit);
                        let challenges = [
                            transcript.read_challenge().elements,
                            transcript.read_challenge().elements,
                        ];

                        let input = ProofInput {
                            fixed: vec![],
                            witness: polys,
                            structural_witness: vec![],
                            public_input: vec![],
                            num_instances,
                        };
                        let _ = prover
                            .create_chip_proof(
                                "ADD",
                                circuit_pk,
                                input,
                                &mut transcript,
                                &challenges,
                            )
                            .expect("create_proof failed");
                        let elapsed = instant.elapsed();
                        println!(
                            "AddInstruction::create_proof, instance_num_vars = {}, time = {}",
                            instance_num_vars,
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

    type E = GoldilocksExt2;
}
