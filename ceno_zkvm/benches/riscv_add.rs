use std::time::Duration;

use ceno_zkvm::{
    self,
    instructions::{Instruction, riscv::arith::AddInstruction},
    scheme::{create_backend, create_prover, hal::ProofInput, prover::ZKVMProver},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces},
};
mod alloc;
use criterion::*;

use ceno_zkvm::scheme::constants::MAX_NUM_VARIABLES;
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme, SecurityLevel};

use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use rand::rngs::OsRng;
use transcript::{BasicTranscript, Transcript};
use witness::RowMajorMatrix;

#[cfg(feature = "gpu")]
use gkr_iop::gpu::{MultilinearExtensionGpu, gpu_prover::*};
#[cfg(feature = "gpu")]
use itertools::Itertools;
#[cfg(feature = "gpu")]
use std::sync::Arc;

#[cfg(feature = "flamegraph")]
criterion_group! {
    name = op_add;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof2::criterion::PProfProfiler::new(100, pprof2::criterion::Output::Flamegraph(None)));
    targets = bench_add
}

#[cfg(not(feature = "flamegraph"))]
criterion_group! {
    name = op_add;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_add
}

criterion_main!(op_add);

const NUM_SAMPLES: usize = 10;

fn bench_add(c: &mut Criterion) {
    type Pcs = BasefoldDefault<E>;
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let config = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs, &config);

    let param = Pcs::setup(1 << MAX_NUM_VARIABLES, SecurityLevel::default()).unwrap();
    let (pp, vp) = Pcs::trim(param, 1 << MAX_NUM_VARIABLES).unwrap();

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, 0, zkvm_fixed_traces)
        .expect("keygen failed");

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let prover = ZKVMProver::new_with_single_shard(pk, device);
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
                        let rmms = vec![RowMajorMatrix::rand(&mut OsRng, num_instances, num_witin)];

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

                        // TODO: better way to handle this
                        #[cfg(feature = "gpu")]
                        let cuda_hal = get_cuda_hal().unwrap();
                        #[cfg(feature = "gpu")]
                        let polys = polys
                            .iter()
                            .map(|v| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, v)))
                            .collect_vec();

                        let input = ProofInput {
                            fixed: vec![],
                            witness: polys,
                            structural_witness: vec![],
                            public_values: vec![],
                            pub_io_evals: vec![],
                            num_instances: vec![num_instances],
                            has_ecc_ops: false,
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

    type E = BabyBearExt4;
}
