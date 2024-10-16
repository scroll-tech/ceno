#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::time::{Duration, Instant};

use ark_std::test_rng;
use const_env::from_env;
use criterion::*;

use ff_ext::{ExtensionField, ff::Field};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;

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

use singer::{
    CircuitWiresIn, SingerGraphBuilder, SingerParams,
    instructions::{Instruction, InstructionGraph, SingerCircuitBuilder, add::AddInstruction},
    scheme::GKRGraphProverState,
};
use singer_utils::structs::ChipChallenges;
use transcript::Transcript;

fn bench_add(c: &mut Criterion) {
    let max_thread_id = {
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
    let chip_challenges = ChipChallenges::default();
    let circuit_builder =
        SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");

    for instance_num_vars in 10..14 {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("add_op_{}", instance_num_vars));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_add", format!("prove_add_log2_{}", instance_num_vars)),
            |b| {
                b.iter_with_setup(
                    || {
                        let mut rng = test_rng();
                        let singer_builder = SingerGraphBuilder::<E>::default();
                        let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];
                                (rng, singer_builder, real_challenges)
                    },
           |(mut rng,mut singer_builder, real_challenges)| {
                        let size = AddInstruction::phase0_size();
                        let phase0: CircuitWiresIn<GoldilocksExt2> = vec![(0..(1 << instance_num_vars))
                                .map(|_| {
                                    (0..size)
                                        .map(|_| {
                                            <GoldilocksExt2 as ExtensionField>::BaseField::random(
                                                &mut rng,
                                            )
                                        })
                                        .collect_vec()
                                })
                                .collect_vec().into(),
                        ];


                        let timer = Instant::now();

                        let _ = AddInstruction::construct_graph_and_witness(
                            &mut singer_builder.graph_builder,
                            &mut singer_builder.chip_builder,
                            &circuit_builder.insts_circuits
                                [<AddInstruction as Instruction<E>>::OPCODE as usize],
                            vec![phase0],
                            &real_challenges,
                            1 << instance_num_vars,
                            &SingerParams::default(),
                        )
                        .expect("gkr graph construction failed");

                        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

                        println!(
                            "AddInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
                            instance_num_vars,
                            timer.elapsed().as_secs_f64()
                        );

                        let point = vec![E::random(&mut rng), E::random(&mut rng)];
                        let target_evals = graph.target_evals(&wit, &point);

                        let prover_transcript = &mut Transcript::new(b"Singer");

                        let timer = Instant::now();
                        let _ = GKRGraphProverState::prove(
                            &graph,
                            &wit,
                            &target_evals,
                            prover_transcript,
                            (1 << instance_num_vars).min(max_thread_id),
                        )
                        .expect("prove failed");
                        println!(
                            "AddInstruction::prove, instance_num_vars = {}, time = {}",
                            instance_num_vars,
                            timer.elapsed().as_secs_f64()
                        );
                });
            },
        );

        group.finish();
    }

    type E = GoldilocksExt2;
}
