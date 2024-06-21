use std::time::{Duration, Instant};

use ark_std::test_rng;
use const_env::from_env;
use criterion::*;

use ff_ext::ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::LayerWitness;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;

use singer::{
    instructions::{add::AddInstruction, Instruction, InstructionGraph, SingerCircuitBuilder},
    scheme::GKRGraphProverState,
    CircuitWiresIn, SingerGraphBuilder, SingerParams,
};
use singer_utils::structs::ChipChallenges;
use transcript::Transcript;

fn main() {
    let max_thread_id = 1;
    let instance_num_vars = 9;
    type E = GoldilocksExt2;
    let chip_challenges = ChipChallenges::default();
    let circuit_builder =
        SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
    let mut singer_builder = SingerGraphBuilder::<E>::new();

    let mut rng = test_rng();
    let size = AddInstruction::phase0_size();
    let phase0: CircuitWiresIn<<GoldilocksExt2 as ff_ext::ExtensionField>::BaseField> =
        vec![LayerWitness {
            instances: (0..(1 << instance_num_vars))
                .map(|_| {
                    (0..size)
                        .map(|_| <GoldilocksExt2 as ExtensionField>::BaseField::random(&mut rng))
                        .collect_vec()
                })
                .collect_vec(),
        }];

    let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

    let timer = Instant::now();

    let _ = AddInstruction::construct_graph_and_witness(
        &mut singer_builder.graph_builder,
        &mut singer_builder.chip_builder,
        &circuit_builder.insts_circuits[<AddInstruction as Instruction<E>>::OPCODE as usize],
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

    let mut prover_transcript = &mut Transcript::new(b"Singer");

    let timer = Instant::now();
    let _ = GKRGraphProverState::prove(
        &graph,
        &wit,
        &target_evals,
        &mut prover_transcript,
        (1 << instance_num_vars).min(max_thread_id),
    )
    .expect("prove failed");
    println!(
        "AddInstruction::prove, instance_num_vars = {}, time = {}",
        instance_num_vars,
        timer.elapsed().as_secs_f64()
    );
}
