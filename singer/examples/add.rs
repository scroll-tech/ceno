use std::{collections::BTreeMap, time::Instant};

use ark_std::test_rng;
use ff_ext::{ff::Field, ExtensionField};
use gkr::structs::LayerWitness;
use gkr_graph::structs::CircuitGraphAuxInfo;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;

use simple_frontend::structs::CellId;
use singer::{
    instructions::{add::AddInstruction, Instruction, InstructionGraph, SingerCircuitBuilder},
    scheme::{GKRGraphProverState, GKRGraphVerifierState},
    u64vec, CircuitWiresIn, SingerGraphBuilder, SingerParams,
};
use singer_utils::{
    constants::RANGE_CHIP_BIT_WIDTH,
    structs::{ChipChallenges, StackUInt, TSUInt},
};
use tracing_flame::FlameLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};
use transcript::Transcript;

fn get_single_instance_values_map() -> BTreeMap<&'static str, Vec<Goldilocks>> {
    let mut phase0_values_map = BTreeMap::<&'static str, Vec<Goldilocks>>::new();
    phase0_values_map.insert(
        AddInstruction::phase0_pc_str(),
        vec![Goldilocks::from(1u64)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_stack_ts_str(),
        vec![Goldilocks::from(3u64)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_memory_ts_str(),
        vec![Goldilocks::from(1u64)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_stack_top_str(),
        vec![Goldilocks::from(100u64)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_clk_str(),
        vec![Goldilocks::from(1u64)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_pc_add_str(),
        vec![], // carry is 0, may test carry using larger values in PCUInt
    );
    phase0_values_map.insert(
        AddInstruction::phase0_stack_ts_add_str(),
        vec![
            Goldilocks::from(4u64), /* first TSUInt::N_RANGE_CHECK_CELLS = 1*(56/16) = 4
                                     * cells are range values, stack_ts + 1 = 4 */
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            // no place for carry
        ],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_old_stack_ts0_str(),
        vec![Goldilocks::from(2u64)],
    );
    let m: u64 = (1 << TSUInt::C) - 1;
    let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
    phase0_values_map.insert(
        AddInstruction::phase0_old_stack_ts_lt0_str(),
        vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64), // borrow
        ],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_old_stack_ts1_str(),
        vec![Goldilocks::from(1u64)],
    );
    let m: u64 = (1 << TSUInt::C) - 2;
    let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
    phase0_values_map.insert(
        AddInstruction::phase0_old_stack_ts_lt1_str(),
        vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64), // borrow
        ],
    );
    let m: u64 = (1 << StackUInt::C) - 1;
    phase0_values_map.insert(
        AddInstruction::phase0_addend_0_str(),
        vec![Goldilocks::from(m)],
    );
    phase0_values_map.insert(
        AddInstruction::phase0_addend_1_str(),
        vec![Goldilocks::from(1u64)],
    );
    let range_values = u64vec::<{ StackUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m + 1);
    let mut wit_phase0_instruction_add: Vec<Goldilocks> = vec![];
    for i in 0..16 {
        wit_phase0_instruction_add.push(Goldilocks::from(range_values[i]))
    }
    wit_phase0_instruction_add.push(Goldilocks::from(1u64)); // carry is [1, 0, ...]
    phase0_values_map.insert(
        AddInstruction::phase0_instruction_add_str(),
        wit_phase0_instruction_add,
    );
    phase0_values_map
}
fn main() {
    let max_thread_id = 8;
    let instance_num_vars = 11;
    type E = GoldilocksExt2;
    let chip_challenges = ChipChallenges::default();
    let circuit_builder =
        SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
    let mut singer_builder = SingerGraphBuilder::<E>::new();

    let mut rng = test_rng();
    let size = AddInstruction::phase0_size();
    let phase0_values_map = get_single_instance_values_map();
    let phase0_idx_map = AddInstruction::phase0_idxes_map();

    let mut single_witness_in = vec![<GoldilocksExt2 as ExtensionField>::BaseField::ZERO; size];

    for key in phase0_idx_map.keys() {
        let range = phase0_idx_map
            .get(key)
            .unwrap()
            .clone()
            .collect::<Vec<CellId>>();
        let values = phase0_values_map
            .get(key)
            .expect(&("unknown key ".to_owned() + key));
        for (value_idx, cell_idx) in range.into_iter().enumerate() {
            if value_idx < values.len() {
                single_witness_in[cell_idx] = values[value_idx];
            }
        }
    }

    let phase0: CircuitWiresIn<<GoldilocksExt2 as ff_ext::ExtensionField>::BaseField> =
        vec![LayerWitness {
            instances: (0..(1 << instance_num_vars))
                .map(|_| single_witness_in.clone())
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

    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();
    let subscriber = Registry::default()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .with(EnvFilter::from_default_env())
        .with(flame_layer.with_threads_collapsed(true));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let point = vec![E::random(&mut rng), E::random(&mut rng)];
    let target_evals = graph.target_evals(&wit, &point);

    for _ in 0..5 {
        let mut prover_transcript = &mut Transcript::new(b"Singer");
        let timer = Instant::now();
        let proof = GKRGraphProverState::prove(
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
        let mut verifier_transcript = Transcript::new(b"Singer");
        let _ = GKRGraphVerifierState::verify(
            &graph,
            &real_challenges,
            &target_evals,
            proof,
            &CircuitGraphAuxInfo {
                instance_num_vars: wit
                    .node_witnesses
                    .iter()
                    .map(|witness| witness.instance_num_vars())
                    .collect(),
            },
            &mut verifier_transcript,
        )
        .expect("verify failed");
    }
}
