use std::sync::Arc;

use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    chip_handler::{BytecodeChipOperations, ROMOperations},
    error::UtilError,
    structs::{ChipChallenges, PCUInt, ROMHandler},
};

use super::ChipCircuitGadgets;

fn construct_circuit<F: SmallField>(challenges: &ChipChallenges) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPRAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let mut rom_handler = ROMHandler::new(&challenges);
    rom_handler.bytecode_with_pc_byte(&mut circuit_builder, &pc_cells, bytecode_cells[0]);
    let _ = rom_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add bytecode table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_bytecode_table_and_witness<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bytecode: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, PredType, usize), UtilError> {
    let bytecode_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(bytecode.len(), 1);

    let selector_node_id = builder.add_node_with_witness(
        "bytecode selector circuit",
        &selector.circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        bytecode.len().next_power_of_two(),
    )?;

    let wits_in = vec![
        LayerWitness {
            instances: PCUInt::counter_vector::<F::BaseField>(bytecode.len().next_power_of_two())
                .into_iter()
                .map(|x| vec![x])
                .collect_vec(),
        },
        LayerWitness {
            instances: bytecode
                .iter()
                .map(|x| vec![F::BaseField::from(*x as u64)])
                .collect_vec(),
        },
    ];

    let table_node_id = builder.add_node_with_witness(
        "bytecode table circuit",
        &bytecode_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wits_in,
        bytecode.len().next_power_of_two(),
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(bytecode.len()) - 1,
    ))
}

/// Add bytecode table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_bytecode_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bytecode_len: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, PredType, usize), UtilError> {
    let bytecode_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(bytecode_len, 1);

    let selector_node_id =
        builder.add_node("bytecode selector circuit", &selector.circuit, vec![])?;

    let table_node_id = builder.add_node(
        "bytecode table circuit",
        &bytecode_circuit,
        vec![PredType::Source; 2],
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(bytecode_len) - 1,
    ))
}

#[cfg(test)]
mod test {
    use ark_std::rand::Rng;
    use ark_std::test_rng;
    use goldilocks::{GoldilocksExt2, SmallField};
    use itertools::Itertools;
    use std::time::Instant;
    use transcript::Transcript;

    use crate::chips::bytecode::construct_bytecode_table_and_witness;
    use crate::structs::ChipChallenges;
    use gkr_graph::structs::{CircuitGraphBuilder, IOPProverState};

    fn bench_construct_bytecode_table_and_witness_helper<F: SmallField>(bytecode_size: usize) {
        let chip_challenges = ChipChallenges::default();
        let mut circuit_graph_builder = CircuitGraphBuilder::<F>::new();

        let mut rng = test_rng();
        let bytecode: Vec<u8> = (0..bytecode_size).map(|_| rng.gen()).collect_vec();

        let real_challenges = vec![F::random(&mut rng), F::random(&mut rng)];

        let timer = Instant::now();

        let _ = construct_bytecode_table_and_witness(
            &mut circuit_graph_builder,
            &bytecode,
            &chip_challenges,
            &real_challenges,
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = circuit_graph_builder.finalize_graph_and_witness();

        println!(
            "bytecode::construct_bytecode_table_and_witness, bytecode_size = {}, time = {}",
            bytecode_size,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![F::random(&mut rng), F::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = IOPProverState::<F>::prove(&graph, &wit, &target_evals, &mut prover_transcript)
            .expect("prove failed");
        println!(
            "bytecode::prove, bytecode_size = {}, time = {}",
            bytecode_size,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_construct_bytecode_table_and_witness() {
        bench_construct_bytecode_table_and_witness_helper::<GoldilocksExt2>(16);
    }
}
