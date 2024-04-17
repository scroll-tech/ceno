use std::sync::Arc;

use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    chip_handler::{ROMOperations, RangeChipOperations},
    constants::RANGE_CHIP_BIT_WIDTH,
    error::UtilError,
    structs::{ChipChallenges, ROMHandler},
};

fn construct_circuit<F: SmallField>(challenges: &ChipChallenges) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let cells = circuit_builder.create_counter_in(0);

    let mut rom_handler = ROMHandler::new(&challenges);
    rom_handler.range_check_table_item(&mut circuit_builder, cells[0]);
    let _ = rom_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add range table circuit and witness to the circuit graph. Return node id and
/// lookup instance log size.
pub(crate) fn construct_range_table_and_witness<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bit_with: usize,
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, usize), UtilError> {
    let range_circuit = construct_circuit(challenges);

    let table_node_id = builder.add_node_with_witness(
        "range table circuit",
        &range_circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        1 << RANGE_CHIP_BIT_WIDTH,
    )?;
    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        bit_with - 1,
    ))
}

/// Add range table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_range_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bit_with: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, usize), UtilError> {
    let range_circuit = construct_circuit(challenges);

    let table_node_id = builder.add_node("range table circuit", &range_circuit, vec![])?;
    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        bit_with - 1,
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

    use crate::chips::range::construct_range_table_and_witness;
    use crate::structs::ChipChallenges;
    use gkr_graph::structs::{CircuitGraphBuilder, IOPProverState};

    fn bench_construct_range_table_and_witness_helper<F: SmallField>(bit_width: usize) {
        let chip_challenges = ChipChallenges::default();
        let mut circuit_graph_builder = CircuitGraphBuilder::<F>::new();

        let mut rng = test_rng();

        let real_challenges = vec![F::random(&mut rng), F::random(&mut rng)];

        let timer = Instant::now();

        let _ = construct_range_table_and_witness(
            &mut circuit_graph_builder,
            bit_width,
            &chip_challenges,
            &real_challenges,
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = circuit_graph_builder.finalize_graph_and_witness();

        println!(
            "range::construct_range_table_and_witness, bit_width = {}, time = {}",
            bit_width,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![F::random(&mut rng), F::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = IOPProverState::<F>::prove(&graph, &wit, &target_evals, &mut prover_transcript)
            .expect("prove failed");
        println!(
            "range::prove, bit_width = {}, time = {}",
            bit_width,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_construct_range_table_and_witness() {
        bench_construct_range_table_and_witness_helper::<GoldilocksExt2>(1);
    }
}
