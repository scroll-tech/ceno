use std::sync::Arc;

use crate::{
    chip_handler::{CalldataChipOperations, ROMOperations},
    error::UtilError,
    structs::{ChipChallenges, ROMHandler, StackUInt, UInt64},
};

use super::ChipCircuitGadgets;
use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::CircuitBuilder;

fn construct_circuit<F: SmallField>(challenges: &ChipChallenges) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, id_cells) = circuit_builder.create_witness_in(UInt64::N_OPRAND_CELLS);
    let (_, calldata_cells) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);
    let mut rom_handler = ROMHandler::new(&challenges);
    rom_handler.calldataload(&mut circuit_builder, &id_cells, &calldata_cells);
    let _ = rom_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add calldata table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_calldata_table_and_witness<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    program_input: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, PredType, usize), UtilError> {
    let calldata_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(program_input.len(), 1);

    let selector_node_id = builder.add_node_with_witness(
        "calldata selector circuit",
        &selector.circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        program_input.len().next_power_of_two(),
    )?;

    let calldata = program_input
        .iter()
        .map(|x| F::BaseField::from(*x as u64))
        .collect_vec();
    let wits_in = vec![
        LayerWitness {
            instances: (0..calldata.len())
                .map(|x| vec![F::BaseField::from(x as u64)])
                .collect_vec(),
        },
        LayerWitness {
            instances: (0..calldata.len())
                .step_by(StackUInt::N_OPRAND_CELLS)
                .map(|i| {
                    calldata[i..(i + StackUInt::N_OPRAND_CELLS).min(calldata.len())]
                        .iter()
                        .cloned()
                        .rev()
                        .collect_vec()
                })
                .collect_vec(),
        },
    ];

    let table_node_id = builder.add_node_with_witness(
        "calldata table circuit",
        &calldata_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wits_in,
        program_input.len().next_power_of_two(),
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(program_input.len()) - 1,
    ))
}

/// Add calldata table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_calldata_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    program_input_len: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, PredType, usize), UtilError> {
    let calldata_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(program_input_len, 1);

    let selector_node_id =
        builder.add_node("calldata selector circuit", &selector.circuit, vec![])?;

    let table_node_id = builder.add_node(
        "calldata table circuit",
        &calldata_circuit,
        vec![PredType::Source; 2],
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(program_input_len) - 1,
    ))
}

#[cfg(test)]
mod test {
    use ark_std::rand::Rng;
    use ark_std::test_rng;
    use gkr::structs::CircuitWitness;
    use goldilocks::{GoldilocksExt2, SmallField};
    use itertools::Itertools;
    use std::time::Instant;
    use transcript::Transcript;

    use crate::chips::calldata::{construct_calldata_table_and_witness, construct_circuit};
    use crate::structs::ChipChallenges;
    use gkr_graph::structs::{CircuitGraphBuilder, IOPProverState};

    fn test_calldata_construct_circuit_helper<F: SmallField>() {
        let challenges = ChipChallenges::default();
        let circuit = construct_circuit::<F>(&challenges);
        let n_witness_in = circuit.n_witness_in;
        let mut witness_in = vec![vec![]; n_witness_in];
        // id, UInt64::N_OPRAND_CELLS = 2 cells
        witness_in[0] = vec![F::BaseField::from(1u64), F::BaseField::from(0u64)];
        // calldata, StackUInt::N_OPRAND_CELLS = 8 cells
        witness_in[1] = vec![
            F::BaseField::from(1u64),
            F::BaseField::from(2u64),
            F::BaseField::from(3u64),
            F::BaseField::from(4u64),
            F::BaseField::from(5u64),
            F::BaseField::from(6u64),
            F::BaseField::from(7u64),
            F::BaseField::from(8u64),
        ];

        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c: u64 = 6;
        let circuit_witness_challenges = vec![F::from(c), F::from(c), F::from(c)];

        let circuit_witness = {
            let mut circuit_witness = CircuitWitness::new(&circuit, circuit_witness_challenges);
            circuit_witness.add_instance(&circuit, witness_in);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);
    }

    #[test]
    fn test_calldata_construct_circuit() {
        test_calldata_construct_circuit_helper::<GoldilocksExt2>()
    }

    fn bench_construct_calldata_table_and_witness_helper<F: SmallField>(program_input_size: usize) {
        let chip_challenges = ChipChallenges::default();
        let mut circuit_graph_builder = CircuitGraphBuilder::<F>::new();

        let mut rng = test_rng();
        let program_input: Vec<u8> = (0..program_input_size).map(|_| rng.gen()).collect_vec();

        let real_challenges = vec![F::random(&mut rng), F::random(&mut rng)];

        let timer = Instant::now();

        let _ = construct_calldata_table_and_witness(
            &mut circuit_graph_builder,
            &program_input,
            &chip_challenges,
            &real_challenges,
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = circuit_graph_builder.finalize_graph_and_witness();

        println!(
            "calldata::construct_bytecode_table_and_witness, program_input_size = {}, time = {}",
            program_input_size,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![F::random(&mut rng), F::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = IOPProverState::<F>::prove(&graph, &wit, &target_evals, &mut prover_transcript)
            .expect("prove failed");
        println!(
            "program_input::prove, program_input_size = {}, time = {}",
            program_input_size,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_construct_calldata_table_and_witness() {
        bench_construct_calldata_table_and_witness_helper::<GoldilocksExt2>(16);
    }
}
