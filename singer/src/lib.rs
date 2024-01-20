#![feature(generic_const_exprs)]

use chips::construct_chip_circuits;
use chips::ChipCircuitGadgets;
use chips::LookupChipType;
use error::ZKVMError;
use gkr::utils::ceil_log2;
use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphBuilder;
use gkr_graph::structs::CircuitGraphWitness;
use gkr_graph::structs::NodeOutputType;
use gkr_graph::structs::PredType;
use goldilocks::SmallField;
use instructions::construct_opcode_circuit;
use instructions::output_size;
use instructions::ChipChallenges;
use instructions::InstCircuit;
use instructions::InstOutputType;
use std::mem;
use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::chips::construct_table_circuits;

pub mod chips;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;

// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

#[derive(Clone, Debug)]
pub struct SingerCircuitBuilder<F: SmallField> {
    /// Opcode circuits
    opcode_circuits: [Arc<InstCircuit<F>>; 256],
    chip_circuit_gadgets: ChipCircuitGadgets<F>,

    challenges: ChipChallenges,
}

impl<F: SmallField> SingerCircuitBuilder<F> {
    pub fn new(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let mut opcode_circuits = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcode_circuits.push(Arc::new(construct_opcode_circuit(opcode, &challenges)?));
        }
        let opcode_circuits: [Arc<InstCircuit<F>>; 256] = opcode_circuits
            .try_into()
            .map_err(|_| ZKVMError::CircuitError)?;

        let chip_circuit_gadgets = ChipCircuitGadgets::new();
        Ok(Self {
            opcode_circuits,
            chip_circuit_gadgets,
            challenges,
        })
    }

    pub fn construct_gkr_graph(
        &self,
        mut singer_wires_in: SingerWiresIn<F>,
        bytecode: &[u8],
        program_input: &[u8],
        real_challenges: &[F],
    ) -> Result<(SingerCircuit<F>, SingerWitness<F>, SingerWiresOutID), ZKVMError> {
        let mut builder = CircuitGraphBuilder::new();
        let mut opcode_node_ids = Vec::new();
        let mut node_ids: Vec<Vec<NodeOutputType>> =
            Vec::with_capacity(InstOutputType::iter().count());
        let mut table_ids: Vec<NodeOutputType> = Vec::with_capacity(LookupChipType::iter().count());
        for (opcode, opcode_wires_in) in singer_wires_in.opcode_wires_in.iter_mut() {
            // Add opcodes to the graph, generate witness correspondingly.
            let inst_circuit = &self.opcode_circuits[*opcode as usize];
            let n_wires_in = inst_circuit.circuit.n_wires_in;
            let (opcode_id, instance_num_vars) = builder.add_node_with_witness(
                stringify!(OpcodeType::from(opcode)),
                &inst_circuit.circuit,
                vec![PredType::Source; n_wires_in],
                real_challenges.to_vec(),
                mem::take(opcode_wires_in),
            )?;
            opcode_node_ids.push((*opcode, opcode_id));

            // Add chip circuits to the graph, generate witness correspondingly.
            for output_type in InstOutputType::iter() {
                if let Some(output_wire_id) = inst_circuit.outputs_wire_id[output_type as usize] {
                    let size = (output_size(*opcode, output_type) / 2 << instance_num_vars)
                        .next_power_of_two();
                    let num_vars = ceil_log2(size);
                    let chip_out = construct_chip_circuits(
                        &mut builder,
                        output_type,
                        NodeOutputType::WireOut(opcode_id, output_wire_id),
                        num_vars,
                        &self.chip_circuit_gadgets,
                        real_challenges,
                    )?;

                    node_ids[output_type as usize].push(chip_out);
                }
            }
        }

        // Construct tables for lookup arguments.
        for table_type in LookupChipType::iter() {
            table_ids.push(construct_table_circuits(
                table_type,
                &mut builder,
                bytecode,
                program_input,
                &self.challenges,
                real_challenges,
                &self.chip_circuit_gadgets,
            )?);
        }

        let (graph, graph_witness) = builder.finalize();
        Ok((
            SingerCircuit(graph),
            SingerWitness(graph_witness),
            SingerWiresOutID {
                node_ids,
                table_ids,
            },
        ))
    }
}

pub struct SingerCircuit<F: SmallField>(CircuitGraph<F>);

pub struct SingerWitness<F: SmallField>(CircuitGraphWitness<F>);

// Indexed by 1. wires_in id (or phase); 2. instance id; 3. wire id.
pub(crate) type CircuitWiresIn<F> = Vec<Vec<Vec<F>>>;

pub struct SingerWiresIn<F: SmallField> {
    opcode_wires_in: Vec<(u8, CircuitWiresIn<F>)>,
}

impl<F: SmallField> SingerWiresIn<F> {
    pub fn new() -> Self {
        let mut opcode_wires_in = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcode_wires_in.push((opcode, Vec::new()));
        }
        Self { opcode_wires_in }
    }
}

pub struct SingerWiresOutID {
    /// List of output for each chip generated by the opcode circuits.
    /// 1. chip type; 2. opcode; 3. wire out id.
    node_ids: Vec<Vec<NodeOutputType>>,
    /// List of output for those lookup chips.
    table_ids: Vec<NodeOutputType>,
}
