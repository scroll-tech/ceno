#![feature(generic_const_exprs)]

use error::ZKVMError;
use ff_ext::ExtensionField;
use gkr_graph::structs::{
    CircuitGraph, CircuitGraphAuxInfo, CircuitGraphBuilder, CircuitGraphWitness, NodeOutputType,
};
use instructions::{
    construct_inst_graph, construct_inst_graph_and_witness, InstOutputType, SingerCircuitBuilder,
};
use multilinear_extensions::{
    mle::DenseMultilinearExtension, virtual_poly_v2::ArcMultilinearExtension,
};
use singer_utils::chips::SingerChipBuilder;
use std::mem;

pub mod error;
pub mod instructions;
pub mod scheme;
#[cfg(test)]
pub mod test;
pub use utils::u64vec;
mod utils;

// Process sketch:
// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

/// Circuit graph builder for Singer. `output_wires_id` is indexed by
/// InstOutputType, corresponding to the product of summation of the chip check
/// records. `public_output_size` is the wire id stores the size of public
/// output.
pub struct SingerGraphBuilder<'a, E: ExtensionField> {
    pub graph_builder: CircuitGraphBuilder<'a, E>,
    pub chip_builder: SingerChipBuilder<E>,
    pub public_output_size: Option<NodeOutputType>,
}

impl<'a, E: ExtensionField> SingerGraphBuilder<'a, E> {
    pub fn new() -> Self {
        Self {
            graph_builder: CircuitGraphBuilder::new(),
            chip_builder: SingerChipBuilder::new(),
            public_output_size: None,
        }
    }

    pub fn construct_graph_and_witness(
        mut self,
        circuit_builder: &SingerCircuitBuilder<E>,
        singer_wires_in: SingerWiresIn<E>,
        bytecode: &[u8],
        program_input: &[u8],
        real_challenges: &[E],
        params: &SingerParams,
    ) -> Result<(SingerCircuit<E>, SingerWitness<'a, E>, SingerWiresOutID), ZKVMError> {
        // Add instruction and its extension (if any) circuits to the graph.
        for inst_wires_in in singer_wires_in.instructions.into_iter() {
            let InstWiresIn {
                opcode,
                real_n_instances,
                wires_in,
            } = inst_wires_in;
            let inst_circuits = &circuit_builder.insts_circuits[opcode as usize];
            let pub_out_id = construct_inst_graph_and_witness(
                opcode,
                &mut self.graph_builder,
                &mut self.chip_builder,
                &inst_circuits,
                wires_in,
                real_challenges,
                real_n_instances,
                params,
            )?;
            if pub_out_id.is_some() {
                self.public_output_size = pub_out_id;
            }
        }

        // Construct tables for lookup arguments, including bytecode, range and
        // calldata.
        let table_out_node_id = self.chip_builder.construct_lookup_table_graph_and_witness(
            &mut self.graph_builder,
            bytecode,
            program_input,
            singer_wires_in.table_count,
            &circuit_builder.challenges,
            real_challenges,
        )?;

        let SingerGraphBuilder {
            graph_builder,
            chip_builder,
            public_output_size,
        } = self;

        let mut output_wires_id = chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            ram_load: mem::take(&mut output_wires_id[InstOutputType::RAMLoad as usize]),
            ram_store: mem::take(&mut output_wires_id[InstOutputType::RAMStore as usize]),
            rom_input: mem::take(&mut output_wires_id[InstOutputType::ROMInput as usize]),
            rom_table: table_out_node_id,

            public_output_size,
        };

        let (graph, graph_witness) =
            graph_builder.finalize_graph_and_witness_with_targets(&singer_wire_out_id.to_vec());
        Ok((
            SingerCircuit(graph),
            SingerWitness(graph_witness),
            singer_wire_out_id,
        ))
    }

    pub fn construct_graph(
        mut self,
        circuit_builder: &SingerCircuitBuilder<E>,
        aux_info: &SingerAuxInfo,
    ) -> Result<SingerCircuit<E>, ZKVMError> {
        // Add instruction and its extension (if any) circuits to the graph.
        for (opcode, real_n_instances) in aux_info.real_n_instances.iter() {
            let inst_circuits = &circuit_builder.insts_circuits[*opcode as usize];
            let pub_out_id = construct_inst_graph(
                *opcode,
                &mut self.graph_builder,
                &mut self.chip_builder,
                &inst_circuits,
                *real_n_instances,
                &aux_info.singer_params,
            )?;
            if pub_out_id.is_some() {
                self.public_output_size = pub_out_id;
            }
        }

        // Construct tables for lookup arguments, including bytecode, range and
        // calldata.
        let table_out_node_id = self.chip_builder.construct_lookup_table_graph(
            &mut self.graph_builder,
            aux_info.bytecode_len,
            aux_info.program_input_len,
            &circuit_builder.challenges,
        )?;

        let SingerGraphBuilder {
            graph_builder,
            chip_builder,
            public_output_size,
        } = self;

        let mut output_wires_id = chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            ram_load: mem::take(&mut output_wires_id[InstOutputType::RAMLoad as usize]),
            ram_store: mem::take(&mut output_wires_id[InstOutputType::RAMStore as usize]),
            rom_input: mem::take(&mut output_wires_id[InstOutputType::ROMInput as usize]),
            rom_table: table_out_node_id,

            public_output_size: public_output_size,
        };

        let graph = graph_builder.finalize_graph_with_targets(&singer_wire_out_id.to_vec());
        Ok(SingerCircuit(graph))
    }
}

pub struct SingerCircuit<E: ExtensionField>(CircuitGraph<E>);

pub struct SingerWitness<'a, E: ExtensionField>(pub CircuitGraphWitness<'a, E>);

#[derive(Clone, Debug, Default)]
pub struct SingerWiresIn<E: ExtensionField> {
    pub instructions: Vec<InstWiresIn<E>>,
    pub table_count: Vec<DenseMultilinearExtension<E>>,
}

#[derive(Clone, Debug, Default)]
pub struct SingerParams {
    pub n_public_output_bytes: usize,
    pub n_mem_initialize: usize,
    pub n_mem_finalize: usize,
    pub n_stack_finalize: usize,
}
#[derive(Clone, Debug)]
pub struct SingerWiresOutID {
    ram_load: Vec<NodeOutputType>,
    ram_store: Vec<NodeOutputType>,
    rom_input: Vec<NodeOutputType>,
    rom_table: Vec<NodeOutputType>,

    public_output_size: Option<NodeOutputType>,
}

#[derive(Clone)]
pub struct SingerWiresOutValues<'a, E: ExtensionField> {
    ram_load: Vec<ArcMultilinearExtension<'a, E>>,
    ram_store: Vec<ArcMultilinearExtension<'a, E>>,
    rom_input: Vec<ArcMultilinearExtension<'a, E>>,
    rom_table: Vec<ArcMultilinearExtension<'a, E>>,

    public_output_size: Option<ArcMultilinearExtension<'a, E>>,
}

impl SingerWiresOutID {
    pub fn to_vec(&self) -> Vec<NodeOutputType> {
        let mut res = [
            self.ram_load.clone(),
            self.ram_store.clone(),
            self.rom_input.clone(),
        ]
        .concat();
        if let Some(public_output_size) = self.public_output_size {
            res.push(public_output_size);
        }
        res
    }
}

#[derive(Clone, Debug, Default)]
pub struct SingerAuxInfo {
    pub graph_aux_info: CircuitGraphAuxInfo,
    pub real_n_instances: Vec<(u8, usize)>,
    pub singer_params: SingerParams,
    pub bytecode_len: usize,
    pub program_input_len: usize,
    pub program_output_len: usize,
}

// Indexed by 1. wires_in id (or phase); 2. instance id || wire id.
pub type CircuitWiresIn<E> = Vec<DenseMultilinearExtension<E>>;

#[derive(Clone, Debug, Default)]
pub struct InstWiresIn<E: ExtensionField> {
    pub opcode: u8,
    pub real_n_instances: usize,
    pub wires_in: Vec<CircuitWiresIn<E>>,
}
