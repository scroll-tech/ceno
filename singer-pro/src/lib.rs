#![feature(generic_const_exprs)]
#![feature(const_trait_impl)]

use basic_block::SingerBasicBlockBuilder;
use error::ZKVMError;
use ff_ext::ExtensionField;
use gkr::structs::LayerWitness;
use gkr_graph::structs::{
    CircuitGraph, CircuitGraphAuxInfo, CircuitGraphBuilder, CircuitGraphWitness, NodeOutputType,
};
use goldilocks::SmallField;
use instructions::SingerInstCircuitBuilder;
use itertools::Itertools;
use singer_utils::{
    chips::SingerChipBuilder,
    structs::{ChipChallenges, InstOutChipType},
};
use std::mem;

pub mod basic_block;
pub mod component;
pub mod error;
pub mod instructions;
pub mod scheme;
pub(crate) mod utils;

// Process sketch:
// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

/// Circuit graph builder for Singer pro. `output_wires_id` is indexed by
/// InstOutChipType, corresponding to the product of summation of the chip check
/// records. `public_output_size` is the wire id stores the size of public
/// output.
pub struct SingerGraphBuilder<E: ExtensionField> {
    graph_builder: CircuitGraphBuilder<E>,
    bb_builder: SingerBasicBlockBuilder<E>,
    chip_builder: SingerChipBuilder<E>,
    public_output_size: Option<NodeOutputType>,
}

impl<E: ExtensionField> SingerGraphBuilder<E> {
    pub fn new(
        inst_circuit_builder: SingerInstCircuitBuilder<E>,
        bytecode: &[Vec<u8>],
        challenges: ChipChallenges,
    ) -> Result<Self, ZKVMError> {
        Ok(Self {
            graph_builder: CircuitGraphBuilder::new(),
            bb_builder: SingerBasicBlockBuilder::new(inst_circuit_builder, bytecode, challenges)?,
            chip_builder: SingerChipBuilder::new(),
            public_output_size: None,
        })
    }

    pub fn construct_graph_and_witness(
        mut self,
        singer_wires_in: SingerWiresIn<E::BaseField>,
        program_input: &[u8],
        real_challenges: &[E],
        params: &SingerParams,
    ) -> Result<
        (
            SingerCircuit<E>,
            SingerWitness<E::BaseField>,
            SingerWiresOutID,
        ),
        ZKVMError,
    > {
        let basic_blocks = self.bb_builder.basic_block_bytecode();
        // Construct tables for lookup arguments, including bytecode, range and
        // calldata
        let pub_out_id = self.bb_builder.construct_graph_and_witness(
            &mut self.graph_builder,
            &mut self.chip_builder,
            singer_wires_in.basic_blocks,
            real_challenges,
            params,
        )?;
        if pub_out_id.is_some() {
            self.public_output_size = pub_out_id;
        }

        // Construct tables for lookup arguments, including bytecode, range and
        // calldata.
        let table_out_node_id = self.chip_builder.construct_lookup_table_graph_and_witness(
            &mut self.graph_builder,
            &basic_blocks.iter().cloned().flatten().collect_vec(),
            program_input,
            singer_wires_in.table_count_witnesses,
            &self.bb_builder.challenges,
            real_challenges,
        )?;

        let SingerGraphBuilder {
            graph_builder,
            chip_builder,
            public_output_size,
            bb_builder: _,
        } = self;

        let mut output_wires_id = chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            ram_load: mem::take(&mut output_wires_id[InstOutChipType::RAMLoad as usize]),
            ram_store: mem::take(&mut output_wires_id[InstOutChipType::RAMStore as usize]),
            rom_input: mem::take(&mut output_wires_id[InstOutChipType::ROMInput as usize]),
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
        aux_info: &SingerAuxInfo,
    ) -> Result<SingerCircuit<E>, ZKVMError> {
        // Construct tables for lookup arguments, including bytecode, range and
        // calldata
        let pub_out_id = self.bb_builder.construct_graph(
            &mut self.graph_builder,
            &mut self.chip_builder,
            &aux_info.real_n_instances,
            &aux_info.singer_params,
        )?;
        if pub_out_id.is_some() {
            self.public_output_size = pub_out_id;
        }
        let table_out_node_id = self.chip_builder.construct_lookup_table_graph(
            &mut self.graph_builder,
            aux_info.bytecode_len,
            aux_info.program_input_len,
            &self.bb_builder.challenges,
        )?;

        let SingerGraphBuilder {
            graph_builder,
            chip_builder,
            public_output_size,
            bb_builder: _,
        } = self;

        let mut output_wires_id = chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            ram_load: mem::take(&mut output_wires_id[InstOutChipType::RAMLoad as usize]),
            ram_store: mem::take(&mut output_wires_id[InstOutChipType::RAMStore as usize]),
            rom_input: mem::take(&mut output_wires_id[InstOutChipType::ROMInput as usize]),
            rom_table: table_out_node_id,

            public_output_size,
        };

        let graph = graph_builder.finalize_graph_with_targets(&singer_wire_out_id.to_vec());
        Ok(SingerCircuit(graph))
    }
}

pub struct SingerCircuit<E: ExtensionField>(CircuitGraph<E>);

pub struct SingerWitness<F: SmallField>(CircuitGraphWitness<F>);

#[derive(Clone, Copy, Debug, Default)]
pub struct SingerParams {
    pub n_public_output_bytes: usize,
    pub n_mem_initialize: usize,
    pub n_mem_finalize: usize,
    pub n_stack_finalize: usize,
}

#[derive(Clone, Debug, Default)]
pub struct SingerWiresIn<F: SmallField> {
    pub basic_blocks: Vec<BasicBlockWiresIn<F>>,
    pub table_count_witnesses: Vec<LayerWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct SingerWiresOutID {
    pub ram_load: Vec<NodeOutputType>,
    pub ram_store: Vec<NodeOutputType>,
    pub rom_input: Vec<NodeOutputType>,
    pub rom_table: Vec<NodeOutputType>,

    pub public_output_size: Option<NodeOutputType>,
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

#[derive(Clone, Debug)]
pub struct SingerWiresOutValues<F: SmallField> {
    pub ram_load: Vec<Vec<F>>,
    pub ram_store: Vec<Vec<F>>,
    pub rom_input: Vec<Vec<F>>,
    pub rom_table: Vec<Vec<F>>,

    pub public_output_size: Option<Vec<F>>,
}

pub(crate) type CircuitWitnessIn<F> = Vec<LayerWitness<F>>;

#[derive(Clone, Debug, Default)]
pub struct BasicBlockWiresIn<F: SmallField> {
    pub real_n_instance: usize,
    pub bb_start: CircuitWitnessIn<F>,
    pub opcodes: Vec<Vec<CircuitWitnessIn<F>>>,
    pub bb_final: CircuitWitnessIn<F>,
    pub bb_accs: Vec<CircuitWitnessIn<F>>,
}

#[derive(Clone, Debug, Default)]
pub struct SingerAuxInfo {
    pub graph_aux_info: CircuitGraphAuxInfo,
    pub real_n_instances: Vec<usize>,
    pub singer_params: SingerParams,
    pub bytecode_len: usize,
    pub program_input_len: usize,
    pub program_output_len: usize,
}
