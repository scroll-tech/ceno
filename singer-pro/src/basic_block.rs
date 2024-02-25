use std::{collections::HashSet, mem};

use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use singer_utils::{chips::SingerChipBuilder, constants::OpcodeType, structs::ChipChallenges};

use crate::{
    basic_block::bb_ret::{BBReturnRestMemLoad, BBReturnRestMemStore},
    component::{AccessoryCircuit, BBFinalCircuit, BBStartCircuit},
    error::ZKVMError,
    instructions::{
        construct_inst_graph, construct_inst_graph_and_witness, SingerInstCircuitBuilder,
    },
    BasicBlockWiresIn, SingerParams,
};

use self::{
    bb_final::BasicBlockFinal,
    bb_ret::{BBReturnRestStackPop, BasicBlockReturn},
    bb_start::BasicBlockStart,
    utils::{lower_bound, BasicBlockStack, StackOpMode},
};

// basic block
pub mod bb_final;
pub mod bb_ret;
pub mod bb_start;
pub mod utils;

pub struct SingerBasicBlockBuilder<F: SmallField> {
    inst_builder: SingerInstCircuitBuilder<F>,
    basic_blocks: Vec<BasicBlock<F>>,
    pub(crate) challenges: ChipChallenges,
}

impl<F: SmallField> SingerBasicBlockBuilder<F> {
    pub fn new(
        inst_builder: SingerInstCircuitBuilder<F>,
        bytecode: &[Vec<u8>],
        challenges: ChipChallenges,
    ) -> Result<Self, ZKVMError> {
        let mut basic_blocks = Vec::new();
        let mut pc_start = 0;
        for b in bytecode {
            let len = b.len();
            basic_blocks.push(BasicBlock::new(b, pc_start, challenges)?);
            pc_start += len as u64;
        }
        Ok(SingerBasicBlockBuilder {
            basic_blocks,
            inst_builder,
            challenges,
        })
    }

    pub fn construct_graph_and_witness(
        &self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        mut bbs_wires_in: Vec<BasicBlockWiresIn<F::BaseField>>,
        real_challenges: &[F],
        params: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let mut pub_out_id = None;
        for (bb, bb_wires_in) in self.basic_blocks.iter().zip(bbs_wires_in.iter_mut()) {
            let bb_pub_out_id = bb.construct_graph_and_witness(
                graph_builder,
                chip_builder,
                &self.inst_builder,
                mem::take(bb_wires_in),
                real_challenges,
                params,
            )?;
            if bb_pub_out_id.is_some() {
                pub_out_id = bb_pub_out_id;
            }
        }
        Ok(pub_out_id)
    }

    pub fn construct_graph(
        &self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        real_n_instances: &[usize],
        params: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let mut pub_out_id = None;
        for (bb, real_n_instances) in izip!(self.basic_blocks.iter(), real_n_instances.iter()) {
            let bb_pub_out_id = bb.construct_graph(
                graph_builder,
                chip_builder,
                &self.inst_builder,
                *real_n_instances,
                params,
            )?;
            if bb_pub_out_id.is_some() {
                pub_out_id = bb_pub_out_id;
            }
        }
        Ok(pub_out_id)
    }

    pub(crate) fn basic_block_bytecode(&self) -> Vec<Vec<u8>> {
        self.basic_blocks
            .iter()
            .map(|bb| bb.bytecode.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BasicBlockInfo {
    pub(crate) pc_start: u64,
    pub(crate) bb_start_stack_top_offsets: Vec<i64>,
    pub(crate) bb_final_stack_top_offsets: Vec<i64>,
    pub(crate) delta_stack_top: i64,
}

#[derive(Clone, Debug)]
pub struct BasicBlock<F: SmallField> {
    pub bytecode: Vec<u8>,
    pub info: BasicBlockInfo,

    bb_start_circuit: BBStartCircuit<F>,
    bb_final_circuit: BBFinalCircuit<F>,
    bb_acc_circuits: Vec<AccessoryCircuit<F>>,
}

impl<F: SmallField> BasicBlock<F> {
    pub(crate) fn new(
        bytecode: &[u8],
        pc_start: u64,
        challenges: ChipChallenges,
    ) -> Result<Self, ZKVMError> {
        let mut stack_top = 0 as i64;
        let mut pc = pc_start;
        let mut stack_offsets = HashSet::new();

        while pc < bytecode.len() as u64 {
            let opcode = bytecode[pc as usize];
            match StackOpMode::from(opcode) {
                StackOpMode::PopPush(a, b) => {
                    let a = a as i64;
                    let b = b as i64;
                    stack_offsets.extend((stack_top - a..stack_top).collect_vec());
                    stack_offsets.extend((stack_top - a..stack_top - a + b).collect_vec());
                    stack_top = stack_top - a + b;
                    pc += 1;
                }
                StackOpMode::Swap(n) => {
                    let n = n as i64;
                    stack_offsets.extend([stack_top - n - 1, stack_top - 1]);
                    pc += 1;
                }
                StackOpMode::Dup(n) => {
                    let n = n as i64;
                    stack_offsets.extend([stack_top - n, stack_top]);
                    stack_top += 1;
                    pc += 1;
                }
            }
            if opcode == OpcodeType::RETURN as u8 {
                break;
            }
        }

        let mut stack_offsets = stack_offsets.into_iter().collect_vec();
        stack_offsets.sort();

        let bb_start_stack_top_offsets = stack_offsets[0..=lower_bound(&stack_offsets, 0)].to_vec();
        let bb_final_stack_top_offsets =
            stack_offsets[0..=lower_bound(&stack_offsets, stack_top)].to_vec();

        let info = BasicBlockInfo {
            pc_start,
            bb_start_stack_top_offsets,
            bb_final_stack_top_offsets,
            delta_stack_top: stack_top,
        };

        let bb_start_circuit = BasicBlockStart::construct_circuit(&info, challenges)?;
        let (bb_final_circuit, bb_acc_circuits) =
            if bytecode.last() == Some(&(OpcodeType::RETURN as u8)) {
                (
                    BasicBlockReturn::construct_circuit(&info, challenges)?,
                    vec![
                        BBReturnRestMemLoad::construct_circuit(challenges)?,
                        BBReturnRestMemStore::construct_circuit(challenges)?,
                        BBReturnRestStackPop::construct_circuit(challenges)?,
                    ],
                )
            } else {
                (
                    BasicBlockFinal::construct_circuit(&info, challenges)?,
                    vec![],
                )
            };

        Ok(BasicBlock {
            bytecode: bytecode.to_vec(),
            info,
            bb_start_circuit,
            bb_final_circuit,
            bb_acc_circuits,
        })
    }

    /// Construct the graph and witness for the basic block. Return the
    /// `NodeOutputType` of the public output size, which is generated by Return
    /// instruction.
    pub(crate) fn construct_graph_and_witness(
        &self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_builder: &SingerInstCircuitBuilder<F>,
        mut bb_wires_in: BasicBlockWiresIn<F::BaseField>,
        real_challenges: &[F],
        params: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let bb_start_circuit = &self.bb_start_circuit;
        let bb_final_circuit = &self.bb_final_circuit;
        let bb_acc_circuits = &self.bb_acc_circuits;
        let real_n_instances = bb_wires_in.real_n_instance;

        let bb_start_node_id = graph_builder.add_node_with_witness(
            "BB start",
            &bb_start_circuit.circuit,
            vec![PredType::Source; bb_start_circuit.circuit.n_witness_in],
            real_challenges.to_vec(),
            mem::take(&mut bb_wires_in.bb_start),
            real_n_instances,
        )?;

        // The instances wire in values are padded to the power of two, but we
        // need the real number of instances here.
        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            bb_start_node_id,
            &bb_start_circuit.layout.to_chip_ids,
            real_challenges,
            real_n_instances,
        )?;

        let mut to_succ = &bb_start_circuit.layout.to_succ_inst;
        let mut local_stack =
            BasicBlockStack::initialize(self.info.clone(), bb_start_node_id, to_succ);
        let mut pred_node_id = bb_start_node_id;

        // The return instruction will return the size of the public output. We
        // should leak this to the verifier.
        let mut public_output_size = None;

        for (&opcode, opcode_wires_in) in self.bytecode.iter().zip(bb_wires_in.opcodes.iter_mut()) {
            let (inst_circuit, acc_circuits) = &inst_builder.insts_circuits.get(&opcode).unwrap();
            let opcode_wires_in = mem::take(opcode_wires_in);

            let mode = StackOpMode::from(opcode);
            let stack = local_stack.pop_node_outputs(mode);
            let memory_ts = NodeOutputType::WireOut(pred_node_id, to_succ.next_memory_ts_id);
            let preds = inst_circuit.layout.input(
                inst_circuit.circuit.n_witness_in,
                opcode,
                stack,
                memory_ts,
            );
            let (node_id, stack, po) = construct_inst_graph_and_witness(
                opcode,
                graph_builder,
                chip_builder,
                inst_circuit,
                acc_circuits,
                preds,
                opcode_wires_in,
                real_challenges,
                real_n_instances,
                params,
            )?;
            if po.is_some() {
                public_output_size = po;
            }
            pred_node_id = node_id[0];
            to_succ = &inst_circuit.layout.to_succ_inst;
            local_stack.push_node_outputs(stack, mode);
        }

        let stack = local_stack.finalize();
        let stack_ts = NodeOutputType::WireOut(
            bb_start_node_id,
            bb_start_circuit.layout.to_bb_final.stack_ts_id,
        );
        let memory_ts = NodeOutputType::WireOut(pred_node_id, to_succ.next_memory_ts_id);
        let stack_top = NodeOutputType::WireOut(
            bb_start_node_id,
            bb_start_circuit.layout.to_bb_final.stack_top_id,
        );
        let clk =
            NodeOutputType::WireOut(bb_start_node_id, bb_start_circuit.layout.to_bb_final.clk_id);
        let preds = bb_final_circuit.layout.input(
            bb_final_circuit.circuit.n_witness_in,
            stack,
            stack_ts,
            memory_ts,
            stack_top,
            clk,
        );
        let bb_final_node_id = graph_builder.add_node_with_witness(
            "BB final",
            &bb_final_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut bb_wires_in.bb_final),
            real_n_instances,
        )?;
        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            bb_final_node_id,
            &bb_final_circuit.layout.to_chip_ids,
            real_challenges,
            real_n_instances,
        )?;

        let real_n_instances_bb_accs = vec![
            params.n_mem_finalize,
            params.n_mem_initialize,
            params.n_stack_finalize,
        ];
        for ((acc, acc_wires_in), real_n_instances) in bb_acc_circuits
            .iter()
            .zip(bb_wires_in.bb_accs.iter_mut())
            .zip(real_n_instances_bb_accs)
        {
            let acc_node_id = graph_builder.add_node_with_witness(
                "BB acc",
                &acc.circuit,
                vec![PredType::Source; acc.circuit.n_witness_in],
                real_challenges.to_vec(),
                mem::take(acc_wires_in),
                real_n_instances,
            )?;
            chip_builder.construct_chip_check_graph_and_witness(
                graph_builder,
                acc_node_id,
                &acc.layout.to_chip_ids,
                real_challenges,
                real_n_instances,
            )?;
        }
        Ok(public_output_size)
    }

    pub(crate) fn construct_graph(
        &self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_builder: &SingerInstCircuitBuilder<F>,
        real_n_instances: usize,
        params: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let bb_start_circuit = &self.bb_start_circuit;
        let bb_final_circuit = &self.bb_final_circuit;
        let bb_acc_circuits = &self.bb_acc_circuits;

        let bb_start_node_id = graph_builder.add_node(
            "BB start",
            &bb_start_circuit.circuit,
            vec![PredType::Source; bb_start_circuit.circuit.n_witness_in],
        )?;

        // The instances wire in values are padded to the power of two, but we
        // need the real number of instances here.
        chip_builder.construct_chip_check_graph(
            graph_builder,
            bb_start_node_id,
            &bb_start_circuit.layout.to_chip_ids,
            real_n_instances,
        )?;

        let mut to_succ = &bb_start_circuit.layout.to_succ_inst;
        let mut local_stack =
            BasicBlockStack::initialize(self.info.clone(), bb_start_node_id, to_succ);
        let mut pred_node_id = bb_start_node_id;

        // The return instruction will return the size of the public output. We
        // should leak this to the verifier.
        let mut public_output_size = None;

        for opcode in self.bytecode.iter() {
            let (inst_circuit, acc_circuits) = &inst_builder.insts_circuits.get(&opcode).unwrap();

            let mode = StackOpMode::from(*opcode);
            let stack = local_stack.pop_node_outputs(mode);
            let memory_ts = NodeOutputType::WireOut(pred_node_id, to_succ.next_memory_ts_id);
            let preds = inst_circuit.layout.input(
                inst_circuit.circuit.n_witness_in,
                *opcode,
                stack,
                memory_ts,
            );
            let (node_id, stack, po) = construct_inst_graph(
                *opcode,
                graph_builder,
                chip_builder,
                inst_circuit,
                acc_circuits,
                preds,
                real_n_instances,
                params,
            )?;
            if let Some(po) = po {
                public_output_size = Some(po);
            }
            pred_node_id = node_id[0];
            to_succ = &inst_circuit.layout.to_succ_inst;
            local_stack.push_node_outputs(stack, mode);
        }

        let stack = local_stack.finalize();
        let stack_ts = NodeOutputType::WireOut(
            bb_start_node_id,
            bb_start_circuit.layout.to_bb_final.stack_ts_id,
        );
        let memory_ts = NodeOutputType::WireOut(pred_node_id, to_succ.next_memory_ts_id);
        let stack_top = NodeOutputType::WireOut(
            bb_start_node_id,
            bb_start_circuit.layout.to_bb_final.stack_top_id,
        );
        let clk =
            NodeOutputType::WireOut(bb_start_node_id, bb_start_circuit.layout.to_bb_final.clk_id);
        let preds = bb_final_circuit.layout.input(
            bb_final_circuit.circuit.n_witness_in,
            stack,
            stack_ts,
            memory_ts,
            stack_top,
            clk,
        );
        let bb_final_node_id =
            graph_builder.add_node("BB final", &bb_final_circuit.circuit, preds)?;
        chip_builder.construct_chip_check_graph(
            graph_builder,
            bb_final_node_id,
            &bb_final_circuit.layout.to_chip_ids,
            real_n_instances,
        )?;

        let real_n_instances_bb_accs = vec![
            params.n_mem_finalize,
            params.n_mem_initialize,
            params.n_stack_finalize,
        ];
        for (acc, real_n_instances) in bb_acc_circuits.iter().zip(real_n_instances_bb_accs) {
            let acc_node_id = graph_builder.add_node(
                "BB acc",
                &acc.circuit,
                vec![PredType::Source; acc.circuit.n_witness_in],
            )?;
            chip_builder.construct_chip_check_graph(
                graph_builder,
                acc_node_id,
                &acc.layout.to_chip_ids,
                real_n_instances,
            )?;
        }
        Ok(public_output_size)
    }
}
