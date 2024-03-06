use gkr_graph::structs::NodeOutputType;
use itertools::Itertools;

use crate::component::ToSuccInst;

use super::BasicBlockInfo;

pub(super) struct BasicBlockStack {
    pub(super) stack: Vec<NodeOutputType>,
    pub(super) info: BasicBlockInfo,
}

impl BasicBlockStack {
    pub(super) fn initialize(
        info: BasicBlockInfo,
        bb_start_node_id: usize,
        bb_to_succ: &ToSuccInst,
    ) -> Self {
        let mut stack =
            vec![NodeOutputType::OutputLayer(0); -info.bb_start_stack_top_offsets[0] as usize];
        let stack_top = stack.len() as i64;
        bb_to_succ
            .stack_result_ids
            .iter()
            .zip(info.bb_start_stack_top_offsets.iter().rev())
            .for_each(|(&wire_id, &offset)| {
                stack[(stack_top + offset) as usize] =
                    NodeOutputType::WireOut(bb_start_node_id, wire_id);
            });
        Self { stack, info }
    }

    pub(super) fn finalize(self) -> Vec<NodeOutputType> {
        let stack_top = self.stack.len() as i64;
        self.info
            .bb_final_stack_top_offsets
            .iter()
            .rev()
            .map(|&offset| self.stack[(stack_top + offset) as usize])
            .collect()
    }

    pub(super) fn pop_node_outputs(&mut self, mode: StackOpMode) -> Vec<NodeOutputType> {
        match mode {
            StackOpMode::PopPush(n, _) => (0..n).map(|_| self.stack.pop().unwrap()).collect_vec(),
            StackOpMode::Swap(n) => {
                vec![
                    self.stack[self.stack.len() - 1],
                    self.stack[self.stack.len() - n - 1],
                ]
            }
            StackOpMode::Dup(n) => {
                vec![self.stack[self.stack.len() - n]]
            }
        }
    }

    pub(super) fn push_node_outputs(&mut self, curr: Vec<NodeOutputType>, mode: StackOpMode) {
        let stack_top = self.stack.len();
        match mode {
            StackOpMode::PopPush(_, n) => {
                assert_eq!(curr.len(), n);
                curr.into_iter().for_each(|pred| {
                    self.stack.push(pred);
                });
            }
            StackOpMode::Swap(n) => {
                assert_eq!(curr.len(), 2);
                self.stack.swap(stack_top - 1, stack_top - n - 1);
            }
            StackOpMode::Dup(n) => {
                assert_eq!(curr.len(), 2);
                self.stack[stack_top - n] = curr[1];
                self.stack.push(curr[0]);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum StackOpMode {
    PopPush(usize, usize),
    Swap(usize),
    Dup(usize),
}

// implement From from u8
impl From<u8> for StackOpMode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0x01 => Self::PopPush(2, 1), // ADD
            0x11 => Self::PopPush(2, 1), // GT
            0x35 => Self::PopPush(1, 1), // CALLDATALOAD
            0x50 => Self::PopPush(1, 0), // POP
            0x52 => Self::PopPush(2, 0), // MSTORE
            0x56 => Self::PopPush(1, 0), // JUMP
            0x57 => Self::PopPush(2, 0), // JUMPI
            0x80 => Self::Dup(1),        // DUP1
            0x81 => Self::Dup(2),        // DUP2
            0x91 => Self::Swap(2),       // SWAP2
            0x93 => Self::Swap(4),       // SWAP4
            0xF3 => Self::PopPush(2, 0), // RETURN
            _ => unimplemented!(),
        }
    }
}

pub(crate) fn lower_bound(sorted_vec: &[i64], target: i64) -> usize {
    match sorted_vec.binary_search(&target) {
        Ok(index) => index,
        Err(index) => index,
    }
}
