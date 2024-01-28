use std::sync::Arc;

use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use goldilocks::SmallField;
use simple_frontend::structs::{ChallengeId, WireId};
use strum_macros::EnumIter;

use crate::constants::OpcodeType;

#[derive(Clone, Debug)]
pub struct InstCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) layout: InstLayout,
}

#[derive(Clone, Debug, Default)]
pub struct InstLayout {
    // Input and output wires.
    pub(crate) from_witness: FromWitness,
    pub(crate) from_pred_inst: FromPredInst,
    pub(crate) from_public_io: Option<FromPublicIO>,

    pub(crate) to_succ_inst: ToSuccInst,
    pub(crate) to_chip_ids: ToChipsWires,
    pub(crate) to_bb_final: Option<WireId>,

    pub(crate) to_acc_ooo: Option<WireId>,
    pub(crate) to_acc_dup: Option<WireId>,
}

impl InstLayout {
    pub fn input(
        &self,
        n_wires_in: usize,
        opcode: u8,
        stack: Vec<NodeOutputType>,
        memory_ts: NodeOutputType,
    ) -> Vec<PredType> {
        let mut input = vec![PredType::Source; n_wires_in];
        if opcode == OpcodeType::RETURN as u8 {
            self.from_pred_inst
                .stack_operand_ids
                .iter()
                .enumerate()
                .for_each(|(i, &wire_id)| {
                    input[wire_id as usize] = PredType::PredWireDup(stack[i]);
                });
            input[self.from_pred_inst.memory_ts_id as usize] = PredType::PredWireDup(memory_ts);
        } else {
            self.from_pred_inst
                .stack_operand_ids
                .iter()
                .enumerate()
                .for_each(|(i, &wire_id)| {
                    input[wire_id as usize] = PredType::PredWire(stack[i]);
                });
            input[self.from_pred_inst.memory_ts_id as usize] = PredType::PredWire(memory_ts);
        }
        input
    }
}

#[derive(Clone, Debug)]
pub struct BBStartCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) layout: BBStartLayout,
}

#[derive(Clone, Debug)]
pub struct BBStartLayout {
    pub(crate) from_witness: FromWitness,

    pub(crate) to_succ_inst: ToSuccInst,
    pub(crate) to_bb_final: ToBBFinal,
    pub(crate) to_chip_ids: ToChipsWires,
}

#[derive(Clone, Debug)]
pub struct BBFinalCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) layout: BBFinalLayout,
}

#[derive(Clone, Debug)]
pub struct BBFinalLayout {
    pub(crate) from_witness: FromWitness,
    pub(crate) from_bb_start: FromBBStart,
    pub(crate) from_pred_inst: FromPredInst,
    pub(crate) next_pc_id: Option<WireId>,

    pub(crate) to_chip_ids: ToChipsWires,
}

impl BBFinalLayout {
    pub fn input(
        &self,
        n_wires_in: usize,
        stack: Vec<NodeOutputType>,
        stack_ts: NodeOutputType,
        memory_ts: NodeOutputType,
        stack_top: NodeOutputType,
        clk: NodeOutputType,
    ) -> Vec<PredType> {
        let mut input = vec![PredType::Source; n_wires_in];
        self.from_pred_inst
            .stack_operand_ids
            .iter()
            .enumerate()
            .for_each(|(i, &wire_id)| {
                input[wire_id as usize] = PredType::PredWire(stack[i]);
            });
        input[self.from_bb_start.stack_ts_id as usize] = PredType::PredWire(stack_ts);
        input[self.from_pred_inst.memory_ts_id as usize] = PredType::PredWire(memory_ts);
        input[self.from_bb_start.stack_top_id as usize] = PredType::PredWire(stack_top);
        input[self.from_bb_start.clk_id as usize] = PredType::PredWire(clk);
        input
    }
}

#[derive(Clone, Debug)]
pub struct AccessoryCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) layout: AccessoryLayout,
}

#[derive(Clone, Debug)]
pub struct AccessoryLayout {
    pub(crate) from_witness: FromWitness,
    pub(crate) from_pred_ooo: Option<WireId>,
    pub(crate) from_pred_dup: Option<WireId>,
    pub(crate) to_chip_ids: ToChipsWires,
}

impl AccessoryLayout {
    pub fn input(
        &self,
        from_pred_ooo_id: Option<NodeOutputType>,
        from_pred_dup_id: Option<NodeOutputType>,
    ) -> Vec<PredType> {
        let n_wires_in = self.from_witness.phase_ids.len()
            + self.from_pred_ooo.map_or(0, |_| 1)
            + self.from_pred_dup.map_or(0, |_| 1);
        let mut input = vec![PredType::Source; n_wires_in];
        if let Some(wire_id) = self.from_pred_ooo {
            input[wire_id as usize] = PredType::PredWire(from_pred_ooo_id.unwrap());
        }
        if let Some(wire_id) = self.from_pred_dup {
            input[wire_id as usize] = PredType::PredWireDup(from_pred_dup_id.unwrap());
        }
        input
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FromWitness {
    pub(crate) phase_ids: Vec<WireId>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FromBBStart {
    pub(crate) stack_top_id: WireId,
    pub(crate) stack_ts_id: WireId,
    pub(crate) clk_id: WireId,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FromPredInst {
    pub(crate) memory_ts_id: WireId,
    pub(crate) stack_operand_ids: Vec<WireId>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FromPublicIO {
    pub(crate) public_output_id: WireId,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ToSuccInst {
    pub(crate) next_memory_ts_id: WireId,
    pub(crate) stack_result_ids: Vec<WireId>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ToBBFinal {
    pub(crate) stack_ts_id: WireId,
    pub(crate) stack_top_id: WireId,
    pub(crate) clk_id: WireId,
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum ChipType {
    GlobalStateIn,
    GlobalStateOut,
    BytecodeChip,
    StackPop,
    StackPush,
    RangeChip,
    MemoryLoad,
    MemoryStore,
    CalldataChip,
}

/// The wire id and the number of checks in a single instance.
pub(crate) type ToChipsWires = Vec<Option<(WireId, usize)>>;

#[derive(Clone, Copy, Debug)]
pub struct ChipChallenges {
    // Challenges for multiple-tuple chip records
    record_rlc: ChallengeId,
    // Challenges for multiple-cell values
    record_item_rlc: ChallengeId,
}

impl Default for ChipChallenges {
    fn default() -> Self {
        Self {
            record_rlc: 2,
            record_item_rlc: 1,
        }
    }
}

impl ChipChallenges {
    pub fn new(record_rlc: ChallengeId, record_item_rlc: ChallengeId) -> Self {
        Self {
            record_rlc,
            record_item_rlc,
        }
    }
    pub fn bytecode(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn stack(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn global_state(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn mem(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn range(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn calldata(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn record_item_rlc(&self) -> ChallengeId {
        self.record_item_rlc
    }
}
