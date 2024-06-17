use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use simple_frontend::structs::WitnessId;
use singer_utils::constants::OpcodeType;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct InstCircuit<E: ExtensionField> {
    pub(crate) circuit: Arc<Circuit<E>>,
    pub(crate) layout: InstLayout,
}

pub(crate) type ToChipsWires = Vec<Option<(WitnessId, usize)>>;

#[derive(Clone, Debug, Default)]
pub struct InstLayout {
    // Input and output wires.
    pub(crate) from_witness: FromWitness,
    pub(crate) from_pred_inst: FromPredInst,
    pub(crate) from_public_io: Option<FromPublicIO>,

    pub(crate) to_succ_inst: ToSuccInst,
    pub(crate) to_chip_ids: ToChipsWires,
    pub(crate) to_bb_final: Option<WitnessId>,

    pub(crate) to_acc_ooo: Option<WitnessId>,
    pub(crate) to_acc_dup: Option<WitnessId>,
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
pub struct BBStartCircuit<E: ExtensionField> {
    pub(crate) circuit: Arc<Circuit<E>>,
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
pub struct BBFinalCircuit<E: ExtensionField> {
    pub(crate) circuit: Arc<Circuit<E>>,
    pub(crate) layout: BBFinalLayout,
}

#[derive(Clone, Debug)]
pub struct BBFinalLayout {
    pub(crate) from_witness: FromWitness,
    pub(crate) from_bb_start: FromBBStart,
    pub(crate) from_pred_inst: FromPredInst,
    pub(crate) next_pc_id: Option<WitnessId>,

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
        next_pc: Option<NodeOutputType>,
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
        // TODO: Incorrect
        if let (Some(next_pc_id), Some(next_pc)) = (self.next_pc_id.as_ref(), next_pc) {
            input[*next_pc_id as usize] = PredType::PredWire(next_pc);
        }
        input
    }
}

#[derive(Clone, Debug)]
pub struct AccessoryCircuit<E: ExtensionField> {
    pub(crate) circuit: Arc<Circuit<E>>,
    pub(crate) layout: AccessoryLayout,
}

#[derive(Clone, Debug)]
pub struct AccessoryLayout {
    pub(crate) from_witness: FromWitness,
    pub(crate) from_pred_ooo: Option<WitnessId>,
    pub(crate) from_pred_dup: Option<WitnessId>,
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
    pub(crate) phase_ids: Vec<WitnessId>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FromBBStart {
    pub(crate) stack_top_id: WitnessId,
    pub(crate) stack_ts_id: WitnessId,
    pub(crate) clk_id: WitnessId,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FromPredInst {
    pub(crate) memory_ts_id: WitnessId,
    pub(crate) stack_operand_ids: Vec<WitnessId>,
}

/// From public output. This is used in the return instruction.
#[derive(Clone, Debug, Default)]
pub(crate) struct FromPublicIO {
    pub(crate) public_output_id: WitnessId,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ToSuccInst {
    pub(crate) next_memory_ts_id: WitnessId,
    pub(crate) stack_result_ids: Vec<WitnessId>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ToBBFinal {
    pub(crate) stack_ts_id: WitnessId,
    pub(crate) stack_top_id: WitnessId,
    pub(crate) clk_id: WitnessId,
}
