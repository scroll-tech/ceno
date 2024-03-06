use paste::paste;
use std::sync::Arc;
use strum::IntoEnumIterator;

use simple_frontend::structs::CircuitBuilder;

use gkr::structs::Circuit;
use goldilocks::SmallField;

use crate::component::{ChipType, FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst};
use crate::error::ZKVMError;
use crate::utils::add_assign_each_cell;
use crate::utils::chip_handler::{CalldataChip, ChipHandler};
use crate::utils::uint::{StackUInt, TSUInt, UInt64};

use super::{ChipChallenges, Instruction, InstructionGraph};

impl<F: SmallField> InstructionGraph<F> for CalldataloadInstruction {
    type InstType = Self;
}

pub struct CalldataloadInstruction;

register_witness!(
    CalldataloadInstruction,
    phase0 {
        data => StackUInt::N_OPRAND_CELLS
    }
);

impl<F: SmallField> Instruction<F> for CalldataloadInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_wire_in(TSUInt::N_OPRAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_wire_in(UInt64::N_OPRAND_CELLS);

        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut calldata_chip_handler = ChipHandler::new(challenges.calldata());

        // CallDataLoad check (offset, data)
        let data = &phase0[Self::phase0_data()];
        calldata_chip_handler.calldataload(&mut circuit_builder, &offset, data);

        // To successor instruction
        let (data_copy_id, data_copy) = circuit_builder.create_wire_out(data.len());
        add_assign_each_cell(&mut circuit_builder, &data_copy, &data);
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_wire_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let call_data_id = calldata_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);
        to_chip_ids[ChipType::CalldataChip as usize] = Some(call_data_id);

        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![offset_id],
                },
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: None,

                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![data_copy_id],
                },
                to_bb_final: None,
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}
