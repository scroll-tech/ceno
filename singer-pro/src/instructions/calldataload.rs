use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use singer_utils::{
    chip_handler::{CalldataChipOperations, ROMOperations},
    chips::IntoEnumIterator,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, ROMHandler, StackUInt, TSUInt, UInt64},
};
use std::sync::Arc;

use crate::{
    component::{FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst},
    error::ZKVMError,
    utils::add_assign_each_cell,
};

use super::{Instruction, InstructionGraph};

impl<E: ExtensionField> InstructionGraph<E> for CalldataloadInstruction {
    type InstType = Self;
}

pub struct CalldataloadInstruction;

register_witness!(
    CalldataloadInstruction,
    phase0 {
        data => StackUInt::N_OPRAND_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for CalldataloadInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_witness_in(UInt64::N_OPRAND_CELLS);

        let mut rom_handler = ROMHandler::new(&challenges);

        // CallDataLoad check (offset, data)
        let data = &phase0[Self::phase0_data()];
        rom_handler.calldataload(&mut circuit_builder, &offset, data);

        // To successor instruction
        let (data_copy_id, data_copy) = circuit_builder.create_witness_out(data.len());
        add_assign_each_cell(&mut circuit_builder, &data_copy, &data);
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

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
