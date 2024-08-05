use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use singer_utils::{
    chip_handler::{
        bytecode::BytecodeChip, global_state::GlobalStateChip, range::RangeChip,
        rom_handler::ROMHandler, stack::StackChip, ChipHandler,
    },
    chips::IntoEnumIterator,
    constants::OpcodeType,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};

use crate::{
    component::{FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst},
    error::ZKVMError,
    utils::add_assign_each_cell,
};

use super::{Instruction, InstructionGraph};

pub struct AddInstruction;

impl<E: ExtensionField> InstructionGraph<E> for AddInstruction {
    type InstType = Self;
}

register_witness!(
    AddInstruction,
    phase0 {
        // Witness for addend_0 + addend_1
        instruction_add => AddSubConstants::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for AddInstruction {
    const OPCODE: OpcodeType = OpcodeType::ADD;
    const NAME: &'static str = "ADD";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let (addend_0_id, addend_0) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);
        let (addend_1_id, addend_1) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);

        let mut chip_handler = ChipHandler::new(challenges.clone());

        // Execution result = addend0 + addend1, with carry.
        let addend_0 = addend_0.try_into()?;
        let addend_1 = addend_1.try_into()?;
        let result = StackUInt::add(
            &mut circuit_builder,
            &mut chip_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_instruction_add()],
        )?;
        // To successor instruction
        let stack_result_id = circuit_builder.create_witness_out_from_cells(result.values());
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPERAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let (_, _, rom_id) = chip_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![addend_0_id, addend_1_id],
                },
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: None,

                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![stack_result_id],
                },
                to_bb_final: None,
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}
