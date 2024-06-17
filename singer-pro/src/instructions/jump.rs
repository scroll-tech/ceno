use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use simple_frontend::structs::CircuitBuilder;
use singer_utils::{
    chips::IntoEnumIterator,
    constants::OpcodeType,
    structs::{ChipChallenges, InstOutChipType, StackUInt, TSUInt},
};
use std::sync::Arc;

use super::{Instruction, InstructionGraph};
use crate::{
    component::{FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst},
    error::ZKVMError,
    utils::add_assign_each_cell,
};

pub struct JumpInstruction;

impl<E: ExtensionField> InstructionGraph<E> for JumpInstruction {
    type InstType = Self;
}

impl<E: ExtensionField> Instruction<E> for JumpInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMP;
    const NAME: &'static str = "JUMP";
    fn construct_circuit(_: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let (next_pc_id, next_pc) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);

        // To BB final
        let (next_pc_copy_id, next_pc_copy) = circuit_builder.create_witness_out(next_pc.len());
        add_assign_each_cell(&mut circuit_builder, &next_pc_copy, &next_pc);

        // To Succesor instruction
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPERAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let to_chip_ids = vec![None; InstOutChipType::iter().count()];
        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![next_pc_id],
                },
                from_witness: FromWitness { phase_ids: vec![] },
                from_public_io: None,
                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![],
                },
                to_bb_final: Some(next_pc_copy_id),
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}
