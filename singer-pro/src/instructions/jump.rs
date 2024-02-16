use std::sync::Arc;
use strum::IntoEnumIterator;

use gkr::structs::Circuit;
use goldilocks::SmallField;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    component::{
        ChipChallenges, ChipType, FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst,
    },
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        uint::{StackUInt, TSUInt},
    },
};

use super::{Instruction, InstructionGraph};

pub struct JumpInstruction;

impl<F: SmallField> InstructionGraph<F> for JumpInstruction {
    type InstType = Self;
}

impl<F: SmallField> Instruction<F> for JumpInstruction {
    fn construct_circuit(_: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_wire_in(TSUInt::N_OPRAND_CELLS);
        let (next_pc_id, next_pc) = circuit_builder.create_wire_in(StackUInt::N_OPRAND_CELLS);

        // To BB final
        let (next_pc_copy_id, next_pc_copy) = circuit_builder.create_wire_out(next_pc.len());
        add_assign_each_cell(&mut circuit_builder, &next_pc_copy, &next_pc);

        // To Succesor instruction
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_wire_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let to_chip_ids = vec![None; ChipType::iter().count()];
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
