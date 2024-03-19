use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use itertools::izip;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{BytecodeChipOperations, ROMOperations},
    chips::IntoEnumIterator,
    constants::OpcodeType,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, PCUInt, ROMHandler, StackUInt, TSUInt},
};
use std::sync::Arc;

use crate::{
    component::{FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst},
    error::ZKVMError,
    utils::add_assign_each_cell,
};

use super::{Instruction, InstructionGraph};

pub struct JumpiInstruction;

impl<F: SmallField> InstructionGraph<F> for JumpiInstruction {
    type InstType = Self;
}

register_witness!(
    JumpiInstruction,
    phase0 {
        pc_plus_1 => PCUInt::N_OPRAND_CELLS,
        pc_plus_1_opcode => 1,
        cond_values_inv => StackUInt::N_OPRAND_CELLS,
        cond_non_zero_or_inv => 1
    }
);

impl<F: SmallField> Instruction<F> for JumpiInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let (dest_id, dest) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);
        let (cond_values_id, cond_values) =
            circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);

        let mut rom_handler = ROMHandler::new(&challenges);

        // Execution, cond_values_non_zero[i] = [cond_values[i] != 0]
        let cond_values_inv = &phase0[Self::phase0_cond_values_inv()];
        let mut cond_values_non_zero = Vec::new();
        for (val, wit) in izip!(cond_values, cond_values_inv) {
            cond_values_non_zero.push(rom_handler.non_zero(&mut circuit_builder, val, *wit)?);
        }
        // cond_non_zero = [summation of cond_values_non_zero[i] != 0]
        let non_zero_or = circuit_builder.create_cell();
        cond_values_non_zero
            .iter()
            .for_each(|x| circuit_builder.add(non_zero_or, *x, F::BaseField::ONE));
        let cond_non_zero_or_inv = phase0[Self::phase0_cond_non_zero_or_inv().start];
        let cond_non_zero =
            rom_handler.non_zero(&mut circuit_builder, non_zero_or, cond_non_zero_or_inv)?;

        // If cond_non_zero, next_pc = dest, otherwise, pc = pc + 1
        let pc_plus_1 = &phase0[Self::phase0_pc_plus_1()];
        let (next_pc_id, next_pc) = circuit_builder.create_witness_out(PCUInt::N_OPRAND_CELLS);
        for i in 0..PCUInt::N_OPRAND_CELLS {
            circuit_builder.select(next_pc[i], pc_plus_1[i], dest[i], cond_non_zero);
        }

        // If cond_non_zero, next_opcode = JUMPDEST, otherwise, opcode = pc + 1 opcode
        let pc_plus_1_opcode = phase0[Self::phase0_pc_plus_1_opcode().start];
        let next_opcode = circuit_builder.create_cell();
        circuit_builder.sel_mixed(
            next_opcode,
            pc_plus_1_opcode.into(),
            MixedCell::Constant(F::BaseField::from(OpcodeType::JUMPDEST as u64)),
            cond_non_zero,
        );
        // Check (next_pc, next_opcode) is a valid instruction
        rom_handler.bytecode_with_pc_byte(&mut circuit_builder, &next_pc, next_opcode);

        // To successor instruction
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = None;
        to_chip_ids[InstOutChipType::RAMStore as usize] = None;
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![dest_id, cond_values_id],
                },
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: None,

                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![],
                },
                to_bb_final: Some(next_pc_id),
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}
