use crate::instructions::InstCircuitLayout;
use crate::{CircuitWiresIn};
use ff::Field;
use gkr::structs::{Circuit, LayerWitness};
use goldilocks::SmallField;
use revm_interpreter::Record;
use singer_utils::{
    copy_clock_from_record,
    copy_operand_timestamp_from_record, copy_stack_top_from_record, copy_stack_ts_from_record, copy_stack_ts_lt_from_record,
};

use super::InstructionGraph;
use super::{ChipChallenges, InstCircuit, Instruction};

use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::uint::u2fvec;
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
        RangeChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, TSUInt},
    uint::{UIntAddSub, UIntCmp},
};
use std::sync::Arc;

use crate::error::ZKVMError;

pub struct JumpInstruction;

impl<F: SmallField> InstructionGraph<F> for JumpInstruction {
    type InstType = Self;
}

register_witness!(
    JumpInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        next_pc => PCUInt::N_OPRAND_CELLS,

        old_stack_ts => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    }
);

impl JumpInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMP;
}

impl<F: SmallField> Instruction<F> for JumpInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        ram_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &memory_ts,
            stack_top,
            clk,
        );

        // Pop next pc from stack
        rom_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(F::BaseField::ONE))?;

        let next_pc = &phase0[Self::phase0_next_pc()];
        let old_stack_ts = (&phase0[Self::phase0_old_stack_ts()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::ONE),
            old_stack_ts.values(),
            next_pc,
        );

        ram_handler.state_out(
            &mut circuit_builder,
            &next_pc,
            stack_ts.values(), // Because there is no stack push.
            &memory_ts,
            stack_top_expr.sub(F::BaseField::from(1)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
        rom_handler.bytecode_with_pc_opcode(&mut circuit_builder, pc.values(), Self::OPCODE);
        // Bytecode check for (next_pc, jumpdest)
        rom_handler.bytecode_with_pc_opcode(&mut circuit_builder, &next_pc, OpcodeType::JUMPDEST);

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [ram_load_id, ram_store_id, rom_id];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                ..Default::default()
            },
        })
    }

    fn generate_wires_in(record: &Record) -> CircuitWiresIn<F> {
        let mut wire_values = vec![F::ZERO; Self::phase0_size()];
        copy_stack_ts_from_record!(wire_values, record);
        copy_stack_top_from_record!(wire_values, record);
        copy_clock_from_record!(wire_values, record);
        copy_stack_ts_lt_from_record!(wire_values, record);

        vec![LayerWitness {
            instances: vec![wire_values],
        }]
    }
}
