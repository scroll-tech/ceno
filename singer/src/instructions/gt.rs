use crate::instructions::InstCircuitLayout;
use crate::CircuitWiresIn;
use ff::Field;
use gkr::structs::{Circuit, LayerWitness};
use goldilocks::SmallField;
use revm_interpreter::Record;
use revm_primitives::U256;
use singer_utils::{
    copy_borrow_values_from_oprands, copy_carry_values_from_addends, copy_clock_from_record,
    copy_operand_from_record, copy_operand_timestamp_from_record, copy_pc_add_from_record,
    copy_pc_from_record, copy_range_values_from_u256, copy_stack_memory_ts_add_from_record,
    copy_stack_top_from_record, copy_stack_ts_add_from_record, copy_stack_ts_from_record,
    copy_stack_ts_lt_from_record,
};

use super::InstructionGraph;

use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
        RangeChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, StackUInt, TSUInt},
    uint::{UIntAddSub, UIntCmp},
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, Instruction};

pub struct GtInstruction;

impl<F: SmallField> InstructionGraph<F> for GtInstruction {
    type InstType = Self;
}

register_witness!(
    GtInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        old_stack_ts0 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt0 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        old_stack_ts1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        oprand_0 => StackUInt::N_OPRAND_CELLS,
        oprand_1 => StackUInt::N_OPRAND_CELLS,
        instruction_gt => UIntCmp::<StackUInt>::N_WITNESS_CELLS
    }
);

impl GtInstruction {
    const OPCODE: OpcodeType = OpcodeType::GT;
}

impl<F: SmallField> Instruction<F> for GtInstruction {
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

        let next_pc =
            ROMHandler::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;
        let next_stack_ts = rom_handler.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            &memory_ts,
            stack_top_expr.sub(F::BaseField::from(1)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Execution result = addend0 + addend1, with carry.
        let oprand_0 = (&phase0[Self::phase0_oprand_0()]).try_into()?;
        let oprand_1 = (&phase0[Self::phase0_oprand_1()]).try_into()?;
        let (result, _) = UIntCmp::<StackUInt>::lt(
            &mut circuit_builder,
            &mut rom_handler,
            &oprand_1,
            &oprand_0,
            &phase0[Self::phase0_instruction_gt()],
        )?;

        // Check the range of stack_top - 2 is within [0, 1 << STACK_TOP_BIT_WIDTH).
        rom_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
        )?;

        // Pop two values from stack
        let old_stack_ts0 = (&phase0[Self::phase0_old_stack_ts0()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts0,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt0()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(1)),
            old_stack_ts0.values(),
            oprand_0.values(),
        );

        let old_stack_ts1 = (&phase0[Self::phase0_old_stack_ts1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt1()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            &old_stack_ts1.values(),
            oprand_1.values(),
        );

        // Push one result to stack. Since values are little-endien, it is
        // equivalent to pad result with 0s.
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            stack_ts.values(),
            &[result],
        );

        // Bytecode check for (pc, gt)
        rom_handler.bytecode_with_pc_opcode(&mut circuit_builder, pc.values(), Self::OPCODE);

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
        copy_pc_from_record!(wire_values, record);
        copy_stack_ts_from_record!(wire_values, record);
        copy_stack_top_from_record!(wire_values, record);
        copy_clock_from_record!(wire_values, record);
        copy_pc_add_from_record!(wire_values, record);
        copy_stack_ts_add_from_record!(wire_values, record);
        copy_stack_ts_lt_from_record!(wire_values, record, 0);
        copy_stack_ts_lt_from_record!(wire_values, record, 1);
        copy_operand_from_record!(wire_values, record, phase0_oprand_0, 0);
        copy_operand_from_record!(wire_values, record, phase0_oprand_1, 1);
        copy_range_values_from_u256!(
            wire_values,
            phase0_instruction_gt,
            U256::MAX - record.operands[0] + record.operands[1] + U256::from(1)
        );
        copy_borrow_values_from_oprands!(
            wire_values,
            phase0_instruction_gt,
            record.operands[1],
            record.operands[0]
        );

        vec![LayerWitness {
            instances: vec![wire_values],
        }]
    }
}
