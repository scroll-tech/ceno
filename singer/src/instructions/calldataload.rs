use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, CalldataChipOperations, GlobalStateChipOperations, OAMOperations,
        ROMOperations, RangeChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, StackUInt, TSUInt, UInt64},
    uint::{UIntAddSub, UIntCmp},
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

impl<E: ExtensionField> InstructionGraph<E> for CalldataloadInstruction {
    type InstType = Self;
}

pub struct CalldataloadInstruction;

register_witness!(
    CalldataloadInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        data => StackUInt::N_OPRAND_CELLS,
        offset => UInt64::N_OPRAND_CELLS,
        old_stack_ts => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    }
);

impl CalldataloadInstruction {
    const OPCODE: OpcodeType = OpcodeType::CALLDATALOAD;
}

impl<E: ExtensionField> Instruction<E> for CalldataloadInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
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
            stack_top_expr,
            clk_expr.add(E::BaseField::ONE),
        );

        // Range check for stack top
        rom_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(1)),
        )?;

        // Stack pop offset from the stack.
        let old_stack_ts = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts()])?;
        let offset = &phase0[Self::phase0_offset()];
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts.values(),
            offset,
        );
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;

        // CallDataLoad check (offset, data)
        let data = &phase0[Self::phase0_data()];
        rom_handler.calldataload(&mut circuit_builder, offset, data);

        // Stack push data to the stack.
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            stack_ts.values(),
            data,
        );

        // Bytecode table (pc, CalldataLoad)
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
}
