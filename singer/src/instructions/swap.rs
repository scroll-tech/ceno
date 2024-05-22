use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
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

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};
pub struct SwapInstruction<const N: usize>;

impl<E: ExtensionField, const N: usize> InstructionGraph<E> for SwapInstruction<N> {
    type InstType = Self;
}

register_witness!(
    SwapInstruction<N>,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        old_stack_ts_1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        old_stack_ts_n_plus_1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_n_plus_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        stack_values_1 => StackUInt::N_OPRAND_CELLS,
        stack_values_n_plus_1 => StackUInt::N_OPRAND_CELLS
    }
);

impl<const N: usize> SwapInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::SWAP1,
        2 => OpcodeType::SWAP2,
        4 => OpcodeType::SWAP4,
        _ => unimplemented!(),
    };
}

impl<E: ExtensionField, const N: usize> Instruction<E> for SwapInstruction<N> {
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

        // Check the range of stack_top - (N + 1) is within [0, 1 << STACK_TOP_BIT_WIDTH).
        rom_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(N as u64 + 1)),
        )?;

        // Pop rlc of stack[top - (N + 1)] from stack
        let old_stack_ts_n_plus_1 = (&phase0[Self::phase0_old_stack_ts_n_plus_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts_n_plus_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_n_plus_1()],
        )?;
        let stack_values_n_plus_1 = &phase0[Self::phase0_stack_values_n_plus_1()];
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(N as u64 + 1)),
            old_stack_ts_n_plus_1.values(),
            stack_values_n_plus_1,
        );

        // Pop rlc of stack[top - 1] from stack
        let old_stack_ts_1 = (&phase0[Self::phase0_old_stack_ts_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_1()],
        )?;
        let stack_values_1 = &phase0[Self::phase0_stack_values_1()];
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts_1.values(),
            stack_values_1,
        );

        // Push stack_1 to the stack at top - (N + 1)
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(N as u64 + 1)),
            stack_ts.values(),
            stack_values_1,
        );
        // Push stack_n_plus_1 to the stack at top - 1
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            stack_ts.values(),
            stack_values_n_plus_1,
        );

        // Bytecode check for (pc, SWAP{N}).
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
