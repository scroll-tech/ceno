use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use itertools::izip;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use std::sync::Arc;

use crate::{
    constants::OpcodeType,
    error::ZKVMError,
    utils::{
        chip_handler::{
            BytecodeChipOperations, ChipHandler, GlobalStateChipOperations, RangeChipOperations,
            StackChipOperations,
        },
        uint::{PCUInt, StackUInt, TSUInt, UIntAddSub, UIntCmp},
    },
};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct JumpiInstruction;

impl InstructionGraph for JumpiInstruction {
    type InstType = Self;
}

register_witness!(
    JumpiInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS ,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        old_stack_ts_dest => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_dest_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        old_stack_ts_cond => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_cond_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        dest_values => StackUInt::N_OPRAND_CELLS,
        cond_values => StackUInt::N_OPRAND_CELLS,
        cond_values_inv => StackUInt::N_OPRAND_CELLS,
        cond_non_zero_or_inv => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        pc_plus_1_opcode => 1
    }
);

impl JumpiInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMPI;
}

impl Instruction for JumpiInstruction {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut global_state_out_handler = ChipHandler::new(challenges.global_state());
        let mut bytecode_chip_handler = ChipHandler::new(challenges.bytecode());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());
        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &memory_ts,
            stack_top,
            clk,
        );

        // Range check stack_top - 2
        range_chip_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
        )?;

        // Pop the destination pc from stack.
        let dest_values = &phase0[Self::phase0_dest_values()];
        let dest_stack_addr = stack_top_expr.sub(F::BaseField::ONE);

        let old_stack_ts_dest = (&phase0[Self::phase0_old_stack_ts_dest()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_dest,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_dest_lt()],
        )?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            dest_stack_addr,
            old_stack_ts_dest.values(),
            dest_values,
        );

        // Pop the condition from stack.
        let cond_values = &phase0[Self::phase0_cond_values()];
        let old_stack_ts_cond = (&phase0[Self::phase0_old_stack_ts_cond()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_cond,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_cond_lt()],
        )?;

        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            old_stack_ts_cond.values(),
            cond_values,
        );

        // Execution, cond_values_non_zero[i] = [cond_values[i] != 0]
        let cond_values_inv = &phase0[Self::phase0_cond_values_inv()];
        let mut cond_values_non_zero = Vec::new();
        for (val, wit) in izip!(cond_values, cond_values_inv) {
            cond_values_non_zero.push(range_chip_handler.non_zero(
                &mut circuit_builder,
                *val,
                *wit,
            )?);
        }
        // cond_non_zero = [summation of cond_values_non_zero[i] != 0]
        let non_zero_or = circuit_builder.create_cell();
        cond_values_non_zero
            .iter()
            .for_each(|x| circuit_builder.add(non_zero_or, *x, F::BaseField::ONE));
        let cond_non_zero_or_inv = phase0[Self::phase0_cond_non_zero_or_inv().start];
        let cond_non_zero =
            range_chip_handler.non_zero(&mut circuit_builder, non_zero_or, cond_non_zero_or_inv)?;

        // If cond_non_zero, next_pc = dest, otherwise, pc = pc + 1
        let pc_add_1 = &phase0[Self::phase0_pc_add()];
        let pc_plus_1 = ChipHandler::add_pc_const(&mut circuit_builder, &pc, 1, pc_add_1)?;
        let pc_plus_1 = pc_plus_1.values();
        let next_pc = circuit_builder.create_cells(PCUInt::N_OPRAND_CELLS);
        for i in 0..PCUInt::N_OPRAND_CELLS {
            circuit_builder.select(next_pc[i], pc_plus_1[i], dest_values[i], cond_non_zero);
        }

        // State out
        global_state_out_handler.state_out(
            &mut circuit_builder,
            &next_pc,
            stack_ts.values(), // Because there is no stack push.
            memory_ts,
            stack_top_expr.sub(F::BaseField::from(2)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Bytecode check for (pc, jumpi)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        // If cond_non_zero, next_opcode = JUMPDEST, otherwise, opcode = pc + 1 opcode
        let pc_plus_1_opcode = phase0[Self::phase0_pc_plus_1_opcode().start];
        let next_opcode = circuit_builder.create_cell();
        circuit_builder.sel_mixed(
            next_opcode,
            pc_plus_1_opcode.into(),
            MixedCell::Constant(F::BaseField::from(OpcodeType::JUMPDEST as u64)),
            cond_non_zero,
        );

        // Bytecode check for (next_pc, next_opcode)
        bytecode_chip_handler.bytecode_with_pc_byte(&mut circuit_builder, &next_pc, next_opcode);

        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let global_state_out_id = global_state_out_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let bytecode_chip_id =
            bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_id),
            Some(global_state_out_id),
            Some(bytecode_chip_id),
            Some(stack_pop_id),
            None,
            Some(range_chip_id),
            None,
            None,
            None,
        ];

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
