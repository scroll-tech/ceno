use std::sync::Arc;

use frontend::structs::{CellId, CircuitBuilder, MixedCell};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use crate::instructions::InstCircuitLayout;
use crate::{constants::OpcodeType, error::ZKVMError};

use super::InstructionGraph;
use super::{
    utils::{
        uint::{UIntAddSub, UIntCmp},
        ChipHandler, PCUInt, TSUInt,
    },
    ChipChallenges, InstCircuit, InstOutputType, Instruction,
};

pub struct JumpiInstruction;

impl InstructionGraph for JumpiInstruction {
    type InstType = Self;
}

register_wires_in!(
    JumpiInstruction,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS ,
        phase0_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_old_stack_ts_dest => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_dest_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        phase0_old_stack_ts_cond => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_cond_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_cond => 1,
        phase0_pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        phase0_pc_plus_1_opcode => 1
    },
    phase1_size {
        phase1_dest_rlc => 1,
        phase1_memory_ts_rlc => 1
    }
);

register_wires_out!(
    JumpiInstruction,
    global_state_in_size {
        state_in => 1
    },
    global_state_out_size {
        state_out => 1
    },
    bytecode_chip_size {
        current => 1,
        next => 1
    },
    stack_pop_size {
        next_pc => 1
    },
    range_chip_size {
        stack_top => 1,
        old_stack_ts_lt => TSUInt::N_RANGE_CHECK_CELLS
    }
);

impl JumpiInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMPI;
}

impl Instruction for JumpiInstruction {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            1 => Self::phase1_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::GlobalStateIn => Self::global_state_in_size(),
            InstOutputType::GlobalStateOut => Self::global_state_out_size(),
            InstOutputType::BytecodeChip => Self::bytecode_chip_size(),
            InstOutputType::StackPop => Self::stack_pop_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut global_state_in_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_in_size(),
        );
        let mut global_state_out_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_out_size(),
        );
        let mut bytecode_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::bytecode_chip_size());
        let mut stack_pop_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_pop_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts_rlc = phase1[Self::phase1_memory_ts_rlc().start] as CellId;
        let stack_top = phase0[Self::phase0_stack_top().start] as CellId;
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start] as CellId;
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &[memory_ts_rlc],
            stack_top,
            clk,
        );

        // Range check stack_top - 2
        range_chip_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(F::from(2)))?;

        // Pop the destination pc from stack.
        let dest_rlc = phase1[Self::phase1_dest_rlc().start] as CellId;
        let dest_stack_addr = stack_top_expr.sub(F::ONE);

        let old_stack_ts_dest = (&phase0[Self::phase0_old_stack_ts_dest()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_dest,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_dest_lt()],
        )?;
        stack_pop_handler.stack_pop_rlc(
            &mut circuit_builder,
            dest_stack_addr,
            old_stack_ts_dest.values(),
            dest_rlc,
        );

        // Pop the condition from stack.
        let cond = phase0[Self::phase0_cond().start] as CellId;
        let old_stack_ts_cond = (&phase0[Self::phase0_old_stack_ts_cond()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_cond,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_cond_lt()],
        )?;

        stack_pop_handler.stack_pop_rlc(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(2)),
            old_stack_ts_cond.values(),
            cond,
        );

        // Compute next pc = cond ? dest : pc + 1
        let pc_plus_1 = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        let pc_plus_1_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(
            pc_plus_1_rlc,
            pc_plus_1.values(),
            challenges.record_item_rlc(),
        );

        let next_pc_rlc = circuit_builder.create_cell();
        circuit_builder.sel(next_pc_rlc, pc_plus_1_rlc, dest_rlc, cond);

        // State out
        global_state_out_handler.state_out(
            &mut circuit_builder,
            &[next_pc_rlc],
            stack_ts.values(), // Because there is no stack push.
            &[memory_ts_rlc],
            stack_top_expr.sub(F::from(2)),
            clk_expr.add(F::ONE),
        );

        // Bytecode check for (pc_rlc, jumpi)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        let pc_plus_1_opcode = phase0[Self::phase0_pc_plus_1_opcode().start];
        let next_opcode = circuit_builder.create_cell();
        circuit_builder.sel_mixed(
            next_opcode,
            pc_plus_1_opcode.into(),
            MixedCell::Constant(F::from(OpcodeType::JUMPDEST as u64)),
            cond,
        );
        // Bytecode check for (next_pc_rlc, next_opcode)
        bytecode_chip_handler.bytecode_with_pc_byte(
            &mut circuit_builder,
            &[next_pc_rlc],
            next_opcode,
        );

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        global_state_out_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            Some(global_state_out_handler.wire_out_id()),
            Some(bytecode_chip_handler.wire_out_id()),
            Some(stack_pop_handler.wire_out_id()),
            None,
            Some(range_chip_handler.wire_out_id()),
            None,
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                ..Default::default()
            },
        })
    }
}
