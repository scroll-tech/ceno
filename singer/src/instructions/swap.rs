use std::sync::Arc;

use frontend::structs::{CircuitBuilder, MixedCell};
use gkr::structs::Circuit;
use goldilocks::SmallField;
use revm_interpreter::Record;

use crate::instructions::InstCircuitLayout;
use crate::{constants::OpcodeType, error::ZKVMError};
use crate::{PrepareSingerWiresIn, SingerWiresIn};

use super::InstructionGraph;
use super::{
    utils::{
        uint::{UIntAddSub, UIntCmp},
        ChipHandler, PCUInt, TSUInt,
    },
    ChipChallenges, InstCircuit, InstOutputType, Instruction,
};

pub struct SwapInstruction<const N: usize>;

impl<const N: usize> InstructionGraph for SwapInstruction<N> {
    type InstType = Self;
}

register_wires_in!(
    SwapInstruction<N>,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS,
        phase0_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        phase0_stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_old_stack_ts_1 => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        phase0_old_stack_ts_n_plus_1 => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt_n_plus_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    },
    phase1_size {
        phase1_stack_rlc_1 => 1,
        phase1_stack_rlc_n_plus_1 => 1,
        phase1_memory_ts_rlc => 1
    }
);

register_wires_out!(
    SwapInstruction<N>,
    global_state_in_size {
        state_in => 1
    },
    global_state_out_size {
        state_out => 1
    },
    bytecode_chip_size {
        current => 1
    },
    stack_pop_size {
        top_minus_1 => 1,
        top_minus_n_plus_1 => 1
    },
    stack_push_size {
        top_minus_1 => 1,
        top_minus_n_plus_1 => 1
    },
    range_chip_size {
        stack_ts_add => TSUInt::N_RANGE_CHECK_NO_OVERFLOW_CELLS,
        old_stack_ts_lt_1 => TSUInt::N_RANGE_CHECK_CELLS,
        old_stack_ts_lt_n_plus_1 => TSUInt::N_RANGE_CHECK_CELLS
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

impl<const N: usize> Instruction for SwapInstruction<N> {
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
            InstOutputType::StackPush => Self::stack_push_size(),
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
        let mut stack_push_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_push_size());
        let mut stack_pop_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_pop_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts_rlc = phase1[Self::phase1_memory_ts_rlc().start];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &[memory_ts_rlc],
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        let next_stack_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            &[memory_ts_rlc],
            stack_top_expr,
            clk_expr.add(F::ONE),
        );

        // Check the range of stack_top - (N + 1) is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(N as u64 + 1)),
        )?;

        // Pop rlc of stack[top - (N + 1)] from stack
        let old_stack_ts_n_plus_1 = (&phase0[Self::phase0_old_stack_ts_n_plus_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_n_plus_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_n_plus_1()],
        )?;
        let stack_rlc_n_plus_1 = phase1[Self::phase1_stack_rlc_n_plus_1().start];
        stack_pop_handler.stack_pop_rlc(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(N as u64 + 1)),
            old_stack_ts_n_plus_1.values(),
            stack_rlc_n_plus_1,
        );

        // Pop rlc of stack[top - 1] from stack
        let old_stack_ts_1 = (&phase0[Self::phase0_old_stack_ts_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_1()],
        )?;
        let stack_rlc_1 = phase1[Self::phase1_stack_rlc_1().start];
        stack_pop_handler.stack_pop_rlc(
            &mut circuit_builder,
            stack_top_expr.sub(F::ONE),
            old_stack_ts_1.values(),
            stack_rlc_1,
        );

        // Push stack_rlc_1 to the stack at top - (N + 1)
        stack_push_handler.stack_push_rlc(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(N as u64 + 1)),
            stack_ts.values(),
            stack_rlc_1,
        );
        // Push stack_rlc_n_plus_1 to the stack at top - 1
        stack_push_handler.stack_push_rlc(
            &mut circuit_builder,
            stack_top_expr.sub(F::ONE),
            stack_ts.values(),
            stack_rlc_n_plus_1,
        );

        // Bytecode check for (pc, SWAP{N}).
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        global_state_out_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_push_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            Some(global_state_out_handler.wire_out_id()),
            Some(bytecode_chip_handler.wire_out_id()),
            Some(stack_pop_handler.wire_out_id()),
            Some(stack_push_handler.wire_out_id()),
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

    fn generate_pre_wires_in<F: SmallField>(record: &Record, index: usize) -> Option<Vec<F>> {
        todo!()
    }
    fn complete_wires_in<F: SmallField>(
        pre_wires_in: &PrepareSingerWiresIn<F>,
        challenges: &Vec<F>,
    ) -> SingerWiresIn<F> {
        todo!();
    }
}
