use std::sync::Arc;

use frontend::structs::{CircuitBuilder, MixedCell};
use gkr::structs::Circuit;
use goldilocks::SmallField;
use itertools::Itertools;
use revm_interpreter::Record;

use crate::{
    constants::{OpcodeType, EVM_STACK_BYTE_WIDTH},
    error::ZKVMError,
    instructions::InstCircuitLayout,
};
use crate::{PrepareSingerWiresIn, SingerWiresIn};

use super::{
    utils::{
        uint::{UIntAddSub, UIntCmp},
        ChipHandler, PCUInt, StackUInt, TSUInt,
    },
    ChipChallenges, InstCircuit, InstOutputType, Instruction, InstructionGraph,
};
pub struct MstoreInstruction;

impl InstructionGraph for MstoreInstruction {
    type InstType = Self;
}

register_wires_in!(
    MstoreInstruction,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS,
        phase0_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_memory_ts => TSUInt::N_OPRAND_CELLS,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        phase0_memory_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_old_stack_ts_offset => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt_offset => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        phase0_old_stack_ts_value => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt_value => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_old_memory_ts => EVM_STACK_BYTE_WIDTH * TSUInt::N_OPRAND_CELLS,
        phase0_old_memory_ts_lt => EVM_STACK_BYTE_WIDTH * UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_offset => StackUInt::N_OPRAND_CELLS,
        phase0_offset_add_i_plus_1 => (EVM_STACK_BYTE_WIDTH - 1) * UIntAddSub::<StackUInt>::N_WITNESS_CELLS,
        phase0_mem_bytes => EVM_STACK_BYTE_WIDTH,
        phase0_prev_mem_bytes => EVM_STACK_BYTE_WIDTH
    }
);

register_wires_out!(
    MstoreInstruction,
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
        offset => 1,
        value => 1
    },
    range_chip_size {
        stack_top => 1,
        old_stack_ts_lt0 => TSUInt::N_RANGE_CHECK_CELLS,
        old_stack_ts_lt1 => TSUInt::N_RANGE_CHECK_CELLS,
        offset_add => (EVM_STACK_BYTE_WIDTH - 1) * StackUInt::N_RANGE_CHECK_CELLS,
        memory_ts_add => TSUInt::N_RANGE_CHECK_NO_OVERFLOW_CELLS,
        old_memory_ts_lt => EVM_STACK_BYTE_WIDTH * TSUInt::N_RANGE_CHECK_CELLS,
        new_stack_bytes => EVM_STACK_BYTE_WIDTH
    },
    memory_load_size {
        old_stack_value => EVM_STACK_BYTE_WIDTH
    },
    memory_store_size {
        new_stack_value => EVM_STACK_BYTE_WIDTH
    }
);

impl MstoreInstruction {
    const OPCODE: OpcodeType = OpcodeType::MSTORE;
}

impl Instruction for MstoreInstruction {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
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
            InstOutputType::MemoryLoad => Self::memory_load_size(),
            InstOutputType::MemoryStore => Self::memory_store_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
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
        let mut memory_load_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::memory_load_size());
        let mut memory_store_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::memory_store_size());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = TSUInt::try_from(&phase0[Self::phase0_memory_ts()])?;
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            memory_ts.values(),
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        let next_memory_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &memory_ts,
            1,
            &phase0[Self::phase0_memory_ts_add()],
        )?;
        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(),
            next_memory_ts.values(),
            stack_top_expr,
            clk_expr.add(F::ONE),
        );

        range_chip_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(F::from(2)))?;

        // Pop offset from stack
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        let old_stack_ts_offset = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_offset()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_offset,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_offset()],
        )?;
        stack_pop_handler.stack_pop_values(
            &mut circuit_builder,
            stack_top_expr.sub(F::ONE),
            old_stack_ts_offset.values(),
            offset.values(),
        );

        // Pop mem_bytes from stack
        let mem_bytes = &phase0[Self::phase0_mem_bytes()];
        range_chip_handler.range_check_bytes(&mut circuit_builder, mem_bytes)?;

        let mem_value = StackUInt::from_bytes_big_endien(&mut circuit_builder, &mem_bytes)?;
        let old_stack_ts_value = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_value()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_value,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_value()],
        )?;
        stack_pop_handler.stack_pop_values(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(2)),
            old_stack_ts_value.values(),
            mem_value.values(),
        );

        // Compute offset, offset + 1, ..., offset + EVM_STACK_BYTE_WIDTH - 1.
        // Load previous memory bytes.
        let prev_mem_bytes = &phase0[Self::phase0_prev_mem_bytes()];
        let all_old_memory_ts = {
            let mut all_old_memory_ts = Vec::new();
            for chunk in phase0[Self::phase0_old_memory_ts()].chunks(TSUInt::N_OPRAND_CELLS) {
                all_old_memory_ts.push(TSUInt::try_from(chunk)?);
            }
            all_old_memory_ts
        };
        let all_old_memory_ts_lt = &phase0[Self::phase0_old_memory_ts_lt()]
            .chunks(UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS)
            .collect_vec();
        let all_offset_add_i_plus_1 = &phase0[Self::phase0_offset_add_i_plus_1()]
            .chunks(UIntAddSub::<StackUInt>::N_WITNESS_CELLS)
            .collect_vec();
        for i in 0..EVM_STACK_BYTE_WIDTH {
            let offset_plus_i = if i == 0 {
                offset.clone()
            } else {
                UIntAddSub::<StackUInt>::add_const(
                    &mut circuit_builder,
                    &mut range_chip_handler,
                    &offset,
                    &F::from(i as u64),
                    all_offset_add_i_plus_1[i - 1],
                )?
            };
            UIntCmp::<TSUInt>::assert_lt(
                &mut circuit_builder,
                &mut range_chip_handler,
                &all_old_memory_ts[i],
                &memory_ts,
                all_old_memory_ts_lt[i],
            )?;
            memory_load_handler.mem_load(
                &mut circuit_builder,
                offset_plus_i.values(),
                all_old_memory_ts[i].values(),
                prev_mem_bytes[i],
            );
            memory_store_handler.mem_store(
                &mut circuit_builder,
                offset_plus_i.values(),
                memory_ts.values(),
                mem_bytes[i],
            )
        }

        // Bytecode check for (pc, mstore)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        global_state_out_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        memory_load_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        memory_store_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            Some(global_state_out_handler.wire_out_id()),
            Some(bytecode_chip_handler.wire_out_id()),
            Some(stack_pop_handler.wire_out_id()),
            None,
            Some(range_chip_handler.wire_out_id()),
            Some(memory_load_handler.wire_out_id()),
            Some(memory_store_handler.wire_out_id()),
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), None],
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
