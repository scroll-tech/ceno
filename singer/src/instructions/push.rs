use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
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
        uint::{PCUInt, StackUInt, TSUInt, UIntAddSub},
    },
};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct PushInstruction<const N: usize>;

impl<const N: usize> InstructionGraph for PushInstruction<N> {
    type InstType = Self;
}

register_witness!(
    PushInstruction<N>,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add_i_plus_1 => N * UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        stack_bytes => N
    }
);

impl<const N: usize> PushInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::PUSH1,
        _ => unimplemented!(),
    };
}

impl<const N: usize> Instruction for PushInstruction<N> {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut global_state_out_handler = ChipHandler::new(challenges.global_state());
        let mut bytecode_chip_handler = ChipHandler::new(challenges.bytecode());
        let mut stack_push_handler = ChipHandler::new(challenges.stack());
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
        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            N as i64 + 1,
            &phase0[Self::phase0_pc_add_i_plus_1()],
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
            &memory_ts,
            stack_top_expr.add(F::BaseField::from(1)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Check the range of stack_top is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler.range_check_stack_top(&mut circuit_builder, stack_top_expr)?;

        let stack_bytes = &phase0[Self::phase0_stack_bytes()];
        let stack_values = StackUInt::from_bytes_big_endien(&mut circuit_builder, stack_bytes)?;
        // Push value to stack
        stack_push_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr,
            stack_ts.values(),
            stack_values.values(),
        );

        // Bytecode check for (pc, PUSH{N}), (pc + 1, byte[0]), ..., (pc + N, byte[N - 1])
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );
        for (i, pc_add_i_plus_1) in phase0[Self::phase0_pc_add_i_plus_1()]
            .chunks(UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS)
            .enumerate()
        {
            let next_pc = ChipHandler::add_pc_const(
                &mut circuit_builder,
                &pc,
                i as i64 + 1,
                pc_add_i_plus_1,
            )?;
            bytecode_chip_handler.bytecode_with_pc_byte(
                &mut circuit_builder,
                next_pc.values(),
                stack_bytes[i],
            );
        }

        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let global_state_out_id = global_state_out_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let bytecode_chip_id =
            bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_push_id =
            stack_push_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_id),
            Some(global_state_out_id),
            Some(bytecode_chip_id),
            None,
            Some(stack_push_id),
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

#[cfg(test)]
mod test {
    use core::ops::Range;
    use std::collections::BTreeMap;

    use crate::instructions::{ChipChallenges, Instruction, PushInstruction};
    use crate::test::test_opcode_circuit;
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CellId;

    impl<const N: usize> PushInstruction<N> {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert(
                "phase0_pc_add_i_plus_1".to_string(),
                Self::phase0_pc_add_i_plus_1(),
            );
            map.insert(
                "phase0_stack_ts_add".to_string(),
                Self::phase0_stack_ts_add(),
            );
            map.insert("phase0_stack_bytes".to_string(), Self::phase0_stack_bytes());

            map
        }
    }

    #[test]
    fn test_push1_construct_circuit() {
        let challenges = ChipChallenges::default();

        // initialize general test inputs associated with push1
        let inst_circuit =
            PushInstruction::<1>::construct_circuit::<Goldilocks>(challenges).unwrap();

        println!("{:?}", inst_circuit);

        let phase0_idx_map = PushInstruction::<1>::phase0_idxes_map();
        println!("{:?}", &phase0_idx_map);
        let phase0_witness_size = PushInstruction::<1>::phase0_size();
        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_top".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add_i_plus_1".to_string(),
            vec![Goldilocks::from(3u64)],
        );
        phase0_values_map.insert(
            "phase0_stack_ts_add".to_string(),
            vec![Goldilocks::from(2u64)],
        );
        phase0_values_map.insert(
            "phase0_stack_bytes".to_string(),
            vec![Goldilocks::from(1u64)],
        );

        test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
        );
    }
}
