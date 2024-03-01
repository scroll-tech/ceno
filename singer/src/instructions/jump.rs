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
        uint::{PCUInt, TSUInt, UIntCmp},
    },
};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct JumpInstruction;

impl InstructionGraph for JumpInstruction {
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
        old_stack_ts_lt => UIntCmp::<TSUInt>::N_WITNESS_CELLS
    }
);

impl JumpInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMP;
}

impl Instruction for JumpInstruction {
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

        // Pop next pc from stack
        range_chip_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(F::BaseField::ONE))?;

        let next_pc = &phase0[Self::phase0_next_pc()];
        let old_stack_ts = (&phase0[Self::phase0_old_stack_ts()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::ONE),
            old_stack_ts.values(),
            next_pc,
        );

        global_state_out_handler.state_out(
            &mut circuit_builder,
            &next_pc,
            stack_ts.values(), // Because there is no stack push.
            &memory_ts,
            stack_top_expr.sub(F::BaseField::from(1)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );
        // Bytecode check for (next_pc, jumpdest)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            &next_pc,
            OpcodeType::JUMPDEST,
        );

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

#[cfg(test)]
mod test {
    use core::ops::Range;
    use std::collections::BTreeMap;

    use crate::constants::RANGE_CHIP_BIT_WIDTH;
    use crate::instructions::{ChipChallenges, Instruction, JumpInstruction};
    use crate::test::{get_uint_params, test_opcode_circuit, u2vec};
    use crate::utils::uint::TSUInt;
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CellId;

    impl JumpInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_next_pc".to_string(), Self::phase0_next_pc());
            map.insert(
                "phase0_old_stack_ts".to_string(),
                Self::phase0_old_stack_ts(),
            );
            map.insert(
                "phase0_old_stack_ts_lt".to_string(),
                Self::phase0_old_stack_ts_lt(),
            );

            map
        }
    }

    #[test]
    fn test_jump_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = JumpInstruction::phase0_idxes_map();
        let phase0_witness_size = JumpInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("JUMP {:?}", &phase0_idx_map);
            println!("JUMP witness_size = {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = JumpInstruction::construct_circuit::<Goldilocks>(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(2u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_stack_top".to_string(),
            vec![Goldilocks::from(100u64)],
        );
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_next_pc".to_string(),
            vec![Goldilocks::from(127u64), Goldilocks::from(125u64)],
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts".to_string(),
            vec![Goldilocks::from(1u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // current length has no cells for borrow
            ],
        );

        let circuit_witness_challenges = vec![
            Goldilocks::from(2),
            Goldilocks::from(2),
            Goldilocks::from(2),
        ];

        test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }
}
