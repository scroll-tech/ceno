use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
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
    uint::UIntAddSub,
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct PushInstruction<const N: usize>;

impl<F: SmallField, const N: usize> InstructionGraph<F> for PushInstruction<N> {
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

impl<F: SmallField, const N: usize> Instruction<F> for PushInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::PUSH1,
        _ => unimplemented!(),
    };
    const NAME: &'static str = match N {
        1 => "PUSH1",
        _ => unimplemented!(),
    };
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
        let next_pc = ROMHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            N as i64 + 1,
            &phase0[Self::phase0_pc_add_i_plus_1()],
        )?;
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
            stack_top_expr.add(F::BaseField::from(1)),
            clk_expr.add(F::BaseField::ONE),
        );

        // Check the range of stack_top is within [0, 1 << STACK_TOP_BIT_WIDTH).
        rom_handler.range_check_stack_top(&mut circuit_builder, stack_top_expr)?;

        let stack_bytes = &phase0[Self::phase0_stack_bytes()];
        let stack_values = StackUInt::from_bytes_big_endien(&mut circuit_builder, stack_bytes)?;
        // Push value to stack
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr,
            stack_ts.values(),
            stack_values.values(),
        );

        // Bytecode check for (pc, PUSH{N}), (pc + 1, byte[0]), ..., (pc + N, byte[N - 1])
        rom_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<F>>::OPCODE,
        );
        for (i, pc_add_i_plus_1) in phase0[Self::phase0_pc_add_i_plus_1()]
            .chunks(UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS)
            .enumerate()
        {
            let next_pc =
                ROMHandler::add_pc_const(&mut circuit_builder, &pc, i as i64 + 1, pc_add_i_plus_1)?;
            rom_handler.bytecode_with_pc_byte(
                &mut circuit_builder,
                next_pc.values(),
                stack_bytes[i],
            );
        }

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

        let phase0_idx_map = PushInstruction::<1>::phase0_idxes_map();
        let phase0_witness_size = PushInstruction::<1>::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("PUSH1 {:?}", &phase0_idx_map);
            println!("PUSH1 witness_size = {:?}", phase0_witness_size);
        }
        // initialize general test inputs associated with push1
        let inst_circuit = PushInstruction::<1>::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_stack_top".to_string(),
            vec![Goldilocks::from(100u64)],
        );
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add_i_plus_1".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert(
            "phase0_stack_ts_add".to_string(),
            vec![
                Goldilocks::from(2u64), // first TSUInt::N_RANGE_CHECK_CELLS = 1*(56/16) = 4 cells are range values, stack_ts + 1 = 4
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                // no place for carry
            ],
        );
        phase0_values_map.insert(
            "phase0_stack_bytes".to_string(),
            vec![
                Goldilocks::from(0u64),
                Goldilocks::from(1u64),
                Goldilocks::from(2u64),
                Goldilocks::from(3u64),
                Goldilocks::from(4u64),
                Goldilocks::from(5u64),
                Goldilocks::from(6u64),
                Goldilocks::from(7u64),
            ],
        );

        let circuit_witness_challenges = vec![
            Goldilocks::from(2),
            Goldilocks::from(2),
            Goldilocks::from(2),
        ];

        let _circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }
}
