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
    uint::{UIntAddSub, UIntCmp},
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct AddInstruction;

impl<F: SmallField> InstructionGraph<F> for AddInstruction {
    type InstType = Self;
}

register_witness!(
    AddInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        old_stack_ts0 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt0 => UIntCmp::<TSUInt>::N_WITNESS_CELLS,
        old_stack_ts1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt1 => UIntCmp::<TSUInt>::N_WITNESS_CELLS,

        addend_0 => StackUInt::N_OPRAND_CELLS,
        addend_1 => StackUInt::N_OPRAND_CELLS,
        instruction_add => UIntAddSub::<StackUInt>::N_WITNESS_CELLS
    }
);

impl AddInstruction {
    const OPCODE: OpcodeType = OpcodeType::ADD;
}

impl<F: SmallField> Instruction<F> for AddInstruction {
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
        let addend_0 = (&phase0[Self::phase0_addend_0()]).try_into()?;
        let addend_1 = (&phase0[Self::phase0_addend_1()]).try_into()?;
        #[cfg(feature = "dbg-add-opcode")]
        println!(
            "addInstCircuit::phase0_instruction_add: {:?}",
            Self::phase0_instruction_add()
        );
        let result = UIntAddSub::<StackUInt>::add(
            &mut circuit_builder,
            &mut rom_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_instruction_add()],
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
            addend_0.values(),
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
            addend_1.values(),
        );

        // Push one result to stack
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            stack_ts.values(),
            result.values(),
        );

        // Bytecode check for (pc, add)
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

#[cfg(test)]
mod test {
    use core::ops::Range;
    use std::collections::BTreeMap;

    use crate::instructions::{AddInstruction, ChipChallenges, Instruction};
    use crate::test::{get_uint_params, test_opcode_circuit, u2vec};
    use crate::utils::uint::{StackUInt, TSUInt};
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CellId;
    use singer_utils::constants::RANGE_CHIP_BIT_WIDTH;

    impl AddInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_pc_add".to_string(), Self::phase0_pc_add());
            map.insert(
                "phase0_stack_ts_add".to_string(),
                Self::phase0_stack_ts_add(),
            );
            map.insert(
                "phase0_old_stack_ts0".to_string(),
                Self::phase0_old_stack_ts0(),
            );
            map.insert(
                "phase0_old_stack_ts_lt0".to_string(),
                Self::phase0_old_stack_ts_lt0(),
            );
            map.insert(
                "phase0_old_stack_ts1".to_string(),
                Self::phase0_old_stack_ts1(),
            );
            map.insert(
                "phase0_old_stack_ts_lt1".to_string(),
                Self::phase0_old_stack_ts_lt1(),
            );
            map.insert("phase0_addend_0".to_string(), Self::phase0_addend_0());
            map.insert("phase0_addend_1".to_string(), Self::phase0_addend_1());
            map.insert(
                "phase0_instruction_add".to_string(),
                Self::phase0_instruction_add(),
            );

            map
        }
    }

    #[test]
    fn test_add_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = AddInstruction::phase0_idxes_map();
        let phase0_witness_size = AddInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("ADD: {:?}", &phase0_idx_map);
            println!("ADD witness_size: {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = AddInstruction::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(3u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_stack_top".to_string(),
            vec![Goldilocks::from(100u64)],
        );
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert(
            "phase0_stack_ts_add".to_string(),
            vec![
                Goldilocks::from(4u64), // first TSUInt::N_RANGE_CHECK_CELLS = 1*(56/16) = 4 cells are range values, stack_ts + 1 = 4
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                // no place for carry
            ],
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts0".to_string(),
            vec![Goldilocks::from(2u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt0".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts1".to_string(),
            vec![Goldilocks::from(1u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt1".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        let m: u64 = (1 << get_uint_params::<StackUInt>().1) - 1;
        phase0_values_map.insert("phase0_addend_0".to_string(), vec![Goldilocks::from(m)]);
        phase0_values_map.insert("phase0_addend_1".to_string(), vec![Goldilocks::from(1u64)]);
        let range_values = u2vec::<{ StackUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m + 1);
        let mut wit_phase0_instruction_add: Vec<Goldilocks> = vec![];
        for i in 0..16 {
            wit_phase0_instruction_add.push(Goldilocks::from(range_values[i]))
        }
        wit_phase0_instruction_add.push(Goldilocks::from(1u64)); // carry is [1, 0, ...]
        phase0_values_map.insert(
            "phase0_instruction_add".to_string(),
            wit_phase0_instruction_add,
        );

        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c: u64 = 2;
        let circuit_witness_challenges = vec![
            Goldilocks::from(c),
            Goldilocks::from(c),
            Goldilocks::from(c),
        ];

        let circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );

        // check the correctness of add operation
        // stack_push = 98 (stack_top) + c^2 * 3 (stack_ts) + c^4 * 1 + c^11
        // TODO: the new version has a different scheme for stack_push computation so need to match
        let add_stack_push_wire_id = inst_circuit.layout.chip_check_wire_id[1].unwrap().0;
        let add_stack_push =
            &circuit_witness.witness_out_ref()[add_stack_push_wire_id as usize].instances[0][1];
        println!("add_stack_push {:?}", add_stack_push);
        let add_stack_push_value: u64 = 98 + c.pow(2_u32) * 3 + c.pow(4u32) * 1 + c.pow(11_u32);
        println!("add_stack_push_value: {:?}", add_stack_push_value);
        //assert_eq!(*add_stack_push, Goldilocks::from(add_stack_push_value));
    }
}
