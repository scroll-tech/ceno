use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, TSUInt},
    uint::UIntAddSub,
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct JumpdestInstruction;

impl<F: SmallField> InstructionGraph<F> for JumpdestInstruction {
    type InstType = Self;
}

register_witness!(
    JumpdestInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS ,
        stack_ts=> TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS
    }
);

impl JumpdestInstruction {
    pub const OPCODE: OpcodeType = OpcodeType::JUMPDEST;
}

impl<F: SmallField> Instruction<F> for JumpdestInstruction {
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
        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(), // Because there is no stack push.
            memory_ts,
            stack_top.into(),
            clk_expr.add(F::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
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

    use crate::instructions::{ChipChallenges, Instruction, JumpdestInstruction};
    use crate::test::test_opcode_circuit;
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CellId;

    impl JumpdestInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_pc_add".to_string(), Self::phase0_pc_add());

            map
        }
    }

    #[test]
    fn test_jumpdest_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = JumpdestInstruction::phase0_idxes_map();
        let phase0_witness_size = JumpdestInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("JUMPDEST {:?}", &phase0_idx_map);
            println!("JUMPDEST witness_size = {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = JumpdestInstruction::construct_circuit(challenges).unwrap();

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
            "phase0_pc_add".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
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
