use paste::paste;
use std::sync::Arc;
use strum::IntoEnumIterator;

use gkr::structs::Circuit;
use goldilocks::SmallField;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    component::{
        ChipChallenges, ChipType, FromPredInst, FromWitness, InstCircuit, InstLayout, ToSuccInst,
    },
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        chip_handler::ChipHandler,
        uint::{StackUInt, TSUInt, UIntAddSub},
    },
};

use super::{Instruction, InstructionGraph};

pub struct AddInstruction;

impl<F: SmallField> InstructionGraph<F> for AddInstruction {
    type InstType = Self;
}

register_witness!(
    AddInstruction,
    phase0 {
        // Witness for addend_0 + addend_1
        instruction_add => UIntAddSub::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<F: SmallField> Instruction<F> for AddInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let (addend_0_id, addend_0) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);
        let (addend_1_id, addend_1) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);

        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // Execution result = addend0 + addend1, with carry.
        let addend_0 = addend_0.try_into()?;
        let addend_1 = addend_1.try_into()?;
        let result = UIntAddSub::<StackUInt>::add(
            &mut circuit_builder,
            &mut range_chip_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_instruction_add()],
        )?;
        // To successor instruction
        let stack_result_id = circuit_builder.create_witness_out_from_cells(result.values());
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, &memory_ts);

        // To chips
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);

        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![addend_0_id, addend_1_id],
                },
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: None,

                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![stack_result_id],
                },
                to_bb_final: None,
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use core::ops::Range;
    use std::collections::BTreeMap;

    use crate::constants::RANGE_CHIP_BIT_WIDTH;
    use crate::instructions::{AddInstruction, ChipChallenges, Instruction};
    use crate::utils::uint::{StackUInt, TSUInt};
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CellId;

    impl AddInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
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
    }
}
