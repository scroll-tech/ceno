use goldilocks::SmallField;

use crate::{OpcodeType, ZKVMCircuit};

use super::SingerProCircuit;

impl<F: SmallField> ZKVMCircuit<F> for SingerProCircuit<F> {
    fn construct_opcode(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
        opcode: OpcodeType,
        challenge: usize,
    ) -> crate::component_circuits::OpcodeWiresIndices {
        todo!()
    }

    fn construct_memory(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::MemoryWiresIndices {
        todo!()
    }

    fn construct_bytecode_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::BytecodeChipWiresIndices {
        todo!()
    }

    fn construct_stack(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::StackWiresIndices {
        todo!()
    }

    fn construct_global_state_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::GlobalStateChipWiresIndices {
        todo!()
    }

    fn construct_range_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::RangeChipWiresIndices {
        todo!()
    }

    fn construct_bit_op_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::BitOpChipWiresIndices {
        todo!()
    }

    fn construct_hash_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> crate::component_circuits::HashChipWiresIndices {
        todo!()
    }
}
