use goldilocks::SmallField;

use crate::{
    component_circuits::{
        BitOpChipWiresIndices, BytecodeChipWiresIndices, GlobalStateChipWiresIndices,
        HashChipWiresIndices, MemoryWiresIndices, OpcodeWiresIndices, RangeChipWiresIndices,
        StackWiresIndices,
    },
    OpcodeType, ZKVMCircuit,
};

use super::SingerBasicCircuit;

impl<F: SmallField> ZKVMCircuit<F> for SingerBasicCircuit<F> {
    fn construct_opcode(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
        opcode: OpcodeType,
        challenge: usize,
    ) -> OpcodeWiresIndices {
        todo!()
    }

    fn construct_memory(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> MemoryWiresIndices {
        todo!()
    }

    fn construct_bytecode_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> BytecodeChipWiresIndices {
        todo!()
    }

    fn construct_stack(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> StackWiresIndices {
        todo!()
    }

    fn construct_global_state_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> GlobalStateChipWiresIndices {
        todo!()
    }

    fn construct_range_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> RangeChipWiresIndices {
        todo!()
    }

    fn construct_bit_op_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> BitOpChipWiresIndices {
        todo!()
    }

    fn construct_hash_chip(
        &mut self,
        circuit_builder_depot: &crate::circuit_gadgets::CircuitBuilderDepot<F>,
    ) -> HashChipWiresIndices {
        todo!()
    }
}
