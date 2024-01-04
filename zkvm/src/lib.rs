use circuit_gadgets::CircuitBuilderDepot;
use component_circuits::{
    BitOpChipWiresIndices, BytecodeChipWiresIndices, GlobalStateChipWiresIndices,
    HashChipWiresIndices, MemoryWiresIndices, OpcodeWiresIndices, RangeChipWiresIndices,
    StackWiresIndices,
};
use constants::OpcodeType;
use error::ZKVMError;

use goldilocks::SmallField;
use scheme::ZKVMProof;
use transcript::Transcript;

pub mod circuit_gadgets;
pub mod component_circuits;
pub mod constants;
pub mod error;
pub mod scheme;
pub mod singer_basic;
pub mod singer_pro;

pub trait ZKVMCircuit<F: SmallField> {
    fn construct_opcode(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
        opcode: OpcodeType,
        challenge: usize,
    ) -> OpcodeWiresIndices;

    fn construct_memory(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> MemoryWiresIndices;

    fn construct_bytecode_chip(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> BytecodeChipWiresIndices;

    fn construct_stack(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> StackWiresIndices;

    fn construct_global_state_chip(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> GlobalStateChipWiresIndices;

    fn construct_range_chip(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> RangeChipWiresIndices;

    fn construct_bit_op_chip(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> BitOpChipWiresIndices;

    fn construct_hash_chip(
        &mut self,
        circuit_builder_depot: &CircuitBuilderDepot<F>,
    ) -> HashChipWiresIndices;
}

pub trait ZKVMWitness<F: SmallField> {
    type Circuit: ZKVMCircuit<F>;
    fn new(circuit: &Self::Circuit) -> Self;
    fn initialize(&mut self, bytecode: &[u8], public_input: &[F]) -> Result<(), ZKVMError>;
    fn execute(&mut self) -> Result<(), ZKVMError>;
    fn finalize(&mut self) -> Result<(), ZKVMError>;
}

pub trait ZKVMPublicIO<F: SmallField> {
    type Circuit: ZKVMCircuit<F>;
    fn new(circuit: &Self::Circuit, bytecode: &[u8], public_input: &[F]) -> Self;
}

pub trait ZKVM<F: SmallField> {
    type Circuit: ZKVMCircuit<F>;
    type CircuitWitness: ZKVMWitness<F>;
    type PublicIO: ZKVMPublicIO<F>;
    fn construct_circuits(opcode_list: &[OpcodeType]) -> Self::Circuit;
    fn witness_generation(
        zkvm_circuit: &Self::Circuit,
        bytecode: &[u8],
        public_input: &[F],
    ) -> Result<(Self::PublicIO, Self::CircuitWitness), ZKVMError>;
    fn prove(
        circuit: &Self::Circuit,
        circuit_witness: &Self::CircuitWitness,
        transcript: &mut Transcript<F>,
    ) -> ZKVMProof<F>;
    fn verify(
        circuit: &Self::Circuit,
        public_io: &Self::PublicIO,
        proof: &ZKVMProof<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), ZKVMError>;
}
