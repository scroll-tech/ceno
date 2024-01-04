use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphWitness;
use goldilocks::SmallField;

use crate::{error::ZKVMError, OpcodeType, ZKVM};

mod circuit;
mod public_io;
mod witness;

pub struct SingerBasic;

pub struct SingerBasicCircuit<F: SmallField>(CircuitGraph<F>);

pub struct SingerBasicWitness<F: SmallField>(CircuitGraphWitness<F>);

pub struct SingerBasicPublicIO<F: SmallField> {
    bytecode: Vec<F>,
    public_input: Vec<F>,
}

impl<F: SmallField> ZKVM<F> for SingerBasic {
    type Circuit = SingerBasicCircuit<F>;

    type CircuitWitness = SingerBasicWitness<F>;

    type PublicIO = SingerBasicPublicIO<F>;

    fn construct_circuits(opcode_list: &[OpcodeType]) -> Self::Circuit {
        todo!()
    }

    fn witness_generation(
        zkvm_circuit: &Self::Circuit,
        bytecode: &[u8],
        public_input: &[F],
    ) -> Result<(Self::PublicIO, Self::CircuitWitness), ZKVMError> {
        todo!()
    }

    fn prove(
        circuit: &Self::Circuit,
        circuit_witness: &Self::CircuitWitness,
        transcript: &mut transcript::Transcript<F>,
    ) -> crate::scheme::ZKVMProof<F> {
        todo!()
    }

    fn verify(
        circuit: &Self::Circuit,
        public_io: &Self::PublicIO,
        proof: &crate::scheme::ZKVMProof<F>,
        transcript: &mut transcript::Transcript<F>,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
