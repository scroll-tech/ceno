#![feature(generic_const_exprs)]

use std::sync::Arc;

use chips::ChipCircuitGadgets;
use error::ZKVMError;
use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphWitness;
use goldilocks::SmallField;
use instructions::add::AddInstruction;
use instructions::calldataload::CalldataloadInstruction;
use instructions::dup::DupInstruction;
use instructions::gt::GtInstruction;
use instructions::jump::JumpInstruction;
use instructions::jumpdest::JumpdestInstruction;
use instructions::jumpi::JumpiInstruction;
use instructions::mstore::MstoreInstruction;
use instructions::pop::PopInstruction;
use instructions::push::PushInstruction;
use instructions::ret::ReturnInstruction;
use instructions::swap::SwapInstruction;
use instructions::ChipChallenges;
use instructions::InstCircuit;
use instructions::Instruction;

pub mod chips;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;

// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

#[derive(Clone, Debug)]
pub struct SingerCircuitBuilder<F: SmallField> {
    /// Opcode circuits
    opcode_circuits: [Arc<InstCircuit<F>>; 256],
    chip_circuit_gadgets: ChipCircuitGadgets<F>,
}

impl<F: SmallField> SingerCircuitBuilder<F> {
    pub fn new(challenges: &ChipChallenges) -> Result<Self, ZKVMError> {
        let mut opcode_circuits = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcode_circuits.push(Arc::new(construct_opcode_circuit(opcode, challenges)?));
        }
        let opcode_circuits: [Arc<InstCircuit<F>>; 256] = opcode_circuits
            .try_into()
            .map_err(|_| ZKVMError::CircuitError)?;

        let chip_circuit_gadgets = ChipCircuitGadgets::new();
        Ok(Self {
            opcode_circuits,
            chip_circuit_gadgets,
        })
    }

    pub fn construct_gkr_graph(
        singer_wires_in: &SingerWiresIn<F>,
    ) -> (SingerCircuit<F>, SingerWitness<F>) {
        todo!()
    }
}

fn construct_opcode_circuit<F: SmallField>(
    opcode: u8,
    challenges: &ChipChallenges,
) -> Result<InstCircuit<F>, ZKVMError> {
    match opcode {
        0x01 => AddInstruction::construct_circuit(challenges),
        0x11 => GtInstruction::construct_circuit(challenges),
        0x35 => CalldataloadInstruction::construct_circuit(challenges),
        0x50 => PopInstruction::construct_circuit(challenges),
        0x52 => MstoreInstruction::construct_circuit(challenges),
        0x56 => JumpInstruction::construct_circuit(challenges),
        0x57 => JumpiInstruction::construct_circuit(challenges),
        0x5B => JumpdestInstruction::construct_circuit(challenges),
        0x60 => PushInstruction::<1>::construct_circuit(challenges),
        0x80 => DupInstruction::<1>::construct_circuit(challenges),
        0x81 => DupInstruction::<2>::construct_circuit(challenges),
        0x91 => SwapInstruction::<2>::construct_circuit(challenges),
        0x93 => SwapInstruction::<4>::construct_circuit(challenges),
        0xF3 => ReturnInstruction::construct_circuit(challenges),
        _ => unimplemented!(),
    }
}

pub struct SingerCircuit<F: SmallField>(CircuitGraph<F>);

pub struct SingerWitness<F: SmallField>(CircuitGraphWitness<F>);

pub struct SingerWiresIn<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}
