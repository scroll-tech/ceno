use goldilocks::GoldilocksExt2;
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
};

use super::addsub::{AddInstruction, SubInstruction};

#[test]
fn test_multiple_opcode() {
    type E = GoldilocksExt2;
    type PCS = BasefoldDefault<E>;

    let mut cs = ConstraintSystem::new(|| "riscv");
    let _add_config = cs.namespace(
        || "add",
        |cs| {
            let mut circuit_builder = CircuitBuilder::<E>::new(cs);
            let config = AddInstruction::construct_circuit(&mut circuit_builder);
            Ok(config)
        },
    );
    let _sub_config = cs.namespace(
        || "sub",
        |cs| {
            let mut circuit_builder = CircuitBuilder::<E>::new(cs);
            let config = SubInstruction::construct_circuit(&mut circuit_builder);
            Ok(config)
        },
    );
    let rng = ChaCha8Rng::from_seed([0u8; 32]);
    let param = PCS::setup(1 << 10, &rng).unwrap();
    let (pp, _) = PCS::trim(&param, 1 << 10).unwrap();
    cs.key_gen::<PCS>(&pp, None);
}
