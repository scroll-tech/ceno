use goldilocks::GoldilocksExt2;
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme};

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
};

use super::arith::{AddInstruction, SubInstruction};

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
    let param = PCS::setup(1 << 10).unwrap();
    let (pp, _) = PCS::trim(&param, 1 << 10).unwrap();
    cs.key_gen::<PCS>(&pp, None);
}
