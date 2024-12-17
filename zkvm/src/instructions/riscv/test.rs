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
    type Pcs = BasefoldDefault<E>;

    let mut cs = ConstraintSystem::new(|| "riscv");
    let _add_config = cs.namespace(
        || "add",
        |cs| AddInstruction::construct_circuit(&mut CircuitBuilder::<E>::new(cs)),
    );
    let _sub_config = cs.namespace(
        || "sub",
        |cs| SubInstruction::construct_circuit(&mut CircuitBuilder::<E>::new(cs)),
    );
    let param = Pcs::setup(1 << 10).unwrap();
    let (pp, _) = Pcs::trim(param, 1 << 10).unwrap();
    cs.key_gen::<Pcs>(&pp, None);
}
