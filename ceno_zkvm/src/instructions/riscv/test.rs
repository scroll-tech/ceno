use goldilocks::GoldilocksExt2;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
};

use super::addsub::{AddInstruction, SubInstruction};

#[test]
fn test_multiple_opcode() {
    let mut cs = ConstraintSystem::new(|| "riscv");
    let _add_config = cs.namespace(
        || "add",
        |cs| {
            let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(cs);
            let config = AddInstruction::construct_circuit(&mut circuit_builder);
            Ok(config)
        },
    );
    let _sub_config = cs.namespace(
        || "sub",
        |cs| {
            let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(cs);
            let config = SubInstruction::construct_circuit(&mut circuit_builder);
            Ok(config)
        },
    );
    cs.key_gen(None);
}
