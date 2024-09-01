use goldilocks::GoldilocksExt2;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem, ProvingKey},
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
    let vk = cs.key_gen();
    let _pk = ProvingKey::create_pk(vk);
}
