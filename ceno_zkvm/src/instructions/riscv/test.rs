use ff_ext::GoldilocksExt2;
use mpcs::{BasefoldDefault, PolynomialCommitmentScheme, SecurityLevel};

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    structs::{ComposedConstrainSystem, ProgramParams},
};

use super::arith::{AddInstruction, SubInstruction};

#[test]
fn test_multiple_opcode() {
    type E = GoldilocksExt2;
    type Pcs = BasefoldDefault<E>;

    let params = ProgramParams::default();

    let mut cs = ConstraintSystem::new(|| "riscv");
    let add_inst = AddInstruction::<E>::default();
    let _add_config = cs.namespace(
        || "add",
        |cs| add_inst.construct_circuit(&mut CircuitBuilder::<E>::new(cs), &params),
    );
    let sub_inst = SubInstruction::<E>::default();
    let _sub_config = cs.namespace(
        || "sub",
        |cs| sub_inst.construct_circuit(&mut CircuitBuilder::<E>::new(cs), &params),
    );
    let param = Pcs::setup(1 << 10, SecurityLevel::default()).unwrap();
    let (_, _) = Pcs::trim(param, 1 << 10).unwrap();
    let cs = ComposedConstrainSystem {
        zkvm_v1_css: cs,
        gkr_circuit: None,
    };
    cs.key_gen();
}
