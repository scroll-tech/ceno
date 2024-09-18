use ceno_emul::{Change, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MockProver, MOCK_PC_AND, MOCK_PROGRAM},
};

use super::*;

#[test]
#[allow(clippy::option_map_unit_fn)]
fn test_opcode_and() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "and",
            |cb| {
                let config = AndInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (raw_witin, _) = AndInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_AND,
            MOCK_PROGRAM[3],
            0xbead1234,
            0x5678f00d,
            Change::new(0, 0xbead1234 & 0x5678f00d),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied(
        &mut cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
    );
}
