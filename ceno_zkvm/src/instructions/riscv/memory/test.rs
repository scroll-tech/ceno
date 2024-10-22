use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{Instruction, riscv::memory::StoreByte},
    scheme::mock_prover::{MOCK_PC_START, MockProver},
};
use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, Word, WriteOp, encode_rv32};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

fn sb(prev: Word, rs2: Word, shift: u32) -> Word {
    let shift = (shift * 8) as usize;
    prev & !(0xff << shift) | ((rs2 & 0xff) << shift)
}

fn impl_opcode_sb(shift: u32) {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "sb",
            |cb| {
                let config = StoreByte::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(InsnKind::SB, 2, 3, 4, shift);
    let prev_mem_value = 0x40302010;
    let rs2_word = Word::from(0x12345678_u32);
    let (raw_witin, lkm) = StoreByte::assign_instances(&config, cb.cs.num_witin as usize, vec![
        StepRecord::new_s_instruction(
            12,
            MOCK_PC_START,
            insn_code,
            Word::from(0x4000000_u32),
            rs2_word,
            WriteOp {
                addr: ByteAddr(0x4000000).waddr(),
                shift,
                value: Change {
                    before: prev_mem_value,
                    after: sb(prev_mem_value, rs2_word, shift),
                },
                previous_cycle: 4,
            },
            8,
        ),
    ])
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        &[insn_code],
        None,
        Some(lkm),
    );
}

#[test]
fn test_sb() {
    impl_opcode_sb(0);
    impl_opcode_sb(1);
    impl_opcode_sb(2);
    impl_opcode_sb(3);
}
