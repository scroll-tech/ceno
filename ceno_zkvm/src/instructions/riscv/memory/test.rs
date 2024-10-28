use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            memory::{
                LwInstruction, SbInstruction, ShInstruction, SwInstruction,
                load::{
                    LbInstruction, LbOp, LbuInstruction, LbuOp, LhInstruction, LhOp,
                    LhuInstruction, LhuOp, LwOp,
                },
                store::{SBOp, SHOp, SWOp},
            },
        },
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
};
use ceno_emul::{ByteAddr, Change, InsnKind, ReadOp, StepRecord, Word, WriteOp, encode_rv32};
use ff_ext::ExtensionField;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;
use std::hash::Hash;

fn sb(prev: Word, rs2: Word, shift: u32) -> Word {
    let shift = (shift * 8) as usize;
    let mut data = prev;
    data ^= data & (0xff << shift);
    data |= (rs2 & 0xff) << shift;

    data
}

fn sh(prev: Word, rs2: Word, shift: u32) -> Word {
    assert_eq!(shift & 1, 0);
    let shift = (shift * 8) as usize;
    let mut data = prev;

    data ^= data & (0xffff << shift);
    data |= (rs2 & 0xffff) << shift;

    data
}

fn sw(_prev: Word, rs2: Word) -> Word {
    rs2
}

fn signed_extend(val: u32, n_bits: u32) -> u32 {
    match n_bits {
        8 => (val as i8) as u32,
        16 => (val as i16) as u32,
        _ => unreachable!("unsupported n_bits = {}", n_bits),
    }
}

fn load(mem_value: Word, insn: InsnKind, shift: u32) -> Word {
    let val = mem_value >> (8 * shift);
    match insn {
        InsnKind::LB => signed_extend(val & 0xff_u32, 8),
        InsnKind::LBU => val & 0xff_u32,
        InsnKind::LH => {
            assert_eq!(shift & 0x01, 0);
            signed_extend(val & 0xffff_u32, 16)
        }
        InsnKind::LHU => {
            assert_eq!(shift & 0x01, 0);
            val & 0xffff_u32
        }
        InsnKind::LW => {
            assert_eq!(shift & 0x03, 0);
            mem_value
        }
        _ => unreachable!(),
    }
}

fn impl_opcode_store<E: ExtensionField + Hash, I: RIVInstruction, Inst: Instruction<E>>(imm: u32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || Inst::name(),
            |cb| {
                let config = Inst::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(I::INST_KIND, 2, 3, 0, imm);
    let prev_mem_value = 0x40302010;
    let rs2_word = Word::from(0x12345678_u32);
    let rs1_word = Word::from(0x4000000_u32);
    let unaligned_addr = ByteAddr::from(rs1_word.wrapping_add(imm));
    let new_mem_value = match I::INST_KIND {
        InsnKind::SB => sb(prev_mem_value, rs2_word, unaligned_addr.shift()),
        InsnKind::SH => sh(prev_mem_value, rs2_word, unaligned_addr.shift()),
        InsnKind::SW => sw(prev_mem_value, rs2_word),
        x => unreachable!("{:?} is not store instruction", x),
    };
    let (raw_witin, lkm) = Inst::assign_instances(&config, cb.cs.num_witin as usize, vec![
        StepRecord::new_s_instruction(
            12,
            MOCK_PC_START,
            insn_code,
            rs1_word,
            rs2_word,
            WriteOp {
                addr: unaligned_addr.waddr(),
                value: Change {
                    before: prev_mem_value,
                    after: new_mem_value,
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

fn impl_opcode_load<E: ExtensionField + Hash, I: RIVInstruction, Inst: Instruction<E>>(imm: u32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || Inst::name(),
            |cb| {
                let config = Inst::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(I::INST_KIND, 2, 3, 0, imm);
    let mem_value = 0x40302010;
    let rs1_word = Word::from(0x4000000_u32);
    let prev_rd_word = Word::from(0x12345678_u32);
    let unaligned_addr = ByteAddr::from(rs1_word.wrapping_add(imm));
    let new_rd_word = load(mem_value, I::INST_KIND, unaligned_addr.shift());
    let rd_change = Change {
        before: prev_rd_word,
        after: new_rd_word,
    };
    let (raw_witin, lkm) = Inst::assign_instances(&config, cb.cs.num_witin as usize, vec![
        StepRecord::new_im_instruction(
            12,
            MOCK_PC_START,
            insn_code,
            rs1_word,
            rd_change,
            ReadOp {
                addr: unaligned_addr.waddr(),
                value: mem_value,
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

fn impl_opcode_sb(imm: u32) {
    impl_opcode_store::<GoldilocksExt2, SBOp, SbInstruction<GoldilocksExt2>>(imm)
}

fn impl_opcode_sh(imm: u32) {
    assert_eq!(imm & 0x01, 0);
    impl_opcode_store::<GoldilocksExt2, SHOp, ShInstruction<GoldilocksExt2>>(imm)
}

fn impl_opcode_sw(imm: u32) {
    assert_eq!(imm & 0x03, 0);
    impl_opcode_store::<GoldilocksExt2, SWOp, SwInstruction<GoldilocksExt2>>(imm)
}

#[test]
fn test_sb() {
    impl_opcode_sb(0);
    impl_opcode_sb(5);
    impl_opcode_sb(10);
    impl_opcode_sb(15);

    let neg_one = u32::MAX;
    for i in 0..4 {
        impl_opcode_sb(neg_one - i);
    }
}

#[test]
fn test_sh() {
    impl_opcode_sh(0);
    impl_opcode_sh(2);

    let neg_two = u32::MAX - 1;
    for i in [0, 2] {
        impl_opcode_sh(neg_two - i)
    }
}

#[test]
fn test_sw() {
    impl_opcode_sw(0);
    impl_opcode_sw(4);

    let neg_four = u32::MAX - 3;
    impl_opcode_sw(neg_four);
}

#[test]
fn test_lb() {
    impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(0);
    impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(1);
    impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(2);
    impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(3);

    let neg_one = u32::MAX;
    // imm = -1, -2, -3
    for i in 0..3 {
        impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(neg_one - i);
    }
}

#[test]
fn test_lbu() {
    impl_opcode_load::<GoldilocksExt2, LbuOp, LbuInstruction<GoldilocksExt2>>(0);
    impl_opcode_load::<GoldilocksExt2, LbuOp, LbuInstruction<GoldilocksExt2>>(1);
    impl_opcode_load::<GoldilocksExt2, LbuOp, LbuInstruction<GoldilocksExt2>>(2);
    impl_opcode_load::<GoldilocksExt2, LbuOp, LbuInstruction<GoldilocksExt2>>(3);

    let neg_one = u32::MAX;
    // imm = -1, -2, -3
    for i in 0..3 {
        impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(neg_one - i);
    }
}

#[test]
fn test_lh() {
    impl_opcode_load::<GoldilocksExt2, LhOp, LhInstruction<GoldilocksExt2>>(0);
    impl_opcode_load::<GoldilocksExt2, LhOp, LhInstruction<GoldilocksExt2>>(2);
    impl_opcode_load::<GoldilocksExt2, LhOp, LhInstruction<GoldilocksExt2>>(4);

    let neg_two = u32::MAX - 1;
    // imm = -2, -4
    for i in [0, 2] {
        impl_opcode_load::<GoldilocksExt2, LhOp, LhInstruction<GoldilocksExt2>>(neg_two - i);
    }
}

#[test]
fn test_lhu() {
    impl_opcode_load::<GoldilocksExt2, LhuOp, LhuInstruction<GoldilocksExt2>>(0);
    impl_opcode_load::<GoldilocksExt2, LhuOp, LhuInstruction<GoldilocksExt2>>(2);
    impl_opcode_load::<GoldilocksExt2, LhuOp, LhuInstruction<GoldilocksExt2>>(4);

    let neg_two = u32::MAX - 1;
    // imm = -2, -4
    for i in [0, 2] {
        impl_opcode_load::<GoldilocksExt2, LhuOp, LhuInstruction<GoldilocksExt2>>(neg_two - i);
    }
}

#[test]
fn test_lw() {
    impl_opcode_load::<GoldilocksExt2, LwOp, LwInstruction<GoldilocksExt2>>(0);
    impl_opcode_load::<GoldilocksExt2, LwOp, LwInstruction<GoldilocksExt2>>(4);
    impl_opcode_load::<GoldilocksExt2, LwOp, LwInstruction<GoldilocksExt2>>(u32::MAX - 3); // imm = -4
}
