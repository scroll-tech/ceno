#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::memory::LoadStoreWordInstruction;
use crate::{
    Value,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::ShardContext,
    instructions::{
        Instruction,
        riscv::{
            LbInstruction, LbuInstruction, LhInstruction, LhuInstruction, RIVInstruction,
            constants::UInt,
            memory::{LbOp, LbuOp, LhOp, LhuOp, SBOp, SHOp, SbInstruction, ShInstruction},
        },
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
    structs::ProgramParams,
};
use ceno_emul::{
    ByteAddr, Change, InsnKind, InsnKind::SW, ReadOp, StepRecord, Word, WriteOp, encode_rv32,
};
#[cfg(feature = "u16limb_circuit")]
use ff_ext::BabyBearExt4;
use ff_ext::{ExtensionField, GoldilocksExt2};
use gkr_iop::circuit_builder::DebugIndex;
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

fn impl_opcode_store<E: ExtensionField + Hash, I: RIVInstruction, Inst: Instruction<E>>(imm: i32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || Inst::name(),
            |cb| {
                let config = Inst::construct_circuit(cb, &ProgramParams::default());
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(I::INST_KIND, 2, 3, 0, imm);
    let prev_mem_value = 0x40302010;
    let rs2_word = Word::from(0x12345678_u32);
    let rs1_word = Word::from(0x4000000_u32);
    let unaligned_addr = ByteAddr::from(rs1_word.wrapping_add_signed(imm));
    let new_mem_value = match I::INST_KIND {
        InsnKind::SB => sb(prev_mem_value, rs2_word, unaligned_addr.shift()),
        InsnKind::SH => sh(prev_mem_value, rs2_word, unaligned_addr.shift()),
        InsnKind::SW => sw(prev_mem_value, rs2_word),
        x => unreachable!("{:?} is not store instruction", x),
    };
    let (raw_witin, lkm) = Inst::assign_instances(
        &config,
        &mut ShardContext::default(),
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
        &[StepRecord::new_s_instruction(
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
        )],
    )
    .unwrap();

    // verify mem_write
    let expected_mem_written =
        UInt::from_const_unchecked(Value::new_unchecked(new_mem_value).as_u16_limbs().to_vec());
    let mem_written_expr = cb.get_debug_expr(DebugIndex::MemWrite as usize)[0].clone();
    cb.require_equal(
        || "assert_mem_written",
        mem_written_expr,
        expected_mem_written.value(),
    )
    .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

#[cfg(feature = "u16limb_circuit")]
fn impl_opcode_store_word_dynamic<E: ExtensionField + Hash, Inst: Instruction<E>>(
    imm: i32,
    is_load: bool,
) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || Inst::name(),
            |cb| {
                let config = Inst::construct_circuit(cb, &ProgramParams::default());
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_kind = if is_load { InsnKind::LW } else { SW };
    let insn_code = encode_rv32(insn_kind, 2, 3, 0, imm);
    let rs1_word = Word::from(0x4000000_u32);
    let unaligned_addr = ByteAddr::from(rs1_word.wrapping_add_signed(imm));

    if is_load {
        let mem_value = 0x40302010;
        let prev_rd_word = Word::from(0x12345678_u32);
        let new_rd_word = load(mem_value, InsnKind::LW, unaligned_addr.shift());
        let rd_change = Change {
            before: prev_rd_word,
            after: new_rd_word,
        };
        let (raw_witin, lkm) = Inst::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &[StepRecord::new_im_instruction(
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
            )],
        )
        .unwrap();
        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    } else {
        let prev_mem_value = 0x40302010;
        let rs2_word = Word::from(0x12345678_u32);
        let new_mem_value = sw(prev_mem_value, rs2_word);
        let (raw_witin, lkm) = Inst::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &[StepRecord::new_s_instruction(
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
            )],
        )
        .unwrap();

        let expected_mem_written =
            UInt::from_const_unchecked(Value::new_unchecked(new_mem_value).as_u16_limbs().to_vec());
        let mem_written_expr = cb.get_debug_expr(DebugIndex::MemWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_mem_written",
            mem_written_expr,
            expected_mem_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}

fn impl_opcode_load<E: ExtensionField + Hash, I: RIVInstruction, Inst: Instruction<E>>(imm: i32) {
    let mut cs = ConstraintSystem::<E>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || Inst::name(),
            |cb| {
                let config = Inst::construct_circuit(cb, &ProgramParams::default());
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(I::INST_KIND, 2, 3, 0, imm);
    let mem_value = 0x40302010;
    let rs1_word = Word::from(0x4000000_u32);
    let prev_rd_word = Word::from(0x12345678_u32);
    let unaligned_addr = ByteAddr::from(rs1_word.wrapping_add_signed(imm));
    let new_rd_word = load(mem_value, I::INST_KIND, unaligned_addr.shift());
    let rd_change = Change {
        before: prev_rd_word,
        after: new_rd_word,
    };
    let (raw_witin, lkm) = Inst::assign_instances(
        &config,
        &mut ShardContext::default(),
        cb.cs.num_witin as usize,
        cb.cs.num_structural_witin as usize,
        &[StepRecord::new_im_instruction(
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
        )],
    )
    .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

fn impl_opcode_sb(imm: i32) {
    impl_opcode_store::<GoldilocksExt2, SBOp, SbInstruction<GoldilocksExt2>>(imm)
}

fn impl_opcode_sh(imm: i32) {
    assert_eq!(imm & 0x01, 0);
    impl_opcode_store::<GoldilocksExt2, SHOp, ShInstruction<GoldilocksExt2>>(imm)
}

fn impl_opcode_sw(imm: i32) {
    assert_eq!(imm & 0x03, 0);
    impl_opcode_store_word_dynamic::<GoldilocksExt2, LoadStoreWordInstruction<GoldilocksExt2>>(
        imm, false,
    );
    impl_opcode_store_word_dynamic::<BabyBearExt4, LoadStoreWordInstruction<BabyBearExt4>>(
        imm, false,
    );
}

fn impl_opcode_lw(imm: i32) {
    assert_eq!(imm & 0x03, 0);
    impl_opcode_store_word_dynamic::<GoldilocksExt2, LoadStoreWordInstruction<GoldilocksExt2>>(
        imm, true,
    );
    impl_opcode_store_word_dynamic::<BabyBearExt4, LoadStoreWordInstruction<BabyBearExt4>>(
        imm, true,
    );
}

#[test]
fn test_sb() {
    let cases = vec![(0,), (5,), (10,), (15,), (-4,), (-3,), (-2,), (-1,)];

    for &(imm,) in &cases {
        impl_opcode_sb(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_sb(imm);
    }
}

#[test]
fn test_sh() {
    let cases = vec![(0,), (2,), (-4,), (-2,)];

    for &(imm,) in &cases {
        impl_opcode_sh(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_sh(imm);
    }
}

#[test]
fn test_sw() {
    let cases = vec![(0,), (4,), (-4,)];

    for &(imm,) in &cases {
        impl_opcode_sw(imm);
    }
}

#[test]
fn test_lb() {
    let cases = vec![
        // positive immediates
        (0,),
        (1,),
        (2,),
        (3,),
        // negative immediates
        (-3,),
        (-2,),
        (-1,),
    ];

    for &(imm,) in &cases {
        impl_opcode_load::<GoldilocksExt2, LbOp, LbInstruction<GoldilocksExt2>>(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_load::<BabyBearExt4, LbOp, LbInstruction<BabyBearExt4>>(imm);
    }
}

#[test]
fn test_lbu() {
    let cases = vec![
        // positive immediates
        (0,),
        (1,),
        (2,),
        (3,),
        // negative immediates
        (-3,),
        (-2,),
        (-1,),
    ];

    for &(imm,) in &cases {
        impl_opcode_load::<GoldilocksExt2, LbuOp, LbuInstruction<GoldilocksExt2>>(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_load::<BabyBearExt4, LbuOp, LbuInstruction<BabyBearExt4>>(imm);
    }
}

#[test]
fn test_lh() {
    let cases = vec![
        // positive immediates
        (0,),
        (2,),
        (4,),
        // negative immediates
        (-4,),
        (-2,),
    ];

    for &(imm,) in &cases {
        impl_opcode_load::<GoldilocksExt2, LhOp, LhInstruction<GoldilocksExt2>>(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_load::<BabyBearExt4, LhOp, LhInstruction<BabyBearExt4>>(imm);
    }
}

#[test]
fn test_lhu() {
    let cases = vec![
        // positive immediates
        (0,),
        (2,),
        (4,),
        // negative immediates
        (-4,),
        (-2,),
    ];

    for &(imm,) in &cases {
        impl_opcode_load::<GoldilocksExt2, LhuOp, LhuInstruction<GoldilocksExt2>>(imm);
        #[cfg(feature = "u16limb_circuit")]
        impl_opcode_load::<BabyBearExt4, LhuOp, LhuInstruction<BabyBearExt4>>(imm);
    }
}

#[test]
fn test_lw() {
    let cases = vec![(0,), (4,), (-4,)];

    for &(imm,) in &cases {
        impl_opcode_lw(imm);
    }
}
