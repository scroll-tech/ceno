// Based on: https://github.com/risc0/risc0/blob/aeea62f0c8f4223abfba17d4c78cb7e15c513de2/risc0/circuit/rv32im/src/prove/emu/rv32im.rs
//
// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Result, anyhow};
use std::sync::OnceLock;
use strum_macros::EnumIter;

use super::addr::{ByteAddr, RegIdx, WORD_SIZE, Word, WordAddr};

pub trait EmuContext {
    // Handle environment call
    fn ecall(&mut self) -> Result<bool>;

    // Handle a trap
    fn trap(&self, cause: TrapCause) -> Result<bool>;

    // Callback when instructions end normally
    fn on_normal_end(&mut self, _decoded: &DecodedInstruction) {}

    // Get the program counter
    fn get_pc(&self) -> ByteAddr;

    // Set the program counter
    fn set_pc(&mut self, addr: ByteAddr);

    // Load from a register
    fn load_register(&mut self, idx: RegIdx) -> Result<Word>;

    // Store to a register
    fn store_register(&mut self, idx: RegIdx, data: Word) -> Result<()>;

    // Load from memory
    fn load_memory(&mut self, addr: WordAddr) -> Result<Word>;

    // Store to memory
    fn store_memory(&mut self, addr: WordAddr, data: Word) -> Result<()>;

    // Get the value of a register without side-effects.
    fn peek_register(&self, idx: RegIdx) -> Word;

    // Get the value of a memory word without side-effects.
    fn peek_memory(&self, addr: WordAddr) -> Word;

    // Load from memory, in the context of instruction fetching.
    // TODO: figure out how to return a reference.
    fn fetch(&mut self, pc: WordAddr) -> Result<DecodedInstruction>;

    // Check access for instruction load
    fn check_insn_load(&self, _addr: ByteAddr) -> bool {
        true
    }

    // Check access for data load
    fn check_data_load(&self, _addr: ByteAddr) -> bool {
        true
    }

    // Check access for data store
    fn check_data_store(&self, _addr: ByteAddr) -> bool {
        true
    }
}

/// An implementation of the basic ISA (RV32IM), that is instruction decoding and functional units.
pub struct Emulator {}

#[derive(Debug)]
pub enum TrapCause {
    InstructionAddressMisaligned,
    InstructionAccessFault,
    IllegalInstruction(u32),
    Breakpoint,
    LoadAddressMisaligned,
    LoadAccessFault(ByteAddr),
    StoreAddressMisaligned(ByteAddr),
    StoreAccessFault,
    EcallError,
}

#[derive(Clone, Debug, Default)]
struct DecodedInstructionOld {
    insn: u32,
    // TOP bit only has an impact on imm, it seems.
    // So use it there.
    top_bit: u32,
    // The bit fields of the instruction encoding, regardless of the instruction format.
    func7: u32,
    rs2: u32,
    rs1: u32,
    func3: u32,
    rd: u32,
    opcode: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct DecodedInstruction {
    // insn: u32,
    // This should be able to handle i32::MIN to u32::MAX.
    // Convert to field type in the straightforward way.
    pub imm: i64,
    pub rs1: u32,
    pub rs2: u32,
    pub rd: u32,
    pub kind: InsnKind,

    // This should only be her for debugging.
    #[allow(dead_code)]
    pub insn: u32,
}

#[derive(Clone, Copy, Debug)]
enum InsnCategory {
    Compute,
    Branch,
    Load,
    Store,
    System,
    Invalid,
}
use InsnCategory::*;

#[derive(Clone, Copy, Debug)]
pub enum InsnFormat {
    R,
    I,
    S,
    B,
    U,
    J,
}
use InsnFormat::*;

#[derive(Clone, Copy, Debug, PartialEq, EnumIter)]
#[allow(clippy::upper_case_acronyms)]
pub enum InsnKind {
    INVALID,
    ADD,
    SUB,
    XOR,
    OR,
    AND,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,
    ADDI,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    SLTI,
    SLTIU,
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    JAL,
    JALR,
    LUI,
    AUIPC,
    MUL,
    MULH,
    MULHSU,
    MULHU,
    DIV,
    DIVU,
    REM,
    REMU,
    LB,
    LH,
    LW,
    LBU,
    LHU,
    SB,
    SH,
    SW,
    /// ECALL and EBREAK etc.
    EANY,
}
use InsnKind::*;

impl InsnKind {
    pub const fn codes(self) -> InsnCodes {
        RV32IM_ISA[self as usize]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InsnCodes {
    pub format: InsnFormat,
    pub kind: InsnKind,
    pub opcode: u32,
    pub func3: u32,
    pub func7: u32,
}

impl From<DecodedInstructionOld> for DecodedInstruction {
    fn from(d: DecodedInstructionOld) -> Self {
        DecodedInstruction::new(d.insn)
    }
}

impl From<u32> for DecodedInstruction {
    fn from(word: u32) -> Self {
        DecodedInstruction::new(word)
    }
}

impl DecodedInstruction {
    /// A virtual register which absorbs the writes to x0.
    pub const RD_NULL: u32 = 32;

    pub fn new(insn: u32) -> Self {
        let d = DecodedInstructionOld::new(insn);
        let InsnCodes { kind, format, .. } = d.codes();

        let imm = match (format, kind) {
            (R, _) => 0,
            // decode the shift as a multiplication/division by 1 << immediate
            (I, SLLI | SRLI | SRAI) => (1 << d.imm_shamt()).into(),
            (I, SLTI) => (d.imm_i() as i32).into(),
            // EBREAK and ECALL ain't actually I-type in the spec, but it's convenient to pretend.
            (I, EANY) => d.rs1.into(),
            (I, _) => d.imm_i().into(),
            (S, _) => d.imm_s().into(),
            (B, _) => d.imm_b().into(),
            (U, _) => d.imm_u().into(),
            (J, _) => d.imm_j().into(),
        };
        let rs1 = match (format, kind) {
            (_, EANY) => 0,
            (R | I | S | B, _) => d.rs1,
            (U | J, _) => 0,
        };
        let rs2 = match (format, kind) {
            (R | S | B, _) | (_, EANY) => 0,
            (I | U | J, _) => d.rs2,
        };
        let rd = match (format, d.rd) {
            (R | I | U | J, 0) => Self::RD_NULL,
            (R | I | U | J, rd) => rd,
            (S | B, _) => 0,
        };
        let kind = d.codes().kind;
        Self {
            imm,
            rs1,
            rs2,
            rd,
            kind,
            insn,
        }
    }
}

impl DecodedInstructionOld {
    pub fn new(insn: u32) -> Self {
        Self {
            insn,
            top_bit: (insn & 0x80000000) >> 31,
            func7: (insn & 0xfe000000) >> 25,
            rs2: (insn & 0x01f00000) >> 20,
            rs1: (insn & 0x000f8000) >> 15,
            func3: (insn & 0x00007000) >> 12,
            rd: (insn & 0x00000f80) >> 7,
            opcode: insn & 0x0000007f,
        }
    }

    pub fn codes(&self) -> InsnCodes {
        FastDecodeTable::get().lookup(self)
    }

    fn imm_b(&self) -> u32 {
        (self.top_bit * 0xfffff000)
            | ((self.rd & 1) << 11)
            | ((self.func7 & 0x3f) << 5)
            | (self.rd & 0x1e)
    }

    fn imm_i(&self) -> u32 {
        (self.top_bit * 0xffff_f000) | (self.func7 << 5) | self.rs2
    }

    /// Shift amount field of SLLI, SRLI, SRAI.
    fn imm_shamt(&self) -> u32 {
        self.rs2
    }

    fn imm_s(&self) -> u32 {
        (self.top_bit * 0xfffff000) | (self.func7 << 5) | self.rd
    }

    fn imm_j(&self) -> u32 {
        (self.top_bit * 0xfff00000)
            | (self.rs1 << 15)
            | (self.func3 << 12)
            | ((self.rs2 & 1) << 11)
            | ((self.func7 & 0x3f) << 5)
            | (self.rs2 & 0x1e)
    }

    fn imm_u(&self) -> u32 {
        self.insn & 0xfffff000
    }
}

const fn insn(
    format: InsnFormat,
    kind: InsnKind,
    _category: InsnCategory,
    opcode: u32,
    func3: i32,
    func7: i32,
) -> InsnCodes {
    InsnCodes {
        format,
        kind,
        opcode,
        func3: func3 as u32,
        func7: func7 as u32,
    }
}

impl From<InsnKind> for InsnCategory {
    fn from(kind: InsnKind) -> Self {
        // TODO: double check this.
        // Perhaps get it via a macro from RV32IM_ISA.
        match kind {
            INVALID => Invalid,
            ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHSU
            | MULHU | DIV | DIVU | REM | REMU => Compute,
            ADDI | XORI | ORI | ANDI | SLLI | SRLI | SRAI | SLTI | SLTIU => Compute,
            BEQ | BNE | BLT | BGE | BLTU | BGEU => Branch,
            JAL | JALR => Compute,
            LUI | AUIPC => Compute,
            LB | LH | LW | LBU | LHU => Load,
            SB | SH | SW => Store,
            EANY => System,
        }
    }
}

type InstructionTable = [InsnCodes; 47];
type FastInstructionTable = [u8; 1 << 10];

const RV32IM_ISA: InstructionTable = [
    insn(R, INVALID, Invalid, 0x00, 0x0, 0x00),
    insn(R, ADD, Compute, 0x33, 0x0, 0x00),
    insn(R, SUB, Compute, 0x33, 0x0, 0x20),
    insn(R, XOR, Compute, 0x33, 0x4, 0x00),
    insn(R, OR, Compute, 0x33, 0x6, 0x00),
    insn(R, AND, Compute, 0x33, 0x7, 0x00),
    insn(R, SLL, Compute, 0x33, 0x1, 0x00),
    insn(R, SRL, Compute, 0x33, 0x5, 0x00),
    insn(R, SRA, Compute, 0x33, 0x5, 0x20),
    insn(R, SLT, Compute, 0x33, 0x2, 0x00),
    insn(R, SLTU, Compute, 0x33, 0x3, 0x00),
    insn(I, ADDI, Compute, 0x13, 0x0, -1),
    insn(I, XORI, Compute, 0x13, 0x4, -1),
    insn(I, ORI, Compute, 0x13, 0x6, -1),
    insn(I, ANDI, Compute, 0x13, 0x7, -1),
    insn(I, SLLI, Compute, 0x13, 0x1, 0x00),
    insn(I, SRLI, Compute, 0x13, 0x5, 0x00),
    insn(I, SRAI, Compute, 0x13, 0x5, 0x20),
    insn(I, SLTI, Compute, 0x13, 0x2, -1),
    insn(I, SLTIU, Compute, 0x13, 0x3, -1),
    insn(B, BEQ, Branch, 0x63, 0x0, -1),
    insn(B, BNE, Branch, 0x63, 0x1, -1),
    insn(B, BLT, Branch, 0x63, 0x4, -1),
    insn(B, BGE, Branch, 0x63, 0x5, -1),
    insn(B, BLTU, Branch, 0x63, 0x6, -1),
    insn(B, BGEU, Branch, 0x63, 0x7, -1),
    insn(J, JAL, Compute, 0x6f, -1, -1),
    insn(I, JALR, Compute, 0x67, 0x0, -1),
    insn(U, LUI, Compute, 0x37, -1, -1),
    insn(U, AUIPC, Compute, 0x17, -1, -1),
    insn(R, MUL, Compute, 0x33, 0x0, 0x01),
    insn(R, MULH, Compute, 0x33, 0x1, 0x01),
    insn(R, MULHSU, Compute, 0x33, 0x2, 0x01),
    insn(R, MULHU, Compute, 0x33, 0x3, 0x01),
    insn(R, DIV, Compute, 0x33, 0x4, 0x01),
    insn(R, DIVU, Compute, 0x33, 0x5, 0x01),
    insn(R, REM, Compute, 0x33, 0x6, 0x01),
    insn(R, REMU, Compute, 0x33, 0x7, 0x01),
    insn(I, LB, Load, 0x03, 0x0, -1),
    insn(I, LH, Load, 0x03, 0x1, -1),
    insn(I, LW, Load, 0x03, 0x2, -1),
    insn(I, LBU, Load, 0x03, 0x4, -1),
    insn(I, LHU, Load, 0x03, 0x5, -1),
    insn(S, SB, Store, 0x23, 0x0, -1),
    insn(S, SH, Store, 0x23, 0x1, -1),
    insn(S, SW, Store, 0x23, 0x2, -1),
    // TODO: EANY is just an artifact of our previous approach to decoding.
    // Replace with ECALL and EBREAK
    // They are not actually I types in the spec, but it's convenient to pretend.
    insn(I, EANY, System, 0x73, 0x0, 0x00),
];

#[cfg(test)]
#[test]
fn test_isa_table() {
    use strum::IntoEnumIterator;
    for kind in InsnKind::iter() {
        assert_eq!(kind.codes().kind, kind);
    }
}

// RISC-V instruction are determined by 3 parts:
// - Opcode: 7 bits
// - Func3: 3 bits
// - Func7: 7 bits
// In many cases, func7 and/or func3 is ignored.  A standard trick is to decode
// via a table, but a 17 bit lookup table destroys L1 cache.  Luckily for us,
// in practice the low 2 bits of opcode are always 11, so we can drop them, and
// also func7 is always either 0, 1, 0x20 or don't care, so we can reduce func7
// to 2 bits, which gets us to 10 bits, which is only 1k.
struct FastDecodeTable {
    table: FastInstructionTable,
}

impl FastDecodeTable {
    fn new() -> Self {
        let mut table: FastInstructionTable = [0; 1 << 10];
        for (isa_idx, insn) in RV32IM_ISA.iter().enumerate() {
            Self::add_insn(&mut table, insn, isa_idx);
        }
        Self { table }
    }

    fn get() -> &'static Self {
        FAST_DECODE_TABLE.get_or_init(Self::new)
    }

    // Map to 10 bit format
    fn map10(opcode: u32, func3: u32, func7: u32) -> usize {
        let op_high = opcode >> 2;
        // Map 0 -> 0, 1 -> 1, 0x20 -> 2, everything else to 3
        let func72bits = if func7 <= 1 {
            func7
        } else if func7 == 0x20 {
            2
        } else {
            3
        };
        ((op_high << 5) | (func72bits << 3) | func3) as usize
    }

    fn add_insn(table: &mut FastInstructionTable, insn: &InsnCodes, isa_idx: usize) {
        let op_high = insn.opcode >> 2;
        if (insn.func3 as i32) < 0 {
            for f3 in 0..8 {
                for f7b in 0..4 {
                    let idx = (op_high << 5) | (f7b << 3) | f3;
                    table[idx as usize] = isa_idx as u8;
                }
            }
        } else if (insn.func7 as i32) < 0 {
            for f7b in 0..4 {
                let idx = (op_high << 5) | (f7b << 3) | insn.func3;
                table[idx as usize] = isa_idx as u8;
            }
        } else {
            table[Self::map10(insn.opcode, insn.func3, insn.func7)] = isa_idx as u8;
        }
    }

    fn lookup(&self, decoded: &DecodedInstructionOld) -> InsnCodes {
        let isa_idx = self.table[Self::map10(decoded.opcode, decoded.func3, decoded.func7)];
        RV32IM_ISA[isa_idx as usize]
    }
}

static FAST_DECODE_TABLE: OnceLock<FastDecodeTable> = OnceLock::new();

impl Emulator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn step<C: EmuContext>(&self, ctx: &mut C) -> Result<()> {
        let pc = ctx.get_pc();

        if !ctx.check_insn_load(pc) {
            ctx.trap(TrapCause::InstructionAccessFault)?;
            return Err(anyhow!("Fatal: could not fetch instruction at pc={:?}", pc));
        }

        let insn = ctx.fetch(pc.waddr())?;
        // if word & 0x03 != 0x03 {
        //     // Opcode must end in 0b11 in RV32IM.
        //     ctx.trap(TrapCause::IllegalInstruction(word))?;
        //     return Err(anyhow!(
        //         "Fatal: illegal instruction at pc={:?}: 0x{:08x}",
        //         pc,
        //         word
        //     ));
        // }

        // TODO: decode once at the beginning, instead of all the time like here.
        // let insn = DecodedInstruction::new(word);
        tracing::trace!("pc: {:x}, kind: {:?}", pc.0, insn.kind);

        if match insn.kind.into() {
            InsnCategory::Compute => self.step_compute(ctx, &insn)?,
            InsnCategory::Branch => self.step_branch(ctx, &insn)?,
            InsnCategory::Load => self.step_load(ctx, &insn)?,
            InsnCategory::Store => self.step_store(ctx, &insn)?,
            InsnCategory::System => self.step_system(ctx, &insn)?,
            InsnCategory::Invalid => ctx.trap(TrapCause::IllegalInstruction(insn.insn))?,
        } {
            ctx.on_normal_end(&insn);
        };

        Ok(())
    }

    fn step_compute<M: EmuContext>(
        &self,
        ctx: &mut M,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        use InsnKind::*;

        let pc = ctx.get_pc();
        let mut new_pc = pc + WORD_SIZE;

        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        let rs2 = ctx.load_register(decoded.rs2 as usize)?;
        let imm = decoded.imm;

        let out = match decoded.kind {
            // Instructions that do not read rs1 nor rs2.
            JAL => {
                new_pc = pc.wrapping_add(imm as u32);
                (pc + WORD_SIZE).0
            }
            // TODO: consider using better types for imm,
            // perhaps an enum with kind, so we can avoid the cast.
            LUI => decoded.imm as u32,
            AUIPC => (pc.wrapping_add(imm as u32)).0,

            ADDI => rs1.wrapping_add(imm as u32),
            XORI => rs1 ^ imm as u32,
            ORI => rs1 | imm as u32,
            ANDI => rs1 & imm as u32,
            SLLI => rs1 << imm,
            SRLI => rs1 >> imm,
            SRAI => ((rs1 as i32) >> imm) as u32,
            SLTI => {
                if (rs1 as i32) < (imm as i32) {
                    1
                } else {
                    0
                }
            }
            SLTIU => (rs1 < imm as u32).into(),
            JALR => {
                new_pc = ByteAddr(rs1.wrapping_add(imm as u32) & !1);
                (pc + WORD_SIZE).0
            }

            ADD => rs1.wrapping_add(rs2),
            SUB => rs1.wrapping_sub(rs2),
            XOR => rs1 ^ rs2,
            OR => rs1 | rs2,
            AND => rs1 & rs2,
            SLL => rs1 << (rs2 & 0x1f),
            SRL => rs1 >> (rs2 & 0x1f),
            SRA => ((rs1 as i32) >> (rs2 & 0x1f)) as u32,
            SLT => {
                if (rs1 as i32) < (rs2 as i32) {
                    1
                } else {
                    0
                }
            }
            SLTU => {
                if rs1 < rs2 {
                    1
                } else {
                    0
                }
            }
            MUL => rs1.wrapping_mul(rs2),
            MULH => (sign_extend_u32(rs1).wrapping_mul(sign_extend_u32(rs2)) >> 32) as u32,
            MULHSU => (sign_extend_u32(rs1).wrapping_mul(rs2 as i64) >> 32) as u32,
            MULHU => (((rs1 as u64).wrapping_mul(rs2 as u64)) >> 32) as u32,
            DIV => {
                if rs2 == 0 {
                    u32::MAX
                } else {
                    ((rs1 as i32).wrapping_div(rs2 as i32)) as u32
                }
            }
            DIVU => {
                if rs2 == 0 {
                    u32::MAX
                } else {
                    rs1 / rs2
                }
            }
            REM => {
                if rs2 == 0 {
                    rs1
                } else {
                    ((rs1 as i32).wrapping_rem(rs2 as i32)) as u32
                }
            }
            REMU => {
                if rs2 == 0 {
                    rs1
                } else {
                    rs1 % rs2
                }
            }
            _ => unreachable!("Illegal compute instruction: {:?}", decoded),
        };
        if !new_pc.is_aligned() {
            return ctx.trap(TrapCause::InstructionAddressMisaligned);
        }
        ctx.store_register(decoded.rd as usize, out)?;
        ctx.set_pc(new_pc);
        Ok(true)
    }

    fn step_branch<M: EmuContext>(
        &self,
        ctx: &mut M,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        use InsnKind::*;

        let pc = ctx.get_pc();
        let rs1 = ctx.load_register(decoded.rs1 as RegIdx)?;
        let rs2 = ctx.load_register(decoded.rs2 as RegIdx)?;

        let taken = match decoded.kind {
            BEQ => rs1 == rs2,
            BNE => rs1 != rs2,
            BLT => (rs1 as i32) < (rs2 as i32),
            BGE => (rs1 as i32) >= (rs2 as i32),
            BLTU => rs1 < rs2,
            BGEU => rs1 >= rs2,
            _ => unreachable!("Illegal branch instruction: {:?}", decoded.kind),
        };

        let new_pc = if taken {
            pc.wrapping_add(decoded.imm as u32)
        } else {
            pc + WORD_SIZE
        };

        if !new_pc.is_aligned() {
            return ctx.trap(TrapCause::InstructionAddressMisaligned);
        }
        ctx.set_pc(new_pc);
        Ok(true)
    }

    fn step_load<M: EmuContext>(&self, ctx: &mut M, decoded: &DecodedInstruction) -> Result<bool> {
        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        // LOAD instructions do not read rs2.
        let addr = ByteAddr(rs1.wrapping_add(decoded.imm as u32));
        if !ctx.check_data_load(addr) {
            return ctx.trap(TrapCause::LoadAccessFault(addr));
        }
        let data = ctx.load_memory(addr.waddr())?;
        let shift = 8 * (addr.0 & 3);
        let out = match decoded.kind {
            InsnKind::LB => {
                let mut out = (data >> shift) & 0xff;
                if out & 0x80 != 0 {
                    out |= 0xffffff00;
                }
                out
            }
            InsnKind::LH => {
                if addr.0 & 0x01 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                let mut out = (data >> shift) & 0xffff;
                if out & 0x8000 != 0 {
                    out |= 0xffff0000;
                }
                out
            }
            InsnKind::LW => {
                if addr.0 & 0x03 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                data
            }
            InsnKind::LBU => (data >> shift) & 0xff,
            InsnKind::LHU => {
                if addr.0 & 0x01 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                (data >> shift) & 0xffff
            }
            _ => unreachable!(),
        };
        ctx.store_register(decoded.rd as usize, out)?;
        ctx.set_pc(ctx.get_pc() + WORD_SIZE);
        Ok(true)
    }

    fn step_store<M: EmuContext>(&self, ctx: &mut M, decoded: &DecodedInstruction) -> Result<bool> {
        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        let rs2 = ctx.load_register(decoded.rs2 as usize)?;
        let addr = ByteAddr(rs1.wrapping_add(decoded.imm as u32));
        let shift = 8 * (addr.0 & 3);
        if !ctx.check_data_store(addr) {
            tracing::error!("mstore: addr={:x?},rs1={:x}", addr, rs1);
            return ctx.trap(TrapCause::StoreAccessFault);
        }
        let mut data = ctx.peek_memory(addr.waddr());
        match decoded.kind {
            InsnKind::SB => {
                data ^= data & (0xff << shift);
                data |= (rs2 & 0xff) << shift;
            }
            InsnKind::SH => {
                if addr.0 & 0x01 != 0 {
                    tracing::debug!("Misaligned SH");
                    return ctx.trap(TrapCause::StoreAddressMisaligned(addr));
                }
                data ^= data & (0xffff << shift);
                data |= (rs2 & 0xffff) << shift;
            }
            InsnKind::SW => {
                if addr.0 & 0x03 != 0 {
                    tracing::debug!("Misaligned SW");
                    return ctx.trap(TrapCause::StoreAddressMisaligned(addr));
                }
                data = rs2;
            }
            _ => unreachable!(),
        }
        ctx.store_memory(addr.waddr(), data)?;
        ctx.set_pc(ctx.get_pc() + WORD_SIZE);
        Ok(true)
    }

    fn step_system<M: EmuContext>(
        &self,
        ctx: &mut M,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        match decoded.kind {
            // TODO(Matthias): this is silly.  Catch illegal instructions in the decode stage.
            InsnKind::EANY => match decoded.imm {
                0 => ctx.ecall(),
                1 => ctx.trap(TrapCause::Breakpoint),
                _ => ctx.trap(TrapCause::IllegalInstruction(decoded.insn)),
            },
            _ => unreachable!(),
        }
    }
}

fn sign_extend_u32(x: u32) -> i64 {
    (x as i32) as i64
}
