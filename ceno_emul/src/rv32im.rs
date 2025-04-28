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
use num_derive::ToPrimitive;
use strum_macros::{Display, EnumIter};

use super::addr::{ByteAddr, RegIdx, WORD_SIZE, Word, WordAddr};

/// Convenience function to create an `Instruction` with the given fields.
///
/// Pass 0 for unused fields.
pub const fn encode_rv32(kind: InsnKind, rs1: u32, rs2: u32, rd: u32, imm: i32) -> Instruction {
    Instruction {
        kind,
        rs1: rs1 as usize,
        rs2: rs2 as usize,
        rd: rd as usize,
        imm,
        raw: 0,
    }
}

/// Convenience function to create an `Instruction` with the given fields.
///
/// Pass 0 for unused fields.
pub const fn encode_rv32u(kind: InsnKind, rs1: u32, rs2: u32, rd: u32, imm: u32) -> Instruction {
    Instruction {
        kind,
        rs1: rs1 as usize,
        rs2: rs2 as usize,
        rd: rd as usize,
        imm: imm as i32,
        raw: 0,
    }
}

pub trait EmuContext {
    // Handle environment call
    fn ecall(&mut self) -> Result<bool>;

    // Handle a trap
    fn trap(&self, cause: TrapCause) -> Result<bool>;

    // Callback when instructions end normally
    fn on_normal_end(&mut self, _decoded: &Instruction) {}

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

    /// Load from instruction cache
    fn fetch(&mut self, pc: WordAddr) -> Option<Instruction>;

    // Check access for data load
    fn check_data_load(&self, _addr: ByteAddr) -> bool {
        true
    }

    // Check access for data store
    fn check_data_store(&self, _addr: ByteAddr) -> bool {
        true
    }
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instruction {
    pub kind: InsnKind,
    pub rs1: RegIdx,
    pub rs2: RegIdx,
    pub rd: RegIdx,
    pub imm: i32,
    /// `raw` is there only to produce better logging and error messages.
    ///
    /// Set to 0, if you are creating an instruction directly,
    /// instead of decoding it from a raw 32-bit `Word`.
    pub raw: Word,
}

#[derive(Clone, Copy, Debug)]
pub enum InsnCategory {
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

#[derive(
    Clone, Copy, Display, Debug, PartialEq, Eq, PartialOrd, Ord, EnumIter, ToPrimitive, Default,
)]
#[allow(clippy::upper_case_acronyms)]
pub enum InsnKind {
    #[default]
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
    ECALL,
}
use InsnKind::*;

impl InsnKind {
    /// Estimate the ratio of the instruction in a typical program.
    pub const fn estimate_ratio(&self) -> f32 {
        match self {
            // (XOR, 36492984, 237293968, 0.15378807),
            // (ADDI, 26925633, 237293968, 0.11346952),
            // (LW, 40824149, 237293968, 0.17204039),
            // (SW, 33497466, 237293968, 0.14116442),
            XOR | ADDI | LW | SW => 0.2,
            // (ADD, 3496512, 237293968, 0.014734939),
            // (OR, 15291990, 237293968, 0.06444323),
            // (XORI, 11578641, 237293968, 0.0487945),
            // (AND, 12291687, 237293968, 0.05179941),
            // (SLLI, 15187959, 237293968, 0.06400482),
            // (SRLI, 13713808, 237293968, 0.057792485),
            // (BNE, 3201033, 237293968, 0.013489736),
            // (BLTU, 6425555, 237293968, 0.027078459),
            // (LBU, 6248582, 237293968, 0.026332663),
            ADD | OR | XORI | AND | SLLI | SRLI | BNE | BLTU | LBU => 0.1,
            // (SUB, 953274, 237293968, 0.00401727),
            // (SLL, 337878, 237293968, 0.0014238794),
            // (SRL, 334623, 237293968, 0.0014101623),
            // (SLTU, 271558, 237293968, 0.0011443949),
            // (ANDI, 1502743, 237293968, 0.006332833),
            // (SLTIU, 262261, 237293968, 0.0011052156),
            // (BEQ, 1475804, 237293968, 0.006219307),
            // (BGE, 265599, 237293968, 0.0011192826),
            // (BGEU, 1311360, 237293968, 0.00552631),
            // (JAL, 596323, 237293968, 0.0025130138),
            // (JALR, 1214114, 237293968, 0.0051164976),
            // (MUL, 538041, 474587936, 0.0011337014),
            // (LB, 332518, 237293968, 0.0014012915),
            // (SB, 2230543, 237293968, 0.009399914),
            SUB | SLL | SRL | SLTU | ANDI | SLTIU | BEQ | BGE | BGEU | JAL | JALR | MUL | LB | SB => 0.01,
            // (SRAI, 24223, 237293968, 0.000102080136),
            // (BLT, 73253, 237293968, 0.00030870148),
            // (MULHU, 249549, 474587936, 0.00052582246),
            // (LH, 58508, 237293968, 0.00024656337),
            // (SH, 60086, 237293968, 0.00025321334),
            SRAI | BLT | MULHU | LH | SH => 0.001,
            // (SLTI, 2534, 237293968, 1.0678737e-5),
            // (LHU, 20597, 237293968, 8.679951e-5),
            SLTI | LHU => 1e-4,
            // (SLT, 680, 237293968, 2.8656439e-6),
            // (ORI, 633, 237293968, 2.6675773e-6),
            // (MULH, 996, 474587936, 2.0986627e-6),
            SLT | ORI | MULH => 1e-5,
            // (DIVU, 136, 949175872, 1.432822e-7),
            // (REMU, 136, 949175872, 1.432822e-7),
            DIVU | REMU => 1e-7,
            _ => 0.0,
        }
    }
}

impl From<InsnKind> for InsnCategory {
    fn from(kind: InsnKind) -> Self {
        match kind {
            INVALID => Invalid,
            ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHSU
            | MULHU | DIV | DIVU | REM | REMU => Compute,
            ADDI | XORI | ORI | ANDI | SLLI | SRLI | SRAI | SLTI | SLTIU => Compute,
            BEQ | BNE | BLT | BGE | BLTU | BGEU => Branch,
            JAL | JALR => Compute,
            LB | LH | LW | LBU | LHU => Load,
            SB | SH | SW => Store,
            ECALL => System,
        }
    }
}

// For encoding, which is useful for tests.
impl From<InsnKind> for InsnFormat {
    fn from(kind: InsnKind) -> Self {
        match kind {
            ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHSU
            | MULHU | DIV | DIVU | REM | REMU => R,
            ADDI | XORI | ORI | ANDI | SLLI | SRLI | SRAI | SLTI | SLTIU => I,
            BEQ | BNE | BLT | BGE | BLTU | BGEU => B,
            JAL => J,
            JALR => I,
            LB | LH | LW | LBU | LHU => I,
            SB | SH | SW => S,
            ECALL => I,
            INVALID => I,
        }
    }
}

impl Instruction {
    pub const RD_NULL: u32 = 32;
    pub fn rd_internal(&self) -> u32 {
        match InsnFormat::from(self.kind) {
            R | I | U | J if self.rd != 0 => self.rd as u32,
            _ => Self::RD_NULL,
        }
    }
    /// Get the register source 1, or zero if the instruction does not use rs1.
    pub fn rs1_or_zero(&self) -> u32 {
        match InsnFormat::from(self.kind) {
            R | I | S | B => self.rs1 as u32,
            _ => 0,
        }
    }
    /// Get the register source 2, or zero if the instruction does not use rs2.
    pub fn rs2_or_zero(&self) -> u32 {
        match InsnFormat::from(self.kind) {
            R | S | B => self.rs2 as u32,
            _ => 0,
        }
    }
}

pub fn step<C: EmuContext>(ctx: &mut C) -> Result<()> {
    let pc = ctx.get_pc();

    let Some(insn) = ctx.fetch(pc.waddr()) else {
        ctx.trap(TrapCause::InstructionAccessFault)?;
        return Err(anyhow!(
            "Fatal: could not fetch instruction at pc={pc:?}, ELF does not have instructions there."
        ));
    };

    tracing::trace!("pc: {:x}, kind: {:?}", pc.0, insn.kind);

    if match InsnCategory::from(insn.kind) {
        InsnCategory::Compute => step_compute(ctx, insn.kind, &insn)?,
        InsnCategory::Branch => step_branch(ctx, insn.kind, &insn)?,
        InsnCategory::Load => step_load(ctx, insn.kind, &insn)?,
        InsnCategory::Store => step_store(ctx, insn.kind, &insn)?,
        InsnCategory::System => step_system(ctx, insn.kind, &insn)?,
        InsnCategory::Invalid => ctx.trap(TrapCause::IllegalInstruction(insn.raw))?,
    } {
        ctx.on_normal_end(&insn);
    };

    Ok(())
}

fn step_compute<M: EmuContext>(ctx: &mut M, kind: InsnKind, insn: &Instruction) -> Result<bool> {
    use super::InsnKind::*;

    let pc = ctx.get_pc();
    let mut new_pc = pc + WORD_SIZE;
    let imm_i = insn.imm as u32;
    let out = match kind {
        // Instructions that do not read rs1 nor rs2.
        JAL => {
            new_pc = pc.wrapping_add(insn.imm as u32);
            (pc + WORD_SIZE).0
        }
        _ => {
            // Instructions that read rs1 but not rs2.
            let rs1 = ctx.load_register(insn.rs1)?;

            match kind {
                ADDI => rs1.wrapping_add(imm_i),
                XORI => rs1 ^ imm_i,
                ORI => rs1 | imm_i,
                ANDI => rs1 & imm_i,
                SLLI => rs1 << (imm_i & 0x1f),
                SRLI => rs1 >> (imm_i & 0x1f),
                SRAI => ((rs1 as i32) >> (imm_i & 0x1f)) as u32,
                SLTI => {
                    if (rs1 as i32) < (imm_i as i32) {
                        1
                    } else {
                        0
                    }
                }
                SLTIU => {
                    if rs1 < imm_i {
                        1
                    } else {
                        0
                    }
                }
                JALR => {
                    new_pc = ByteAddr(rs1.wrapping_add(imm_i) & !1);
                    (pc + WORD_SIZE).0
                }

                _ => {
                    // Instructions that use rs1 and rs2.
                    let rs2 = ctx.load_register(insn.rs2)?;

                    match kind {
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
                        MULH => {
                            (sign_extend_u32(rs1).wrapping_mul(sign_extend_u32(rs2)) >> 32) as u32
                        }
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

                        _ => unreachable!("Illegal compute instruction: {:?}", kind),
                    }
                }
            }
        }
    };
    if !new_pc.is_aligned() {
        return ctx.trap(TrapCause::InstructionAddressMisaligned);
    }
    ctx.store_register(insn.rd_internal() as usize, out)?;
    ctx.set_pc(new_pc);
    Ok(true)
}

fn step_branch<M: EmuContext>(ctx: &mut M, kind: InsnKind, decoded: &Instruction) -> Result<bool> {
    use super::InsnKind::*;

    let pc = ctx.get_pc();
    let rs1 = ctx.load_register(decoded.rs1 as RegIdx)?;
    let rs2 = ctx.load_register(decoded.rs2 as RegIdx)?;

    let taken = match kind {
        BEQ => rs1 == rs2,
        BNE => rs1 != rs2,
        BLT => (rs1 as i32) < (rs2 as i32),
        BGE => (rs1 as i32) >= (rs2 as i32),
        BLTU => rs1 < rs2,
        BGEU => rs1 >= rs2,
        _ => unreachable!("Illegal branch instruction: {:?}", kind),
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

fn step_load<M: EmuContext>(ctx: &mut M, kind: InsnKind, decoded: &Instruction) -> Result<bool> {
    let rs1 = ctx.load_register(decoded.rs1)?;
    // LOAD instructions do not read rs2.
    let addr = ByteAddr(rs1.wrapping_add_signed(decoded.imm));
    if !ctx.check_data_load(addr) {
        return ctx.trap(TrapCause::LoadAccessFault(addr));
    }
    let data = ctx.load_memory(addr.waddr())?;
    let shift = 8 * (addr.0 & 3);
    let out = match kind {
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
    ctx.store_register(decoded.rd_internal() as usize, out)?;
    ctx.set_pc(ctx.get_pc() + WORD_SIZE);
    Ok(true)
}

fn step_store<M: EmuContext>(ctx: &mut M, kind: InsnKind, decoded: &Instruction) -> Result<bool> {
    let rs1 = ctx.load_register(decoded.rs1)?;
    let rs2 = ctx.load_register(decoded.rs2)?;
    let addr = ByteAddr(rs1.wrapping_add(decoded.imm as u32));
    let shift = 8 * (addr.0 & 3);
    if !ctx.check_data_store(addr) {
        tracing::error!("mstore: addr={:x?},rs1={:x}", addr, rs1);
        return ctx.trap(TrapCause::StoreAccessFault);
    }
    let mut data = ctx.peek_memory(addr.waddr());
    match kind {
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

fn step_system<M: EmuContext>(ctx: &mut M, kind: InsnKind, decoded: &Instruction) -> Result<bool> {
    match kind {
        InsnKind::ECALL => ctx.ecall(),
        _ => ctx.trap(TrapCause::IllegalInstruction(decoded.raw)),
    }
}

fn sign_extend_u32(x: u32) -> i64 {
    (x as i32) as i64
}
