use crate::rv32im::{InsnKind, Instruction};
use itertools::izip;
use rrs_lib::{
    InstructionProcessor,
    instruction_formats::{BType, IType, ITypeCSR, ITypeShamt, JType, RType, SType, UType},
    process_instruction,
};

/// A transpiler that converts the 32-bit encoded instructions into instructions.
pub(crate) struct InstructionTranspiler {
    pc: u32,
    word: u32,
}

impl Instruction {
    /// Create a new [`Instruction`] from an R-type instruction.
    #[must_use]
    pub const fn from_r_type(kind: InsnKind, dec_insn: &RType, raw: u32) -> Self {
        Self {
            kind,
            rd: dec_insn.rd,
            rs1: dec_insn.rs1,
            rs2: dec_insn.rs2,
            imm: 0,
            raw,
        }
    }

    /// Create a new [`Instruction`] from an I-type instruction.
    #[must_use]
    pub const fn from_i_type(kind: InsnKind, dec_insn: &IType, raw: u32) -> Self {
        Self {
            kind,
            rd: dec_insn.rd,
            rs1: dec_insn.rs1,
            imm: dec_insn.imm,
            rs2: 0,
            raw,
        }
    }

    /// Create a new [`Instruction`] from an I-type instruction with a shamt.
    #[must_use]
    pub const fn from_i_type_shamt(kind: InsnKind, dec_insn: &ITypeShamt, raw: u32) -> Self {
        Self {
            kind,
            rd: dec_insn.rd,
            rs1: dec_insn.rs1,
            imm: dec_insn.shamt as i32,
            rs2: 0,
            raw,
        }
    }

    /// Create a new [`Instruction`] from an S-type instruction.
    #[must_use]
    pub const fn from_s_type(kind: InsnKind, dec_insn: &SType, raw: u32) -> Self {
        Self {
            kind,
            rd: 0,
            rs1: dec_insn.rs1,
            rs2: dec_insn.rs2,
            imm: dec_insn.imm,
            raw,
        }
    }

    /// Create a new [`Instruction`] from a B-type instruction.
    #[must_use]
    pub const fn from_b_type(kind: InsnKind, dec_insn: &BType, raw: u32) -> Self {
        Self {
            kind,
            rd: 0,
            rs1: dec_insn.rs1,
            rs2: dec_insn.rs2,
            imm: dec_insn.imm,
            raw,
        }
    }

    /// Create a new [`Instruction`] that is not implemented.
    #[must_use]
    pub const fn unimp(raw: u32) -> Self {
        Self {
            kind: InsnKind::INVALID,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            raw,
        }
    }
}

impl InstructionProcessor for InstructionTranspiler {
    type InstructionResult = Instruction;

    fn process_add(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::ADD, &dec_insn, self.word)
    }

    fn process_addi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::ADDI, &dec_insn, self.word)
    }

    fn process_sub(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SUB, &dec_insn, self.word)
    }

    fn process_xor(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::XOR, &dec_insn, self.word)
    }

    fn process_xori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::XORI, &dec_insn, self.word)
    }

    fn process_or(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::OR, &dec_insn, self.word)
    }

    fn process_ori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::ORI, &dec_insn, self.word)
    }

    fn process_and(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::AND, &dec_insn, self.word)
    }

    fn process_andi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::ANDI, &dec_insn, self.word)
    }

    fn process_sll(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SLL, &dec_insn, self.word)
    }

    fn process_slli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(InsnKind::SLLI, &dec_insn, self.word)
    }

    fn process_srl(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SRL, &dec_insn, self.word)
    }

    fn process_srli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(InsnKind::SRLI, &dec_insn, self.word)
    }

    fn process_sra(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SRA, &dec_insn, self.word)
    }

    fn process_srai(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(InsnKind::SRAI, &dec_insn, self.word)
    }

    fn process_slt(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SLT, &dec_insn, self.word)
    }

    fn process_slti(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::SLTI, &dec_insn, self.word)
    }

    fn process_sltu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::SLTU, &dec_insn, self.word)
    }

    fn process_sltui(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::SLTIU, &dec_insn, self.word)
    }

    fn process_lb(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::LB, &dec_insn, self.word)
    }

    fn process_lh(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::LH, &dec_insn, self.word)
    }

    fn process_lw(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::LW, &dec_insn, self.word)
    }

    fn process_lbu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::LBU, &dec_insn, self.word)
    }

    fn process_lhu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(InsnKind::LHU, &dec_insn, self.word)
    }

    fn process_sb(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(InsnKind::SB, &dec_insn, self.word)
    }

    fn process_sh(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(InsnKind::SH, &dec_insn, self.word)
    }

    fn process_sw(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(InsnKind::SW, &dec_insn, self.word)
    }

    fn process_beq(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BEQ, &dec_insn, self.word)
    }

    fn process_bne(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BNE, &dec_insn, self.word)
    }

    fn process_blt(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BLT, &dec_insn, self.word)
    }

    fn process_bge(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BGE, &dec_insn, self.word)
    }

    fn process_bltu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BLTU, &dec_insn, self.word)
    }

    fn process_bgeu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(InsnKind::BGEU, &dec_insn, self.word)
    }

    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        Instruction {
            kind: InsnKind::JAL,
            rd: dec_insn.rd,
            rs1: 0,
            rs2: 0,
            imm: dec_insn.imm,
            raw: self.word,
        }
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction {
            kind: InsnKind::JALR,
            rd: dec_insn.rd,
            rs1: dec_insn.rs1,
            rs2: 0,
            imm: dec_insn.imm,
            raw: self.word,
        }
    }

    /// Convert LUI to ADDI.
    ///
    /// RiscV's load-upper-immediate instruction is necessary to build arbitrary constants,
    /// because its ADDI can only have a relatively small immediate value: there's just not
    /// enough space in the 32 bits for more.
    ///
    /// Our internal ADDI does not have this limitation, so we can convert LUI to ADDI.
    /// See [`InstructionTranspiler::process_auipc`] for more background on the conversion.
    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {
        // Verify assumption that the immediate is already shifted left by 12 bits.
        assert_eq!(dec_insn.imm & 0xfff, 0);
        Instruction {
            kind: InsnKind::ADDI,
            rd: dec_insn.rd,
            rs1: 0,
            rs2: 0,
            imm: dec_insn.imm,
            raw: self.word,
        }
    }

    /// Convert AUIPC to ADDI.
    ///
    /// RiscV's instructions are designed to be (mosty) position-independent.  AUIPC is used
    /// to get access to the current program counter, even if the code has been moved around
    /// by the linker.
    ///
    /// Our conversion here happens after the linker has done its job, so we can safely hardcode
    /// the current program counter into the immediate value of our internal ADDI.
    ///
    /// Note that our internal ADDI can have arbitrary intermediate values, not just 12 bits.
    ///
    /// ADDI is slightly more general than LUI or AUIPC, because you can also specify an
    /// input register rs1.  That generality might cost us sligthtly in the non-recursive proof,
    /// but we suspect decreasing the total number of different instruction kinds will speed up
    /// the recursive proof.
    ///
    /// In any case, AUIPC and LUI together make up ~0.1% of instructions executed in typical
    /// real world scenarios like a `reth` run.
    ///
    /// TODO(Matthias): run benchmarks to verify the impact on recursion, once we have a working
    /// recursion.
    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {
        let pc = self.pc;
        // Verify our assumption that the immediate is already shifted left by 12 bits.
        assert_eq!(dec_insn.imm & 0xfff, 0);
        Instruction {
            kind: InsnKind::ADDI,
            rd: dec_insn.rd,
            rs1: 0,
            rs2: 0,
            imm: dec_insn.imm.wrapping_add(pc as i32),
            raw: self.word,
        }
    }

    fn process_ecall(&mut self) -> Self::InstructionResult {
        Instruction {
            kind: InsnKind::ECALL,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            raw: self.word,
        }
    }

    fn process_ebreak(&mut self) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_mul(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::MUL, &dec_insn, self.word)
    }

    fn process_mulh(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::MULH, &dec_insn, self.word)
    }

    fn process_mulhu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::MULHU, &dec_insn, self.word)
    }

    fn process_mulhsu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::MULHSU, &dec_insn, self.word)
    }

    fn process_div(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::DIV, &dec_insn, self.word)
    }

    fn process_divu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::DIVU, &dec_insn, self.word)
    }

    fn process_rem(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::REM, &dec_insn, self.word)
    }

    fn process_remu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(InsnKind::REMU, &dec_insn, self.word)
    }

    fn process_csrrc(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_csrrci(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_csrrs(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_csrrsi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_csrrw(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_csrrwi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_fence(&mut self, _: IType) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_mret(&mut self) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }

    fn process_wfi(&mut self) -> Self::InstructionResult {
        Instruction::unimp(self.word)
    }
}

/// Transpile the [`Instruction`]s from the 32-bit encoded instructions.
#[must_use]
pub fn transpile(base: u32, instructions_u32: &[u32]) -> Vec<Instruction> {
    izip!(enumerate(base, 4), instructions_u32)
        .map(|(pc, &word)| {
            process_instruction(&mut InstructionTranspiler { pc, word }, word)
                .unwrap_or(Instruction::unimp(word))
        })
        .collect()
}

fn enumerate(start: u32, step: u32) -> impl Iterator<Item = u32> {
    std::iter::successors(Some(start), move |&i| Some(i + step))
}
