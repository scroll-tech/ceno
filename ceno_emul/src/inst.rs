/// A description of a RISC-V instruction. That is everything that can be deduced from the bytecode.
#[derive(Clone, Copy, Debug)]
pub struct Inst {
    code: u32,
}

impl Inst {
    pub fn new(code: u32) -> Inst {
        Inst { code }
    }

    pub fn encoded(&self) -> u32 {
        self.code
    }

    /// Major opcode. Also defines the instruction format (R/I/S/B/U/J).
    pub fn opcode(&self) -> u8 {
        (self.code & MASK_7) as u8
    }

    /// Destination register in formats R/I/U/J.
    pub fn rd(&self) -> u8 {
        ((self.code >> 7) & MASK_5) as u8
    }

    /// Source register 1 in formats R/I/S/B.
    pub fn rs1(&self) -> u8 {
        ((self.code >> 15) & MASK_5) as u8
    }

    /// Source register 2 in formats R/S/B.
    pub fn rs2(&self) -> u8 {
        ((self.code >> 20) & MASK_5) as u8
    }

    /// Function field in formats R/I/S/B.
    pub fn funct3(&self) -> u8 {
        ((self.code >> 12) & MASK_3) as u8
    }

    /// Secondary function field in format R.
    pub fn funct7(&self) -> u8 {
        ((self.code >> 25) & MASK_7) as u8
    }

    /// Immediate value in formats I/S/B/U/J.
    pub fn imm(&self) -> u32 {
        todo!(); // Construct depending on the format.
    }
}

const MASK_3: u32 = 0b111;
const MASK_5: u32 = 0b11111;
const MASK_7: u32 = 0b1111111;
