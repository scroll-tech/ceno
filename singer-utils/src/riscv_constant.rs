use strum_macros::EnumIter;

/// This struct is used to define the opcode format for RISC-V instructions,
/// containing three main components: the opcode, funct3, and funct7 fields.
/// These fields are crucial for specifying the
/// exact operation and variants in the RISC-V instruction set architecture.
#[derive(Default, Clone)]
pub struct RvOpcode {
    pub opcode: RV64IOpcode,
    pub funct3: u8,
    pub funct7: u8,
}

impl From<RvOpcode> for u64 {
    fn from(opcode: RvOpcode) -> Self {
        let mut result: u64 = 0;
        result |= (opcode.opcode as u64) & 0xFF;
        result |= ((opcode.funct3 as u64) & 0xFF) << 8;
        result |= ((opcode.funct7 as u64) & 0xFF) << 16;
        result
    }
}

/// List all instruction formats in RV64I which contains
/// R-Type, I-Type, S-Type, B-Type, U-Type, J-Type and special type.
#[derive(Debug, Clone)]
pub enum RV64IOpcode {
    UNKNOWN = 0x00,

    R = 0x33,
    I_LOAD = 0x03,
    I_ARITH = 0x13,
    S = 0x63,
    B = 0x23,
    U_LUI = 0x37,
    U_AUIPC = 0x7,
    J = 0x6F,
    JAR = 0x67,
    SYS = 0x73,
}

impl Default for RV64IOpcode {
    fn default() -> Self {
        RV64IOpcode::UNKNOWN
    }
}

impl From<RV64IOpcode> for u8 {
    fn from(opcode: RV64IOpcode) -> Self {
        opcode as u8
    }
}

#[derive(Debug, Clone, Copy, EnumIter)]
pub enum RvInstructions {
    // Type R
    ADD = 0,
    SUB,
    SLL,
    SLTU,
    SLT,
    XOR,
    SRL,
    SRA,
    OR,
    AND,
    // Type I-LOAD
    LB,
    LH,
    LW,
    LBU,
    LHU,

    // a workaround to get number of valid instructions
    END,
}

impl From<RvInstructions> for RvOpcode {
    fn from(ins: RvInstructions) -> Self {
        // Find the instruction format here:
        // https://fraserinnovations.com/risc-v/risc-v-instruction-set-explanation/
        match ins {
            // Type R
            RvInstructions::ADD => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b000 as u8,
                funct7: 0,
            },
            RvInstructions::SUB => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b000 as u8,
                funct7: 0b010_0000,
            },
            RvInstructions::SLL => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b001 as u8,
                funct7: 0,
            },
            RvInstructions::SLT => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b010 as u8,
                funct7: 0,
            },
            RvInstructions::SLTU => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b011 as u8,
                funct7: 0,
            },
            RvInstructions::XOR => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b100 as u8,
                funct7: 0,
            },
            RvInstructions::SRL => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b101 as u8,
                funct7: 0,
            },
            RvInstructions::SRA => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b101 as u8,
                funct7: 0b010_0000,
            },
            RvInstructions::OR => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b110 as u8,
                funct7: 0,
            },
            RvInstructions::AND => RvOpcode {
                opcode: RV64IOpcode::R,
                funct3: 0b111 as u8,
                funct7: 0,
            },
            // Type I-LOAD
            RvInstructions::LB => RvOpcode {
                opcode: RV64IOpcode::I_LOAD,
                funct3: 0b000 as u8,
                funct7: 0,
            },
            RvInstructions::LH => RvOpcode {
                opcode: RV64IOpcode::I_LOAD,
                funct3: 0b001 as u8,
                funct7: 0,
            },
            RvInstructions::LW => RvOpcode {
                opcode: RV64IOpcode::I_LOAD,
                funct3: 0b010 as u8,
                funct7: 0,
            },
            RvInstructions::LBU => RvOpcode {
                opcode: RV64IOpcode::I_LOAD,
                funct3: 0b100 as u8,
                funct7: 0,
            },
            RvInstructions::LHU => RvOpcode {
                opcode: RV64IOpcode::I_LOAD,
                funct3: 0b101 as u8,
                funct7: 0,
            },
            // TODO add more
            _ => RvOpcode::default(),
        }
    }
}

impl From<RvInstructions> for u64 {
    fn from(ins: RvInstructions) -> Self {
        let opcode: RvOpcode = ins.into();
        opcode.into()
    }
}
