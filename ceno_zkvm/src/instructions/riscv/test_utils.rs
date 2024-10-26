pub fn imm_b(imm: i32) -> u32 {
    // imm is 13 bits in B-type
    imm_with_max_valid_bits(imm, 13)
}

pub fn imm_i(imm: i32) -> u32 {
    // imm is 12 bits in I-type
    imm_with_max_valid_bits(imm, 12)
}

pub fn imm_j(imm: i32) -> u32 {
    // imm is 21 bits in J-type
    imm_with_max_valid_bits(imm, 21)
}

fn imm_with_max_valid_bits(imm: i32, bits: u32) -> u32 {
    imm as u32 & !(u32::MAX << bits)
}

pub fn imm_u(imm: u32) -> u32 {
    // valid imm is imm[12:31] in U-type
    imm << 12
}
