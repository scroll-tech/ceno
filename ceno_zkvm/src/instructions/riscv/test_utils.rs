use proptest::{
    prelude::any,
    prop_oneof,
    strategy::{Just, Strategy},
};

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
    let shift = 32 - bits;
    (imm << shift >> shift) as u32
}

pub fn imm_u(imm: u32) -> u32 {
    // valid imm is imm[12:31] in U-type
    imm << 12
}

#[allow(clippy::cast_sign_loss)]
pub fn u32_extra() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0_u32),
        Just(1_u32),
        Just(u32::MAX),
        any::<u32>(),
        Just(i32::MIN as u32),
        Just(i32::MAX as u32),
    ]
}

#[allow(clippy::cast_possible_wrap)]
pub fn i32_extra() -> impl Strategy<Value = i32> {
    u32_extra().prop_map(|x| x as i32)
}

pub fn imm_extra(bits: u32) -> impl Strategy<Value = i32> {
    i32_extra().prop_map(move |x| imm_with_max_valid_bits(x, bits) as i32)
}

pub fn immu_extra(bits: u32) -> impl Strategy<Value = u32> {
    i32_extra().prop_map(move |x| imm_with_max_valid_bits(x, bits))
}
