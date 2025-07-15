pub mod ops;

use strum_macros::EnumIter;

#[derive(
    Copy, Clone, Debug, EnumIter, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(usize)]
pub enum LookupTable {
    U5 = 0,      // 2^5 = 32
    U8,          // 2^8 = 256
    U14,         // 2^14 = 16,384
    U16,         // 2^16 = 65,536
    And,         // a & b where a, b are bytes
    Or,          // a | b where a, b are bytes
    Xor,         // a ^ b where a, b are bytes
    Ltu,         // a <(usign) b where a, b are bytes and the result is 0/1.
    Pow,         // a ** b where a is 2 and b is 5-bit value
    Instruction, // Decoded instruction from the fixed program.
}

/// Use this trait as parameter to OpsTableCircuit.
pub trait OpsTable {
    const ROM_TYPE: LookupTable;

    fn len() -> usize;

    /// The content of the table: [[a, b, result], ...]
    fn content() -> Vec<[u64; 3]>;

    fn pack(a: u64, b: u64) -> u64 {
        a | (b << 8)
    }

    fn unpack(i: u64) -> (u64, u64) {
        (i & 0xff, (i >> 8) & 0xff)
    }
}
