use ceno_emul::{Cycle, Word, WordAddr};
use gkr_iop::tables::LookupTable;
use smallvec::SmallVec;

use crate::structs::RAMType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LkOp {
    AssertU16 { value: u16 },
    DynamicRange { value: u64, bits: u32 },
    AssertU14 { value: u16 },
    Fetch { pc: u32 },
    DoubleU8 { a: u8, b: u8 },
    And { a: u8, b: u8 },
    Or { a: u8, b: u8 },
    Xor { a: u8, b: u8 },
    Ltu { a: u8, b: u8 },
    Pow2 { value: u8 },
    ShrByte { shift: u8, carry: u8, bits: u8 },
}

impl LkOp {
    pub fn encode_all(&self) -> SmallVec<[(LookupTable, u64); 2]> {
        match *self {
            LkOp::AssertU16 { value } => {
                SmallVec::from_slice(&[(LookupTable::Dynamic, (1u64 << 16) + value as u64)])
            }
            LkOp::DynamicRange { value, bits } => {
                SmallVec::from_slice(&[(LookupTable::Dynamic, (1u64 << bits) + value)])
            }
            LkOp::AssertU14 { value } => {
                SmallVec::from_slice(&[(LookupTable::Dynamic, (1u64 << 14) + value as u64)])
            }
            LkOp::Fetch { pc } => SmallVec::from_slice(&[(LookupTable::Instruction, pc as u64)]),
            LkOp::DoubleU8 { a, b } => {
                SmallVec::from_slice(&[(LookupTable::DoubleU8, ((a as u64) << 8) + b as u64)])
            }
            LkOp::And { a, b } => {
                SmallVec::from_slice(&[(LookupTable::And, (a as u64) | ((b as u64) << 8))])
            }
            LkOp::Or { a, b } => {
                SmallVec::from_slice(&[(LookupTable::Or, (a as u64) | ((b as u64) << 8))])
            }
            LkOp::Xor { a, b } => {
                SmallVec::from_slice(&[(LookupTable::Xor, (a as u64) | ((b as u64) << 8))])
            }
            LkOp::Ltu { a, b } => {
                SmallVec::from_slice(&[(LookupTable::Ltu, (a as u64) | ((b as u64) << 8))])
            }
            LkOp::Pow2 { value } => {
                SmallVec::from_slice(&[(LookupTable::Pow, 2u64 | ((value as u64) << 8))])
            }
            LkOp::ShrByte { shift, carry, bits } => SmallVec::from_slice(&[
                (
                    LookupTable::DoubleU8,
                    ((shift as u64) << 8) + ((shift as u64) << bits),
                ),
                (
                    LookupTable::DoubleU8,
                    ((carry as u64) << 8) + ((carry as u64) << (8 - bits)),
                ),
            ]),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SendEvent {
    pub ram_type: RAMType,
    pub addr: WordAddr,
    pub id: u64,
    pub cycle: Cycle,
    pub prev_cycle: Cycle,
    pub value: Word,
    pub prev_value: Option<Word>,
}
