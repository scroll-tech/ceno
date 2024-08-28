use anyhow::Result;

use crate::{
    addr::{ByteAddr, WordAddr},
    rv32im::{DecodedInstruction, EmuContext, Instruction, TrapCause},
};

#[derive(Debug, Default)]
pub struct Tracer {}

impl Tracer {
    pub fn on_insn_decoded(&mut self, kind: &Instruction, decoded: &DecodedInstruction) {}

    pub fn set_pc(&mut self, pc_after: ByteAddr, pc_before: ByteAddr) {}

    pub fn load_register(&mut self, idx: usize, value: u32) {}

    pub fn store_register(&mut self, idx: usize, value_after: u32, value_before: u32) {}

    pub fn load_memory(&mut self, addr: WordAddr, value: u32) {}

    pub fn store_memory(&mut self, addr: WordAddr, value_after: u32, value_before: u32) {}

    pub fn fetch(&mut self, addr: WordAddr, value: u32) {}
}
