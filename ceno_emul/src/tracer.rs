use std::fmt;

use anyhow::Result;

use crate::{
    addr::{ByteAddr, WordAddr},
    rv32im::{DecodedInstruction, EmuContext, Instruction, TrapCause},
};

#[derive(Debug, Default)]
pub struct Tracer {
    pc: Option<Change<ByteAddr>>,
    fetch: Option<(WordAddr, u32)>,
    instruction: Option<(Instruction, DecodedInstruction)>,

    register_loads: Vec<(usize, u32)>,
    register_stores: Vec<(usize, Change<u32>)>,

    memory_loads: Vec<(WordAddr, u32)>,
    memory_stores: Vec<(WordAddr, Change<u32>)>,
}

impl Tracer {
    pub fn on_insn_decoded(&mut self, kind: &Instruction, decoded: &DecodedInstruction) {
        self.instruction = Some((kind.clone(), decoded.clone()));
    }

    pub fn set_pc(&mut self, pc: Change<ByteAddr>) {
        self.pc = Some(pc);
    }

    pub fn fetch(&mut self, addr: WordAddr, value: u32) {
        self.fetch = Some((addr, value));
    }

    pub fn load_register(&mut self, idx: usize, value: u32) {
        self.register_loads.push((idx, value));
    }

    pub fn store_register(&mut self, idx: usize, value: Change<u32>) {
        self.register_stores.push((idx, value));
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: u32) {
        self.memory_loads.push((addr, value));
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<u32>) {
        self.memory_stores.push((addr, value));
    }
}

#[derive(Clone)]
pub struct Change<T> {
    pub before: T,
    pub after: T,
}

impl<T: fmt::Debug> fmt::Debug for Change<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} -> {:?}", self.before, self.after)
    }
}
