use crate::{
    chip_handler::{ram_handler::RAMHandler, rom_handler::ROMHandler},
    structs::ChipChallenges,
};
use ff_ext::ExtensionField;
use simple_frontend::structs::{ChallengeId, CircuitBuilder, WitnessId};

pub mod bytecode;
pub mod calldata;
pub mod global_state;
pub mod memory;
pub mod ram_handler;
pub mod range;
pub mod rom_handler;
pub mod stack;
mod util;

impl Default for ChipChallenges {
    fn default() -> Self {
        Self {
            record_rlc: 1,
            record_item_rlc: 0,
        }
    }
}

impl ChipChallenges {
    pub fn new(record_rlc: ChallengeId, record_item_rlc: ChallengeId) -> Self {
        Self {
            record_rlc,
            record_item_rlc,
        }
    }
    pub fn record_item_rlc(&self) -> ChallengeId {
        self.record_item_rlc
    }
    pub fn record_rlc(&self) -> ChallengeId {
        self.record_rlc
    }
}

pub struct ChipHandler<Ext: ExtensionField> {
    pub ram_handler: RAMHandler<Ext>,
    pub rom_handler: ROMHandler<Ext>,
}

impl<Ext: ExtensionField> ChipHandler<Ext> {
    pub fn new(challenge: ChipChallenges) -> Self {
        Self {
            ram_handler: RAMHandler::new(challenge.clone()),
            rom_handler: ROMHandler::new(challenge),
        }
    }

    pub fn finalize(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (
        Option<(WitnessId, usize)>,
        Option<(WitnessId, usize)>,
        Option<(WitnessId, usize)>,
    ) {
        let (ram_load_id, ram_store_id) = self.ram_handler.finalize(circuit_builder);
        let rom_id = self.rom_handler.finalize(circuit_builder);
        (ram_load_id, ram_store_id, rom_id)
    }
}
