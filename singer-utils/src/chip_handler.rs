use crate::structs::ChipChallenges;
use simple_frontend::structs::ChallengeId;

// TODO: consider renaming the entire structure from chip_handler to something more representative
//  of the underlying logic.
pub mod bytecode;
pub mod calldata;
pub mod global_state;
pub mod memory;
pub mod oam_handler;
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
