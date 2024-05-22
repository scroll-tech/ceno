use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell, WitnessId};

use crate::structs::{ChipChallenges, ROMHandler};

use super::ROMOperations;

impl<Ext: ExtensionField> ROMHandler<Ext> {
    pub fn new(challenge: &ChipChallenges) -> Self {
        Self {
            records: Vec::new(),
            challenge: challenge.clone(),
        }
    }
}

impl<Ext: ExtensionField> ROMOperations<Ext> for ROMHandler<Ext> {
    fn rom_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        key: &[CellId],
        value: &[CellId],
    ) {
        let out = circuit_builder.create_ext_cell();
        let items = [key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc(&out, &items, self.challenge.record_rlc);
        self.records.push(out);
    }

    fn rom_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        let out = circuit_builder.create_ext_cell();
        let items = [key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc_mixed(&out, &items, self.challenge.record_rlc);
        self.records.push(out);
    }

    fn finalize(self, circuit_builder: &mut CircuitBuilder<Ext>) -> Option<(WitnessId, usize)> {
        if self.records.len() == 0 {
            return None;
        }
        let count = self.records.len().next_power_of_two() - self.records.len();
        let last = self.records[self.records.len() - 1].clone();
        let mut records = self.records;
        for _ in 0..count {
            let out = circuit_builder.create_ext_cell();
            circuit_builder.add_ext(&out, &last, Ext::BaseField::ONE);
            records.push(out);
        }
        Some((
            circuit_builder.create_witness_out_from_exts(&records),
            records.len(),
        ))
    }
}
