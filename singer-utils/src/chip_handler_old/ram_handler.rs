use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, ExtCellId, MixedCell, WitnessId};

use crate::structs::{ChipChallenges, RAMHandler};

use super::{OAMOperations, RAMOperations};

impl<Ext: ExtensionField> RAMHandler<Ext> {
    pub fn new(challenge: &ChipChallenges) -> Self {
        Self {
            rd_records: Vec::new(),
            wt_records: Vec::new(),
            challenge: challenge.clone(),
        }
    }
}

impl<Ext: ExtensionField> OAMOperations<Ext> for RAMHandler<Ext> {
    fn oam_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let mut items = old_ts.to_vec();
        items.extend(key.to_vec());
        items.extend(value.to_vec());
        circuit_builder.rlc(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.rd_records.push(out);
    }

    fn oam_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let mut items = old_ts.to_vec();
        items.extend(key.to_vec());
        items.extend(value.to_vec());
        circuit_builder.rlc_mixed(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.rd_records.push(out);
    }

    fn oam_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let mut items = cur_ts.to_vec();
        items.extend(key.to_vec());
        items.extend(value.to_vec());
        circuit_builder.rlc(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.wt_records.push(out);
    }

    fn oam_store_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let mut items = cur_ts.to_vec();
        items.extend(key.to_vec());
        items.extend(value.to_vec());
        circuit_builder.rlc_mixed(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.wt_records.push(out);
    }

    fn finalize(
        self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (Option<(WitnessId, usize)>, Option<(WitnessId, usize)>) {
        let mut pad_with_one = |records: &mut Vec<ExtCellId<Ext>>| {
            if records.len() == 0 {
                return None;
            }
            let count = records.len().next_power_of_two() - records.len();
            for _ in 0..count {
                let out = circuit_builder.create_ext_cell();
                circuit_builder.add_const(out.cells[0], Ext::BaseField::ONE);
                records.push(out);
            }
            Some((
                circuit_builder.create_witness_out_from_exts(&records),
                records.len(),
            ))
        };

        let mut rd_records = self.rd_records;
        let mut wt_records = self.wt_records;
        (pad_with_one(&mut rd_records), pad_with_one(&mut wt_records))
    }
}

impl<Ext: ExtensionField> RAMOperations<Ext> for RAMHandler<Ext> {
    fn ram_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        self.oam_load(circuit_builder, old_ts, key, value);
        self.oam_store(circuit_builder, cur_ts, key, value);
    }

    fn ram_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        self.oam_load_mixed(circuit_builder, old_ts, key, value);
        self.oam_store_mixed(circuit_builder, cur_ts, key, value);
    }

    fn ram_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        old_value: &[CellId],
        cur_value: &[CellId],
    ) {
        self.oam_load(circuit_builder, old_ts, key, old_value);
        self.oam_store(circuit_builder, cur_ts, key, cur_value);
    }

    fn ram_store_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        old_value: &[MixedCell<Ext>],
        cur_value: &[MixedCell<Ext>],
    ) {
        self.oam_load_mixed(circuit_builder, old_ts, key, old_value);
        self.oam_store_mixed(circuit_builder, cur_ts, key, cur_value);
    }
}
