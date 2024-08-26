use crate::structs::ChipChallenges;
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{Cell, CellId, CircuitBuilder, ExtCellId, MixedCell, WitnessId};

pub struct RAMHandler<Ext: ExtensionField> {
    read_records: Vec<ExtCellId<Ext>>,
    write_records: Vec<ExtCellId<Ext>>,
    challenge: ChipChallenges,
}

impl<Ext: ExtensionField> RAMHandler<Ext> {
    /// Instantiate new `OAMHandler` given chip challenge
    pub fn new(challenge: ChipChallenges) -> Self {
        Self {
            read_records: Vec::new(),
            write_records: Vec::new(),
            challenge,
        }
    }

    pub fn read(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        self.read_oam(circuit_builder, old_ts, key, value);
        self.write_oam(circuit_builder, cur_ts, key, value);
    }

    pub fn read_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        self.read_oam_mixed(circuit_builder, old_ts, key, value);
        self.write_oam_mixed(circuit_builder, cur_ts, key, value);
    }

    pub fn read_oam(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let items = vec![old_ts.to_vec(), key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.read_records.push(out);
    }

    pub fn read_oam_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let items = vec![old_ts.to_vec(), key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc_mixed(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.read_records.push(out);
    }

    pub fn write(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        old_value: &[CellId],
        cur_value: &[CellId],
    ) {
        self.read_oam(circuit_builder, old_ts, key, old_value);
        self.write_oam(circuit_builder, cur_ts, key, cur_value);
    }

    pub fn write_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        old_value: &[MixedCell<Ext>],
        cur_value: &[MixedCell<Ext>],
    ) {
        self.read_oam_mixed(circuit_builder, old_ts, key, old_value);
        self.write_oam_mixed(circuit_builder, cur_ts, key, cur_value);
    }

    pub fn write_oam(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        curr_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let items = vec![curr_ts.to_vec(), key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.write_records.push(out);
    }

    pub fn write_oam_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        curr_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        let item_rlc = circuit_builder.create_ext_cell();
        let items = vec![curr_ts.to_vec(), key.to_vec(), value.to_vec()].concat();
        circuit_builder.rlc_mixed(&item_rlc, &items, self.challenge.record_item_rlc());

        let out = circuit_builder.create_ext_cell();
        circuit_builder.rlc_ext(&out, &[item_rlc], self.challenge.record_rlc());
        self.write_records.push(out);
    }

    pub fn finalize(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (Option<(WitnessId, usize)>, Option<(WitnessId, usize)>) {
        let mut read_records = self.read_records.clone();
        let mut write_records = self.write_records.clone();

        let read_record_output =
            pad_and_generate_output_witness(circuit_builder, &mut read_records);
        let write_record_output =
            pad_and_generate_output_witness(circuit_builder, &mut write_records);

        (read_record_output, write_record_output)
    }
}

fn pad_and_generate_output_witness<Ext: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<Ext>,
    records: &mut Vec<ExtCellId<Ext>>,
) -> Option<(WitnessId, usize)> {
    if records.is_empty() {
        None
    } else {
        pad_with_one(circuit_builder, records);
        Some((
            circuit_builder.create_witness_out_from_exts(&records),
            records.len(),
        ))
    }
}

fn pad_with_one<Ext: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<Ext>,
    records: &mut Vec<ExtCellId<Ext>>,
) {
    let padding_count = records.len().next_power_of_two() - records.len();
    for _ in 0..padding_count {
        let out = circuit_builder.create_ext_cell();
        circuit_builder.add_const(out.cells[0], Ext::BaseField::ONE);
        records.push(out);
    }
}
