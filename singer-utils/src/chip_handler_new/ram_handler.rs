use crate::chip_handler_new::oam_handler::OAMHandler;
use crate::structs::ChipChallenges;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CellType, CircuitBuilder, ExtCellId, MixedCell, WitnessId};

// TODO: add documentation
pub struct RAMHandler<Ext: ExtensionField> {
    oam_handler: OAMHandler<Ext>,
}

impl<Ext: ExtensionField> RAMHandler<Ext> {
    // TODO: add documentation
    fn new(challenge: ChipChallenges) -> Self {
        Self {
            oam_handler: OAMHandler::new(challenge),
        }
    }

    // TODO: add documentation
    fn read(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        self.oam_handler.read(circuit_builder, old_ts, key, value);
        self.oam_handler.write(circuit_builder, cur_ts, key, value);
    }

    // TODO: add documentation
    fn read_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        self.oam_handler
            .read_mixed(circuit_builder, old_ts, key, value);
        self.oam_handler
            .write_mixed(circuit_builder, cur_ts, key, value);
    }

    // TODO: add documentation
    fn write(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        old_value: &[CellId],
        cur_value: &[CellId],
    ) {
        self.oam_handler
            .read(circuit_builder, old_ts, key, old_value);
        self.oam_handler
            .write(circuit_builder, cur_ts, key, cur_value);
    }

    // TODO: add documentation
    fn write_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        old_value: &[MixedCell<Ext>],
        cur_value: &[MixedCell<Ext>],
    ) {
        self.oam_handler
            .read_mixed(circuit_builder, old_ts, key, old_value);
        self.oam_handler
            .write_mixed(circuit_builder, cur_ts, key, cur_value);
    }

    // TODO: add documentation
    fn finalize(
        self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (Option<(WitnessId, usize)>, Option<(WitnessId, usize)>) {
        self.oam_handler.finalize(circuit_builder)
    }
}
