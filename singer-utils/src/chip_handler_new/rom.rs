use crate::structs::ChipChallenges;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, ExtCellId};

// TODO: add documentation
pub struct ROM<Ext: ExtensionField> {
    records: Vec<ExtCellId<Ext>>,
    challenge: ChipChallenges,
}

impl<Ext: ExtensionField> ROM<Ext> {
    // TODO: add documentation
    // TODO: can this be named read?
    fn load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        key: &[CellId],
        value: &[CellId],
    ) {
        // TODO: it might be possible to completely remove the distinction between key and value
        // it seems we first create a cell that holds the compression
        // of the key and value
        // then we mul that with some
        todo!()
    }
}
