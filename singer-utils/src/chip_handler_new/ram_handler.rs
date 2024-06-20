use crate::structs::ChipChallenges;
use ff_ext::ExtensionField;
use simple_frontend::structs::ExtCellId;

// TODO: add documentation
// this shouldn't have it's own read and write records, instead it should have
// an underlying oam structure that it calls.
// I believe the oam structure makes use of
pub struct RAMHandler<Ext: ExtensionField> {
    read_records: Vec<ExtCellId<Ext>>,
    write_records: Vec<ExtCellId<Ext>>,
    challenge: ChipChallenges,
}

impl<Ext: ExtensionField> RAMHandler<Ext> {}
