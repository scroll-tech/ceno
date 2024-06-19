use crate::structs::ChipChallenges;
use ff_ext::ExtensionField;
use simple_frontend::structs::ExtCellId;

// TODO: add documentation
pub struct RAM<Ext: ExtensionField> {
    read_records: Vec<ExtCellId<Ext>>,
    write_records: Vec<ExtCellId<Ext>>,
    challenge: ChipChallenges,
}
