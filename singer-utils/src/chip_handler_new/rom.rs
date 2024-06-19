use crate::structs::ChipChallenges;
use ff_ext::ExtensionField;
use simple_frontend::structs::ExtCellId;

// TODO: add documentation
pub struct ROM<Ext: ExtensionField> {
    records: Vec<ExtCellId<Ext>>,
    challenge: ChipChallenges,
}
