use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, MixedCell};

pub fn cell_to_mixed<Ext: ExtensionField>(cells: &[CellId]) -> Vec<MixedCell<Ext>> {
    cells.iter().map(|&x| x.into()).collect_vec()
}
