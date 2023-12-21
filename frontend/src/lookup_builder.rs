use std::collections::HashMap;

use goldilocks::SmallField;

use crate::structs::{LookupBuilder, TableData};

pub type TableType = usize;

impl<F: SmallField> TableData<F> {
    pub fn new() -> Self {
        todo!()
    }
    pub fn add_table_item(&mut self, cell: usize) {
        self.table_items.push(cell);
    }
    pub fn add_input_item(&mut self, cell: usize) {
        self.input_items.push(cell);
    }
    pub fn add_table_item_const(&mut self, constant: F) {
        self.table_items_const.push(constant);
    }
}

impl<F: SmallField> LookupBuilder<F> {
    pub fn new() -> Self {
        todo!()
    }

    pub(crate) fn define_table_type(&mut self, table_type: TableType) {
        todo!()
    }

    pub(crate) fn add_input_item(&mut self, table_type: TableType, cell: usize) {
        todo!()
    }

    pub(crate) fn add_table_item(&mut self, table_type: TableType, cell: usize) {
        todo!()
    }

    pub(crate) fn add_table_item_const(&mut self, table_type: TableType, constant: F) {
        todo!()
    }

    /// Build the lookup circuit. This method relies on the choice of lookup
    /// scheme.
    pub(crate) fn build_circuit(&mut self) {
        todo!()
    }
}
