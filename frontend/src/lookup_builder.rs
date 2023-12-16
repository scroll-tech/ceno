use std::collections::HashMap;

use goldilocks::SmallField;

use crate::structs::{LookupBuilder, TableData};

impl TableData {
    pub fn new() -> Self {
        Self {
            table_item: Vec::new(),
            input_item: Vec::new(),
            challenge: None,
        }
    }
    pub fn add_table_item(&mut self, cell: usize) {
        self.table_item.push(cell);
    }
    pub fn add_input_item(&mut self, cell: usize) {
        self.input_item.push(cell);
    }
}

impl<F: SmallField> LookupBuilder<F> {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            cells: todo!(),
        }
    }

    pub(crate) fn define_table_type(&mut self, table_type: &'static str) {
        self.tables.insert(table_type, TableData::new());
    }

    pub(crate) fn add_input_item(&mut self, table_type: &'static str, cell: usize) {
        self.tables
            .get_mut(table_type)
            .unwrap()
            .add_input_item(cell);
    }

    pub(crate) fn add_table_item(&mut self, table_type: &'static str, cell: usize) {
        self.tables
            .get_mut(table_type)
            .unwrap()
            .add_table_item(cell);
    }

    /// Build the lookup circuit. This method relies on the choice of lookup
    /// scheme.
    pub(crate) fn build_circuit(&mut self) {
        todo!()
    }
}
