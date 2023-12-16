use goldilocks::SmallField;

use crate::structs::{CircuitBuilder, LookupBuilder};

impl<F: SmallField> CircuitBuilder<F> {
    pub fn new() -> Self {
        todo!()
    }
    pub fn create_cell(&mut self) -> usize {
        todo!()
    }
    /// Create a cell and set the `max_challenge_no` to `challenge_no`. This is
    /// especially used for cells in the input layer related to some challenges.
    pub fn create_cell_with_challenge(&mut self, challenge_no: usize) -> usize {
        todo!()
    }
    pub fn create_challenge_cell(&mut self) -> usize {
        todo!()
    }

    pub fn add(&mut self, out: usize, in_0: usize, in_1: usize, scaler: F) {
        todo!()
    }
    pub fn mul2(&mut self, out: usize, in_0: usize, in_1: usize, scaler: F) {
        todo!()
    }
    pub fn mul3(&mut self, out: usize, in_0: usize, in_1: usize, in_2: usize, scaler: F) {
        todo!()
    }
    pub fn assert_const(&mut self, out: usize, in_0: usize, constant: F) {
        todo!()
    }

    pub fn inner_product(
        &mut self,
        out: usize,
        in_0_array: &[usize],
        in_1_array: &[usize],
        scaler: F,
    ) {
        todo!()
    }
    pub fn inner_product_const(&mut self, out: usize, in_0_array: &[usize], in_1_array: &[F]) {
        todo!()
    }
    pub fn product_of_array(&mut self, out: usize, in_array: &[usize], scaler: F) {
        todo!()
    }

    pub fn define_table_type(&mut self, table_type: &'static str) {
        todo!()
    }
    pub fn add_input_item(&mut self, table_type: &'static str, cell: usize) {
        todo!()
    }
    pub fn add_table_item(&mut self, table_type: &'static str, cell: usize) {
        todo!()
    }

    /// Prepare the circuit. This is to build the circuit structure of lookup
    /// tables, and assign the layers and challenge levels to the cells.
    pub fn synthesize() {
        todo!()
    }
}
