use ff::Field;
use goldilocks::SmallField;

use crate::circuit::Circuit;

enum GateType<F: SmallField> {
    Add(usize, F),
    Mul2(usize, usize, F),
    Mul3(usize, usize, usize, F),
}

pub struct CellConnection<F: SmallField> {
    layer: usize,
    gates: Vec<GateType<F>>,
    assert_const: Option<F>,
}

pub struct CellValue<F: SmallField>(F);

pub struct ParallelCircuitBuilder<F: SmallField> {
    cell_conns: Vec<CellConnection<F>>,
}

trait CircuitBuilder<F: SmallField> {
    fn create_cell(&mut self) -> usize;
    fn add(&mut self, out: usize, in_0: usize, in_1: usize, scale: F);
    fn mul2(&mut self, out: usize, in_0: usize, in_1: usize, scale: F);
    fn mul3(&mut self, out: usize, in_0: usize, in_1: usize, in_2: usize, scale: F);
    fn assert_const(&mut self, out: usize, in_0: usize, constant: F);
    fn inner_product(&mut self, out: usize, in_0_array: &[usize], in_1_array: &[usize], scale: F);
    fn inner_product_const(&mut self, out: usize, in_0_array: &[usize], in_1_array: &[F]);
    fn product_of_array(&mut self, out: usize, in_array: &[usize], scale: F);

    fn create_circuit(&self) -> Circuit<F>;
}
