use ff::Field;
use goldilocks::SmallField;
use itertools::izip;
use simple_frontend::structs::{CellId, CircuitBuilder};

pub(crate) mod chip_handler;
pub(crate) mod uint;

pub(crate) fn i64_to_base_field<F: SmallField>(x: i64) -> F::BaseField {
    if x >= 0 {
        F::BaseField::from(x as u64)
    } else {
        -F::BaseField::from((-x) as u64)
    }
}

pub(crate) fn add_assign_each_cell<F: SmallField>(
    circuit_builder: &mut CircuitBuilder<F>,
    dest: &[CellId],
    src: &[CellId],
) {
    assert_eq!(dest.len(), src.len());
    for (dest, src) in izip!(dest, src) {
        circuit_builder.add(*dest, *src, F::BaseField::ONE);
    }
}
