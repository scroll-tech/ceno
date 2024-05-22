use ff::Field;
use ff_ext::ExtensionField;
use itertools::izip;
use simple_frontend::structs::{CellId, CircuitBuilder};

pub(crate) fn i64_to_base_field<E: ExtensionField>(x: i64) -> E::BaseField {
    if x >= 0 {
        E::BaseField::from(x as u64)
    } else {
        -E::BaseField::from((-x) as u64)
    }
}

pub(crate) fn add_assign_each_cell<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
    dest: &[CellId],
    src: &[CellId],
) {
    assert_eq!(dest.len(), src.len());
    for (dest, src) in izip!(dest, src) {
        circuit_builder.add(*dest, *src, E::BaseField::ONE);
    }
}
