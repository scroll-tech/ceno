use ff::Field;
use ff_ext::ExtensionField;
use itertools::izip;
use simple_frontend::structs::{CellId, CircuitBuilder};

// TODO(Matthias): Check whether we need this function.
#[allow(dead_code)]
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

// split single u64 value into W slices, each slice got C bits.
// all the rest slices will be filled with 0 if W x C > 64
pub fn u64vec<const W: usize, const C: usize>(x: u64) -> [u64; W] {
    assert!(C <= 64);
    let mut x = x;
    let mut ret = [0; W];
    for item in &mut ret {
        *item = x & ((1 << C) - 1);
        x >>= C;
    }
    ret
}
