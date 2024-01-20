use frontend::structs::{CellId, WireId};
use goldilocks::SmallField;

use crate::constants::{EVM_STACK_BIT_WIDTH, VALUE_BIT_WIDTH};

pub(in crate::instructions) mod chip_handler;
pub(in crate::instructions) mod uint;

fn i64_to_field<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from(x as u64)
    } else {
        -F::from((-x) as u64)
    }
}
#[derive(Clone, Debug)]
pub(super) struct ChipHandler {
    wire_out_id: WireId,
    records: Vec<usize>,
    count: usize,
}

/// Unsigned integer with `M` bits. C denotes the cell bit width.
#[derive(Clone, Debug)]
pub(crate) struct UInt<const M: usize, const C: usize> {
    values: Vec<CellId>,
}

pub(crate) type UInt64 = UInt<64, VALUE_BIT_WIDTH>;
pub(crate) type PCUInt = UInt64;
pub(crate) type TSUInt = UInt<56, 56>;
pub(crate) type StackUInt = UInt<{ EVM_STACK_BIT_WIDTH as usize }, { VALUE_BIT_WIDTH as usize }>;
