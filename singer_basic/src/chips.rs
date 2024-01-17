use gkr::structs::Circuit;
use goldilocks::SmallField;

pub mod circuit_gadgets;
pub struct ChipCircuitGadgets<F: SmallField> {
    inv_sum_circuit: Circuit<F>,
    frac_sum_circuit: Circuit<F>,
    product_circuit: Circuit<F>,
}
