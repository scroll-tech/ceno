use std::collections::HashMap;

use frontend::structs::WireId;
use gkr::structs::Circuit;
use goldilocks::SmallField;

use super::InputWiresInfo;
use crate::{chips::circuit_gadgets::pad_with_constant_circuit, error::ZKVMError};

pub struct MemoryChip<F: SmallField> {
    load_wires_id: HashMap<u8, WireId>,
    load_pad_circuit: Circuit<F>,

    store_wires_id: HashMap<u8, WireId>,
    store_pad_circuit: Circuit<F>,
}

impl<F: SmallField> MemoryChip<F> {
    pub fn new(
        prep_load_wires: &[InputWiresInfo],
        prep_store_wires: &[InputWiresInfo],
    ) -> Result<Self, ZKVMError> {
        let compute = |prep_wires: &[InputWiresInfo]| {
            let (pad_circuit, wires_in_id) = {
                let old_sizes = prep_load_wires
                    .iter()
                    .map(|wire_in| wire_in.n_instance * wire_in.instance_size)
                    .collect_vec();
                pad_with_constant_circuit(&F::ONE, &old_sizes)
            };
            let wires_id = prep_load_wires
                .iter()
                .zip(wires_in_id.iter())
                .map(|(info, wire_in_id)| (info.opcode, wire_in_id))
                .collect::<HashMap<u8, WireId>>();
            (pad_circuit, wires_id)
        };
        let (load_pad_circuit, load_wires_id) = compute(prep_load_wires);
        let (store_pad_circuit, store_wires_id) = compute(prep_store_wires);
        Self {
            load_wires_id,
            load_pad_circuit,
            store_wires_id,
            store_pad_circuit,
        }
    }
}
