use std::collections::HashMap;

use frontend::structs::WireId;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use itertools::Itertools;

use crate::error::ZKVMError;

use super::{circuit_gadgets::pad_with_constant_circuit, InputWiresInfo};

pub struct GlobalStateChip<F: SmallField> {
    state_in_wires_id: HashMap<u8, WireId>,
    state_in_pad_circuit: Circuit<F>,

    state_out_wires_id: HashMap<u8, WireId>,
    state_out_pad_circuit: Circuit<F>,
}

impl<F: SmallField> GlobalStateChip<F> {
    pub fn new(
        prep_state_in_wires: &[InputWiresInfo],
        prep_state_out_wires: &[InputWiresInfo],
    ) -> Result<Self, ZKVMError> {
        let compute = |prep_wires: &[InputWiresInfo]| {
            let (pad_circuit, wires_in_id) = {
                let old_sizes = prep_state_in_wires
                    .iter()
                    .map(|wire_in| wire_in.n_instance * wire_in.instance_size)
                    .collect_vec();
                pad_with_constant_circuit(&F::ONE, &old_sizes)
            };
            let wires_id = prep_state_in_wires
                .iter()
                .zip(wires_in_id.iter())
                .map(|(info, wire_in_id)| (info.opcode, wire_in_id))
                .collect::<HashMap<u8, WireId>>();
            (pad_circuit, wires_id)
        };
        let (state_in_pad_circuit, state_in_wires_id) = compute(prep_state_in_wires);
        let (state_out_pad_circuit, state_out_wires_id) = compute(prep_state_out_wires);
        Self {
            state_in_wires_id,
            state_in_pad_circuit,
            state_out_wires_id,
            state_out_pad_circuit,
        }
    }
}
