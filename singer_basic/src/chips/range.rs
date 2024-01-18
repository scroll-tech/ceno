use std::collections::HashMap;

use frontend::structs::{CircuitBuilder, WireId};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use crate::instructions::ChipChallenges;

use super::InputWiresInfo;
use crate::chips::circuit_gadgets::inv_pad_with_zero_frac;

pub struct RangeChip<F: SmallField> {
    input_wires_id: HashMap<u8, WireId>,
    input_pad_circuit: Circuit<F>,

    table_circuit: Circuit<F>,
}

impl<F: SmallField> RangeChip<F> {
    pub fn new(
        prep_wires: &[InputWiresInfo],
        challenges: &ChipChallenges,
    ) -> Result<Self, ZKVMError> {
        let (input_pad_circuit, wires_in_id) = {
            let old_sizes = prep_wires
                .iter()
                .map(|wire_in| {
                    #[cfg(debug_assertions)]
                    assert_eq!(
                        wire_in.instance_size,
                        wire_in.instance_size.next_power_of_two()
                    );
                    wire_in.n_instance * wire_in.instance_size
                })
                .collect_vec();
            inv_pad_with_zero_frac(&old_sizes)
        };
        let input_wires_id = prep_wires
            .iter()
            .zip(wires_in_id.iter())
            .map(|(info, wire_in_id)| (info.opcode, wire_in_id))
            .collect::<HashMap<u8, WireId>>();

        let (table_circuit, _, _) = {
            let mut circuit_builder = CircuitBuilder::<F>::new();
            let (_, cells) = circuit_builder.create_wire_in(1);
            let rlc = circuit_builder.create_wire_out(1);
            circuit_builder.rlc(rlc[0], &[cells[0]], challenges.range());
        };
        Self {
            input_wires_id,
            input_pad_circuit,
            table_circuit,
        }
    }
}
