use std::collections::HashMap;

use frontend::structs::{CellId, CircuitBuilder, WireId};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use super::InputWiresInfo;
use crate::{
    chips::circuit_gadgets::pad_with_constant_circuit, error::ZKVMError, instructions::ChipChallenges,
};

pub struct StackChip<F: SmallField> {
    pop_wires_id: HashMap<u8, WireId>,
    pop_pad_circuit: Circuit<F>,

    push_wires_id: HashMap<u8, WireId>,
    push_pad_circuit: Circuit<F>,
}

impl<F: SmallField> StackChip<F> {
    pub fn new(
        prep_pop_wires: &[InputWiresInfo],
        prep_push_wires: &[InputWiresInfo],
    ) -> Result<Self, ZKVMError> {
        let compute = |prep_wires: &[InputWiresInfo]| {
            let (pad_circuit, wires_in_id) = {
                let old_sizes = prep_pop_wires
                    .iter()
                    .map(|wire_in| wire_in.n_instance * wire_in.instance_size)
                    .collect_vec();
                pad_with_constant_circuit(&F::ONE, &old_sizes)
            };
            let wires_id = prep_pop_wires
                .iter()
                .zip(wires_in_id.iter())
                .map(|(info, wire_in_id)| (info.opcode, wire_in_id))
                .collect::<HashMap<u8, WireId>>();
            (pad_circuit, wires_id)
        };
        let (pop_pad_circuit, pop_wires_id) = compute(prep_pop_wires);
        let (push_pad_circuit, push_wires_id) = compute(prep_push_wires);
        Self {
            pop_wires_id,
            pop_pad_circuit,
            push_wires_id,
            push_pad_circuit,
        }
    }

    pub fn pop_values(
        circuit_builder: &mut CircuitBuilder<F>,
        pop_cell: CellId,
        stack_top: CellId,
        stack_ts: CellId,
        values: &[CellId],
        challenges: &ChipChallenges,
    ) {
        let stack_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(stack_rlc, values, challenges.record_item_rlc());
        circuit_builder.rlc(
            pop_cell,
            &[stack_top, stack_ts, stack_rlc],
            challenges.stack(),
        );
    }

    pub fn push_values(
        circuit_builder: &mut CircuitBuilder<F>,
        pop_cell: CellId,
        stack_top: CellId,
        stack_ts: CellId,
        values: &[CellId],
        challenges: &ChipChallenges,
    ) {
        let stack_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(stack_rlc, values, challenges.record_item_rlc());
        circuit_builder.rlc(
            pop_cell,
            &[stack_top, stack_ts, stack_rlc],
            challenges.stack(),
        );
    }
}
