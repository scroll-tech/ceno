use std::collections::HashMap;

use frontend::structs::{CellId, CircuitBuilder, MixedCell, WireId};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use crate::{constants::OpcodeType, error::ZKVMError, instructions::ChipChallenges};

use super::{
    circuit_gadgets::{frac_sum_pad_with_zero_frac, inv_pad_with_zero_frac},
    Chip, InputWiresInfo,
};

pub struct BytecodeChip<F: SmallField> {
    input_wires_id: HashMap<u8, WireId>,
    input_pad_circuit: Circuit<F>,

    pc_wire_id: WireId,
    bytecode_wire_id: WireId,
    table_circuit: Circuit<F>,

    rlc_wire_id: WireId,
    count_wire_id: WireId,
    table_pad_circuit: Circuit<F>,
}

impl<F: SmallField> BytecodeChip<F> {
    fn new(
        prep_wires: &[InputWiresInfo],
        challenges: &ChipChallenges,
        bytecode_size: usize,
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

        let (table_circuit, table_pad_circuit, pc_wire_id, bytecode_wire_id) = {
            let mut circuit_builder = CircuitBuilder::<F>::new();
            let (bytecode_wire_id, bytecode) = circuit_builder.create_wire_in(1);
            let (pc_wire_id, pc) = circuit_builder.create_wire_in(1);
            let rlc = circuit_builder.create_wire_out(1);
            circuit_builder.rlc(rlc[0], &[pc[0], bytecode[0]], challenges.bytecode());
        };
        let (table_pad_circuit, rlc_wire_id, count_wire_id) = {
            let old_sizes = vec![bytecode_size];
            frac_sum_pad_with_zero_frac(&old_sizes)
        };

        Self {
            input_wires_id,
            input_pad_circuit,
            table_circuit,
            pc_wire_id,
            bytecode_wire_id,
            rlc_wire_id: rlc_wire_id[0],
            count_wire_id: count_wire_id[0],
            table_pad_circuit,
        }
    }

    pub fn check_pc_opcode(
        circuit_builder: &CircuitBuilder<F>,
        bytecode_cell: CellId,
        pc: &[CellId],
        opcode: u8,
        challenges: &ChipChallenges,
    ) {
        let mut items = pc.iter().map(|x| (*x).into()).collect_vec();
        items.push(MixedCell::Constant(F::from(OpcodeType::JUMPDEST as u64)));
        circuit_builder.rlc_mixed(bytecode_cell, &items, challenges.bytecode());
    }

    pub fn check_pc_byte(
        circuit_builder: &CircuitBuilder<F>,
        bytecode_cell: CellId,
        pc: &[CellId],
        byte: CellId,
        challenges: &ChipChallenges,
    ) {
        let mut items = pc.to_vec();
        items.push(byte);
        circuit_builder.rlc(bytecode_cell, &items, challenges.bytecode());
    }
}
