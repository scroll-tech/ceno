use std::collections::HashMap;

use frontend::structs::{CellType, CircuitBuilder, ConstantType, GateType};
use goldilocks::SmallField;
use itertools::Itertools;

use crate::{
    structs::{Circuit, Gate1In, Gate2In, Gate3In, GateCIn, Layer},
    utils::ceil_log2,
};

impl<F: SmallField> Circuit<F> {
    /// Generate the circuit from circuit builder.
    pub fn new(circuit_builder: &CircuitBuilder<F>) -> Self {
        assert!(circuit_builder.n_layers.is_some());

        // Put cells into layers. Maintain two vectors: `layers_of_cell_id`
        // stores all cell ids in each layer; `wire_ids_in_layer` stores the
        // wire id of each cell in its layer.
        let n_layers = circuit_builder.n_layers.unwrap();
        let mut layers_of_cell_id = vec![vec![]; n_layers];
        let mut wire_ids_in_layer = vec![0; circuit_builder.cells.len()];
        for i in 0..circuit_builder.cells.len() {
            if let Some(layer) = circuit_builder.cells[i].layer {
                wire_ids_in_layer[i] = layers_of_cell_id[layer].len();
                layers_of_cell_id[layer].push(i);
            } else {
                panic!("The layer of the cell is not specified.");
            }
        }
        // The layers are numbered from the output to the inputs.
        layers_of_cell_id.reverse();

        let mut layers = (0..n_layers)
            .map(|_| Layer::<F> {
                add_consts: vec![],
                adds: vec![],
                mul2s: vec![],
                mul3s: vec![],
                assert_consts: vec![],
                copy_from: HashMap::new(),
                paste_to: HashMap::new(),
                num_vars: 0,
            })
            .collect_vec();

        // From the input layer to the output layer, construct the gates. If a
        // gate has the input from multiple previous layers, then we need to
        // copy them to the last layer.

        // Input layer if pasted from wires_in || other_witnesses.
        let (wires_in_cell_ids, other_witnesses_cell_ids, wires_out_cell_ids) = {
            let mut wires_in_cell_ids = vec![vec![]];
            let mut other_witnesses_cell_ids = vec![vec![]];
            let mut wires_out_cell_ids = vec![vec![]];
            for marked_cell in circuit_builder.marked_cells.iter() {
                match marked_cell.0 {
                    CellType::WireIn(id) => {
                        if wires_in_cell_ids.len() <= *id {
                            wires_in_cell_ids.resize(id + 1, vec![]);
                        }
                        wires_in_cell_ids[*id] = marked_cell.1.iter().map(|x| *x).collect();
                        wires_in_cell_ids[*id].sort();
                    }
                    CellType::OtherInWitness(id) => {
                        if other_witnesses_cell_ids.len() <= *id {
                            other_witnesses_cell_ids.resize(id + 1, vec![]);
                        }
                        other_witnesses_cell_ids[*id] = marked_cell.1.iter().map(|x| *x).collect();
                        other_witnesses_cell_ids[*id].sort();
                    }
                    CellType::WireOut(id) => {
                        if wires_out_cell_ids.len() <= *id {
                            wires_out_cell_ids.resize(id + 1, vec![]);
                        }
                        wires_out_cell_ids[*id] = marked_cell.1.iter().map(|x| *x).collect();
                        wires_out_cell_ids[*id].sort();
                    }
                }
            }
            (
                wires_in_cell_ids,
                other_witnesses_cell_ids,
                wires_out_cell_ids,
            )
        };

        let all_inputs = wires_in_cell_ids
            .iter()
            .chain(other_witnesses_cell_ids.iter())
            .collect_vec();
        let input_paste_to = &mut layers[n_layers - 1].paste_to;
        for (i, input_segment) in all_inputs.iter().enumerate() {
            input_paste_to.insert(
                i,
                input_segment
                    .iter()
                    .map(|cell_id| wire_ids_in_layer[*cell_id])
                    .collect_vec(),
            );
        }

        for layer_id in (0..n_layers - 1).rev() {
            // current_subsets: old_layer_id -> (old_wire_id, new_wire_id)
            // It only stores the wires not in the last layer.
            let new_layer_id = layer_id + 1;
            let subsets = {
                let mut subsets = HashMap::new();
                let mut wire_id_assigner =
                    layers_of_cell_id[new_layer_id].len().next_power_of_two();
                let mut update_subset = |old_cell_id: usize| {
                    let old_layer_id =
                        n_layers - 1 - circuit_builder.cells[old_cell_id].layer.unwrap();
                    if old_layer_id == new_layer_id {
                        return;
                    }
                    subsets
                        .entry(old_layer_id)
                        .or_insert(HashMap::new())
                        .insert(wire_ids_in_layer[old_cell_id], wire_id_assigner);
                    wire_id_assigner += 1;
                };
                for cell_id in layers_of_cell_id[layer_id].iter() {
                    let cell = &circuit_builder.cells[*cell_id];
                    for gate in cell.gates.iter() {
                        match gate {
                            GateType::Add(in_0, _) => {
                                update_subset(*in_0);
                            }
                            GateType::Mul2(in_0, in_1, _) => {
                                update_subset(*in_0);
                                update_subset(*in_1);
                            }
                            GateType::Mul3(in_0, in_1, in_2, _) => {
                                update_subset(*in_0);
                                update_subset(*in_1);
                                update_subset(*in_2);
                            }
                            _ => {}
                        }
                    }
                }
                layers[new_layer_id].num_vars = ceil_log2(wire_id_assigner) as usize;
                subsets
            };

            // Copy subsets from previous layers and put them into the last
            // layer.
            for (old_layer_id, old_wire_ids) in subsets.iter() {
                for (old_wire_id, new_wire_id) in old_wire_ids.iter() {
                    layers[new_layer_id]
                        .paste_to
                        .entry(*old_layer_id)
                        .or_insert(vec![])
                        .push(*new_wire_id);
                    layers[*old_layer_id]
                        .copy_from
                        .entry(new_layer_id)
                        .or_insert(vec![])
                        .push(*old_wire_id);
                }
            }

            // Compute gates with new wire ids accordingly.
            let current_wire_id = |old_cell_id: usize| -> usize {
                let old_layer_id = n_layers - 1 - circuit_builder.cells[old_cell_id].layer.unwrap();
                let old_wire_id = wire_ids_in_layer[old_cell_id];
                if old_layer_id == new_layer_id {
                    return old_wire_id;
                }
                *subsets
                    .get(&old_layer_id)
                    .unwrap()
                    .get(&old_wire_id)
                    .unwrap()
            };
            for (i, cell_id) in layers_of_cell_id[layer_id].iter().enumerate() {
                let cell = &circuit_builder.cells[*cell_id];
                if let Some(assert_const) = cell.assert_const {
                    layers[layer_id].assert_consts.push(GateCIn {
                        idx_out: i,
                        constant: ConstantType::Field(assert_const),
                    });
                }
                for gate in cell.gates.iter() {
                    match gate {
                        GateType::AddC(c) => {
                            layers[layer_id].add_consts.push(GateCIn {
                                idx_out: i,
                                constant: *c,
                            });
                        }
                        GateType::Add(in_0, scaler) => {
                            layers[layer_id].adds.push(Gate1In {
                                idx_in: current_wire_id(*in_0),
                                idx_out: i,
                                scaler: *scaler,
                            });
                        }
                        GateType::Mul2(in_0, in_1, scaler) => {
                            layers[layer_id].mul2s.push(Gate2In {
                                idx_in1: current_wire_id(*in_0),
                                idx_in2: current_wire_id(*in_1),
                                idx_out: i,
                                scaler: *scaler,
                            });
                        }
                        GateType::Mul3(in_0, in_1, in_2, scaler) => {
                            layers[layer_id].mul3s.push(Gate3In {
                                idx_in1: current_wire_id(*in_0),
                                idx_in2: current_wire_id(*in_1),
                                idx_in3: current_wire_id(*in_2),
                                idx_out: i,
                                scaler: *scaler,
                            });
                        }
                    }
                }
            }
        }

        layers[0].num_vars = ceil_log2(layers_of_cell_id[0].len()) as usize;

        let output_copy_from = wires_out_cell_ids
            .iter()
            .map(|cell_ids| {
                cell_ids
                    .iter()
                    .map(|cell_id| wire_ids_in_layer[*cell_id])
                    .collect_vec()
            })
            .collect_vec();

        Self {
            layers,
            output_copy_from,
            n_wires_in: wires_in_cell_ids.len(),
            n_other_witnesses: other_witnesses_cell_ids.len(),
        }
    }

    pub fn last_layer_ref(&self) -> &Layer<F> {
        self.layers.first().unwrap()
    }

    pub fn first_layer_ref(&self) -> &Layer<F> {
        self.layers.last().unwrap()
    }

    pub fn output_num_vars(&self) -> usize {
        self.last_layer_ref().num_vars
    }

    pub fn output_size(&self) -> usize {
        1 << self.last_layer_ref().num_vars
    }
}

impl<F: SmallField> Layer<F> {
    pub fn size(&self) -> usize {
        1 << self.num_vars
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
}
