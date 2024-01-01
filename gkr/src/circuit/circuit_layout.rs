use core::fmt;
use std::collections::HashMap;

use frontend::structs::{CellType, CircuitBuilder, ConstantType, GateType};
use goldilocks::SmallField;
use itertools::Itertools;

use crate::{
    structs::{Circuit, Gate1In, Gate2In, Gate3In, GateCIn, Layer},
    utils::{ceil_log2, MatrixMLEColumnFirst, MatrixMLERowFirst},
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
                copy_to: HashMap::new(),
                paste_from: HashMap::new(),
                num_vars: 0,
                max_previous_num_vars: 0,
            })
            .collect_vec();

        // From the input layer to the output layer, construct the gates. If a
        // gate has the input from multiple previous layers, then we need to
        // copy them to the last layer.

        // Input layer if pasted from wires_in || other_witnesses.
        let (wires_in_cell_ids, wires_out_cell_ids) = {
            let mut wires_in_cell_ids = vec![vec![]; circuit_builder.n_wires_in()];
            let mut wires_out_cell_ids = vec![vec![]; circuit_builder.n_wires_out()];
            for marked_cell in circuit_builder.marked_cells.iter() {
                match marked_cell.0 {
                    CellType::WireIn(id) => {
                        wires_in_cell_ids[*id] = marked_cell.1.iter().map(|x| *x).collect();
                        wires_in_cell_ids[*id].sort();
                    }
                    CellType::WireOut(id) => {
                        wires_out_cell_ids[*id] = marked_cell.1.iter().map(|x| *x).collect();
                        wires_out_cell_ids[*id].sort();
                    }
                }
            }
            (wires_in_cell_ids, wires_out_cell_ids)
        };

        let input_paste_from = &mut layers[n_layers - 1].paste_from;
        for (i, wire_in) in wires_in_cell_ids.iter().enumerate() {
            input_paste_from.insert(
                i,
                wire_in
                    .iter()
                    .enumerate()
                    .map(|(i, cell_id)| {
                        // Each wire_in should be assigned with a consecutive
                        // input layer segment. Then we can use a special
                        // sumcheck protocol to prove it.
                        assert!(
                            i == 0
                                || wire_ids_in_layer[*cell_id]
                                    == wire_ids_in_layer[wire_in[i - 1]] + 1
                        );
                        wire_ids_in_layer[*cell_id]
                    })
                    .collect_vec(),
            );
        }
        layers[n_layers - 1].max_previous_num_vars =
            ceil_log2(wires_in_cell_ids.iter().map(|x| x.len()).max().unwrap());

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
                        .paste_from
                        .entry(*old_layer_id)
                        .or_insert(vec![])
                        .push(*new_wire_id);
                    layers[*old_layer_id]
                        .copy_to
                        .entry(new_layer_id)
                        .or_insert(vec![])
                        .push(*old_wire_id);
                }
            }
            layers[new_layer_id].max_previous_num_vars =
                layers[new_layer_id].max_previous_num_vars.max(ceil_log2(
                    layers[new_layer_id]
                        .paste_from
                        .iter()
                        .map(|(_, old_wire_ids)| old_wire_ids.len())
                        .max()
                        .unwrap_or(1),
                ));
            layers[layer_id].max_previous_num_vars = layers[new_layer_id].num_vars;

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

        let output_copy_to = wires_out_cell_ids
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
            output_copy_to,
            n_wires_in: circuit_builder.n_wires_in(),
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

    pub fn max_previous_num_vars(&self) -> usize {
        self.max_previous_num_vars
    }

    pub fn max_previous_size(&self) -> usize {
        1 << self.max_previous_num_vars
    }

    pub fn paste_from_fix_variables_eq(
        &self,
        old_layer_id: usize,
        current_point_eq: &[F],
    ) -> Vec<F> {
        assert_eq!(current_point_eq.len(), self.size());
        self.paste_from
            .get(&old_layer_id)
            .unwrap()
            .as_slice()
            .fix_row_col_first(current_point_eq, self.max_previous_num_vars)
    }

    pub fn paste_from_eval_eq(
        &self,
        old_layer_id: usize,
        current_point_eq: &[F],
        subset_point_eq: &[F],
    ) -> F {
        assert_eq!(current_point_eq.len(), self.size());
        assert_eq!(subset_point_eq.len(), self.max_previous_size());
        self.paste_from
            .get(&old_layer_id)
            .unwrap()
            .as_slice()
            .eval_col_first(current_point_eq, subset_point_eq)
    }

    pub fn copy_to_fix_variables(&self, new_layer_id: usize, subset_point_eq: &[F]) -> Vec<F> {
        let old_wire_ids = self.copy_to.get(&new_layer_id).unwrap();
        old_wire_ids
            .as_slice()
            .fix_row_row_first(subset_point_eq, self.num_vars)
    }

    pub fn copy_to_eval_eq(
        &self,
        new_layer_id: usize,
        subset_point_eq: &[F],
        current_point_eq: &[F],
    ) -> F {
        self.copy_to
            .get(&new_layer_id)
            .unwrap()
            .as_slice()
            .eval_row_first(subset_point_eq, current_point_eq)
    }
}

impl<F: SmallField> fmt::Debug for Layer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Layer {{")?;
        writeln!(f, "  num_vars: {}", self.num_vars)?;
        writeln!(f, "  max_previous_num_vars: {}", self.max_previous_num_vars)?;
        writeln!(f, "  adds: ")?;
        for add in self.adds.iter() {
            writeln!(f, "    {:?}", add)?;
        }
        writeln!(f, "  mul2s: ")?;
        for mul2 in self.mul2s.iter() {
            writeln!(f, "    {:?}", mul2)?;
        }
        writeln!(f, "  mul3s: ")?;
        for mul3 in self.mul3s.iter() {
            writeln!(f, "    {:?}", mul3)?;
        }
        writeln!(f, "  assert_consts: ")?;
        for assert_const in self.assert_consts.iter() {
            writeln!(f, "    {:?}", assert_const)?;
        }
        writeln!(f, "  copy_to: {:?}", self.copy_to)?;
        writeln!(f, "  paste_from: {:?}", self.paste_from)?;
        writeln!(f, "}}")
    }
}

impl<F: SmallField> fmt::Debug for Circuit<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Circuit {{")?;
        writeln!(f, "  n_wires_in: {}", self.n_wires_in)?;
        writeln!(f, "  layers: ")?;
        for layer in self.layers.iter() {
            writeln!(f, "    {:?}", layer)?;
        }
        writeln!(f, "  output_copy_to: {:?}", self.output_copy_to)?;
        writeln!(f, "}}")
    }
}
