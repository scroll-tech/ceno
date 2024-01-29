use goldilocks::SmallField;

use crate::structs::{Cell, CellId, CellType, CircuitBuilder, GateType, LayerId};

mod base_opt;
mod derives;
mod ext_opt;

impl<Ext: SmallField> Cell<Ext> {
    pub fn new() -> Self {
        Self {
            layer: None,
            gates: vec![],
            assert_const: None,
            cell_type: None,
        }
    }
}

impl<Ext: SmallField> CircuitBuilder<Ext> {
    pub fn new() -> Self {
        Self {
            cells: vec![],
            n_layers: None,
            n_wires_in: 0,
            n_wires_out: 0,
        }
    }

    /// Prepare the circuit. This is to build the circuit structure of lookup
    /// tables, and assign the layers and challenge levels to the cells.
    pub fn configure(&mut self) {
        // Assign layers and challenge levels to all cells.
        for cell_id in 0..self.cells.len() {
            if matches!(self.cells[cell_id].cell_type, Some(CellType::In(_))) {
                self.cells[cell_id].layer = Some(0);
            }
        }

        let mut max_layer_id = 0;
        for i in 0..self.cells.len() {
            if self.cells[i].layer.is_none() {
                let _ = self.assign_layer(i);
            }
            if let Some(layer) = self.cells[i].layer {
                // todo: remove
                println!("Cell: {:?}", self.cells[i]);
                // assert!(layer > 0 || matches!(self.cells[i].cell_type, Some(CellType::In(_))));
                max_layer_id = max_layer_id.max(layer);
            }
        }
        self.n_layers = Some(max_layer_id + 1);

        // Force wire_out to be at the last layer.
        for i in 0..self.cells.len() {
            if matches!(self.cells[i].cell_type, Some(CellType::Out(_))) {
                self.cells[i].layer = Some(max_layer_id);
            }
        }
    }

    /// Recursively assign layers to all cells.
    fn assign_layer(&mut self, id: CellId) -> LayerId {
        if self.cells[id].gates.len() == 0 {
            self.cells[id].layer = Some(0);
            return 0;
        }
        if self.cells[id].layer.is_some() {
            return self.cells[id].layer.unwrap();
        }
        let mut prep_max_layer = 0;

        let cell = self.cells[id].clone();
        for gate in cell.gates.iter() {
            match gate {
                GateType::Add(in_0, _) => {
                    let prep_layer = self.assign_layer(*in_0);
                    prep_max_layer = std::cmp::max(prep_max_layer, prep_layer);
                }
                GateType::AddC(_) => prep_max_layer = std::cmp::max(prep_max_layer, 0),
                GateType::Mul2(in_0, in_1, _) => {
                    let prep_0_layer = self.assign_layer(*in_0);
                    let prep_1_layer = self.assign_layer(*in_1);
                    prep_max_layer =
                        std::cmp::max(prep_max_layer, std::cmp::max(prep_0_layer, prep_1_layer));
                }
                GateType::Mul3(in_0, in_1, in_2, _) => {
                    let prep_0_layer = self.assign_layer(*in_0);
                    let prep_1_layer = self.assign_layer(*in_1);
                    let prep_2_layer = self.assign_layer(*in_2);
                    prep_max_layer = std::cmp::max(
                        prep_max_layer,
                        std::cmp::max(prep_0_layer, std::cmp::max(prep_1_layer, prep_2_layer)),
                    );
                }
            }
        }
        self.cells[id].layer = Some(prep_max_layer + 1);
        prep_max_layer + 1
    }

    pub fn n_wires_in(&self) -> usize {
        self.n_wires_in
    }

    pub fn n_wires_out(&self) -> usize {
        self.n_wires_out
    }

    #[cfg(debug_assertions)]
    pub fn print_info(&self) {
        println!("The number of layers: {}", self.n_layers.as_ref().unwrap());
        println!("The number of cells: {}", self.cells.len());

        for (i, cell) in self.cells.iter().enumerate() {
            println!("Cell {}: {:?}", i, cell);
        }
    }
}
