use goldilocks::SmallField;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

#[derive(Clone, Copy, Debug, Serialize)]
pub enum ConstantType<F: SmallField> {
    Field(F),
    Challenge(usize),
    Challenge2(usize), // challenge^2
    Challenge3(usize), // challenge^3
    Challenge4(usize), // challenge^4
}

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scaler.
#[derive(Clone, Debug)]
pub enum GateType<F: SmallField> {
    AddC(ConstantType<F>),
    Add(usize, ConstantType<F>),
    Mul2(usize, usize, ConstantType<F>),
    Mul3(usize, usize, usize, ConstantType<F>),
}

/// Store wire structure of the circuit.
#[derive(Clone, Debug)]
pub struct Cell<F: SmallField> {
    /// The layer of the cell.
    pub layer: Option<usize>,
    /// The value of the cell is the sum of all gates.
    pub gates: Vec<GateType<F>>,
    /// The value of the cell should equal to a constant.
    pub assert_const: Option<F>,
    /// The type of the cell, e.g., public input, witness, challenge, etc.
    pub cell_type: Option<CellType>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum CellType {
    ConstantIn(i64), // just for implementation convenience.
    WireIn(usize),
    WireOut(usize),
}

#[derive(Clone)]
pub(crate) struct TableData<F: SmallField> {
    pub(crate) table_items: Vec<usize>,
    pub(crate) table_items_const: Vec<F>,
    pub(crate) input_items: Vec<usize>,
    /// Indicate the challenge used to construct the lookup circuit.
    pub(crate) challenge: Option<ConstantType<F>>,
    /// Witness vector index.
    pub(crate) count_witness_cell_type: CellType,
}

pub type TableType = usize;

pub struct CircuitBuilder<F: SmallField> {
    pub cells: Vec<Cell<F>>,

    /// Number of layers in the circuit.
    pub n_layers: Option<usize>,

    /// Collect all cells that have the same functionally. For example,
    /// public_input, witnesses, and challenge, etc.
    pub marked_cells: HashMap<CellType, HashSet<usize>>,

    /// Store all tables.
    pub(crate) tables: HashMap<TableType, TableData<F>>,

    pub(crate) n_wires_in: usize,
    pub(crate) n_wires_out: usize,
}
