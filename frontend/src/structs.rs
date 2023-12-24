use goldilocks::SmallField;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scaler.
#[derive(Clone, Debug)]
pub enum GateType<F: SmallField> {
    AddC(F),
    Add(usize, F),
    Mul2(usize, usize, F),
    Mul3(usize, usize, usize, F),
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
    /// How many challenges are needed to evaluate this cell. In the IOP
    /// protocol, this indicates in which round this cell can be computed.
    pub challenge_level: Option<usize>,
    /// The type of the cell, e.g., public input, witness, challenge, etc.
    pub cell_type: Option<CellType>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum CellType {
    PublicInput,
    Witness(usize),
    Challenge,
    Output,
}

/// Indicate the challenge used to construct the lookup circuit. In our case,
/// only one challenge is needed.
#[derive(Clone)]
pub struct TableChallenge {
    pub index: usize,
}

#[derive(Clone)]
pub(crate) struct TableData<F: SmallField> {
    pub(crate) table_items: Vec<usize>,
    pub(crate) table_items_const: Vec<F>,
    pub(crate) input_items: Vec<usize>,
    /// Indicate the challenge used to construct the lookup circuit.
    pub(crate) challenge: Option<TableChallenge>,
}

pub type TableType = usize;

pub struct CircuitBuilder<F: SmallField> {
    pub cells: Vec<Cell<F>>,

    /// Number of layers in the circuit.
    pub n_layers_of_gates: Option<usize>,
    /// Number of challenges in the circuit.
    pub n_challenges: usize,

    /// Collect all cells that have the same functionally. For example,
    /// public_input, witnesses, and challenge, etc.
    pub marked_cells: HashMap<CellType, HashSet<usize>>,

    /// Store all tables.
    pub(crate) tables: HashMap<TableType, TableData<F>>,
}
