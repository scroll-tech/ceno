use std::{cell::RefCell, collections::HashMap, sync::Arc};

use goldilocks::SmallField;

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scaler.
enum GateType<F: SmallField> {
    Add(usize, F),
    Mul2(usize, usize, F),
    Mul3(usize, usize, usize, F),
}

/// Store wire structure of the circuit.
pub struct Cell<F: SmallField> {
    pub layer: Option<usize>,
    /// Indicate the value of the cell is the sum of all gates.
    pub gates: Vec<GateType<F>>,
    /// Indicate the value of the cell should equal to a constant.
    pub assert_const: Option<F>,
    /// How many challenges are needed to evaluate this cell. In the IOP
    /// protocol, this indicates in which round this cell can be computed.
    pub challenge_level: Option<usize>,
    /// Whether it is a challenge cell and its index.
    pub challenge: Option<usize>,
}

pub(crate) type SharedCells<F: SmallField> = Arc<RefCell<Vec<Cell<F>>>>;

pub struct CircuitBuilder<F: SmallField> {
    pub cells: SharedCells<F>,
    pub challenges: Vec<usize>,

    pub marked_cells: Vec<Vec<usize>>,
    pub(crate) lookup_builder: LookupBuilder<F>,
}

/// Indicate the challenge used to construct the lookup circuit. In our case,
/// only one challenge is needed.
pub(crate) struct TableChallenge {
    pub(crate) challenge: usize,
}

pub(crate) struct TableData<F: SmallField> {
    pub(crate) table_items: Vec<usize>,
    pub(crate) table_items_const: Vec<F>,
    pub(crate) input_items: Vec<usize>,
    /// Indicate the challenge used to construct the lookup circuit.
    pub(crate) challenge: Option<TableChallenge>,
}

/// Store information to build lookup circuits.
pub(crate) struct LookupBuilder<F: SmallField> {
    pub(crate) cells: SharedCells<F>,
    /// Store all tables.
    pub(crate) tables: Vec<TableData<F>>,
}
