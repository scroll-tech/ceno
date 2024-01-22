use goldilocks::SmallField;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

// we make use of three identifiers.
// For type safety we want different alias for those identifiers; while disallow arithmetics cross different identifiers.
// We achieve this via setting them to different primitive types.
// This works better/simpler than struct-wrapping
pub type TableType = u16;
pub type WireId = u16;
pub type LayerId = u32;
pub type CellId = usize;

#[derive(Clone, Copy, Debug, Serialize)]
pub enum ConstantType<F: SmallField> {
    Field(F),
    Challenge(usize),
    ChallengeScaled(usize, F),
    ChallengePow(usize, usize),
    ChallengePowScaled(usize, usize, F),
}

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scaler.
#[derive(Clone, Debug)]
pub enum GateType<F: SmallField> {
    AddC(ConstantType<F>),
    Add(CellId, ConstantType<F>),
    Mul2(CellId, CellId, ConstantType<F>),
    Mul3(CellId, CellId, CellId, ConstantType<F>),
}

/// Store wire structure of the circuit.
#[derive(Clone, Debug)]
pub struct Cell<F: SmallField> {
    /// The layer of the cell.
    pub layer: Option<LayerId>,
    /// The value of the cell is the sum of all gates.
    pub gates: Vec<GateType<F>>,
    /// The value of the cell should equal to a constant.
    pub assert_const: Option<F>,
    /// The type of the cell, e.g., public input, witness, challenge, etc.
    pub cell_type: Option<CellType>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug, Serialize)]
pub enum InType {
    Counter(usize),
    Constant(i64),
    Wire(WireId),
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug, Serialize)]
pub enum OutType {
    Wire(WireId),
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug, Serialize)]
pub enum CellType {
    In(InType),
    Out(OutType),
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum MixedCell<F: SmallField> {
    Constant(F),
    Cell(usize),
    CellExpr(usize, F, F),
}

impl<F: SmallField> From<CellId> for MixedCell<F> {
    fn from(cell_id: CellId) -> Self {
        MixedCell::Cell(cell_id)
    }
}

impl<F: SmallField> MixedCell<F> {
    pub fn add(&self, shift: F) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c + shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, F::ONE, shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh + shift),
        }
    }
    pub fn sub(&self, shift: F) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c - shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, F::ONE, -shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh - shift),
        }
    }
    pub fn mul(&self, scaler: F) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scaler),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, scaler, F::ZERO),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scaler, *sh * scaler),
        }
    }
    pub fn expr(&self, scaler: F, shift: F) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scaler + shift),
            MixedCell::Cell(c) => MixedCell::Cell(*c),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scaler, *sh * shift),
        }
    }
}

#[derive(Clone)]
pub(crate) struct TableData<F: SmallField> {
    pub(crate) table_items: Vec<CellId>,
    pub(crate) table_items_const: Vec<F>,
    pub(crate) input_items: Vec<CellId>,
    /// Indicate the challenge used to construct the lookup circuit.
    pub(crate) challenge: Option<ConstantType<F>>,
    /// Witness vector index.
    pub(crate) count_witness_cell_type: CellType,
}

pub struct CircuitBuilder<F: SmallField> {
    pub cells: Vec<Cell<F>>,

    /// Number of layers in the circuit.
    pub n_layers: Option<u32>,

    /// Collect all cells that have the same functionally. For example,
    /// public_input, witnesses, and challenge, etc.
    pub marked_cells: HashMap<CellType, HashSet<CellId>>,

    /// Store all tables.
    pub(crate) tables: HashMap<TableType, TableData<F>>,

    pub(crate) n_wires_in: usize,
    pub(crate) n_wires_out: usize,
}
