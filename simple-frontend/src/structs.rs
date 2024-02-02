use ff::Field;
use goldilocks::SmallField;
use serde::Serialize;
use std::hash::Hash;

// we make use of three identifiers.
// For type safety we want different alias for those identifiers; while disallow arithmetics cross different identifiers.
// We achieve this via setting them to different primitive types.
// This works better/simpler than struct-wrapping
pub type ChallengeId = u8;
pub type TableType = u16;
pub type WireId = u16;
pub type LayerId = u32;
pub type CellId = usize;

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq, Hash)]
pub struct ChallengeConst {
    pub challenge: ChallengeId,
    pub exp: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum ConstantType<F: SmallField> {
    Field(F::BaseField),
    Challenge(ChallengeConst, usize),
    ChallengeScaled(ChallengeConst, usize, F::BaseField),
}

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scalar.
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
    pub assert_const: Option<F::BaseField>,
    /// The type of the cell, e.g., public input, witness, challenge, etc.
    pub cell_type: Option<CellType>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug, Serialize)]
pub enum InType {
    /// Constant keeps the same for all instances.
    Constant(i64),
    /// Constant(num_vars) acts like a counter (0, 1, 2, ...) through all
    /// instances. Each instance hold 1 << num_vars of them.
    Counter(usize),
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
    Constant(F::BaseField),
    Cell(usize),
    CellExpr(usize, F::BaseField, F::BaseField),
}

impl<F: SmallField> From<CellId> for MixedCell<F> {
    fn from(cell_id: CellId) -> Self {
        MixedCell::Cell(cell_id)
    }
}

impl<F: SmallField> MixedCell<F> {
    pub fn add(&self, shift: F::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c + shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, F::BaseField::ONE, shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh + shift),
        }
    }
    pub fn sub(&self, shift: F::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c - shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, F::BaseField::ONE, -shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh - shift),
        }
    }
    pub fn mul(&self, scalar: F::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scalar),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, scalar, F::BaseField::ZERO),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scalar, *sh * scalar),
        }
    }
    pub fn expr(&self, scalar: F::BaseField, shift: F::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scalar + shift),
            MixedCell::Cell(c) => MixedCell::Cell(*c),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scalar, *sh * shift),
        }
    }
}

pub struct CircuitBuilder<F: SmallField> {
    pub cells: Vec<Cell<F>>,

    /// Number of layers in the circuit.
    pub n_layers: Option<u32>,

    pub(crate) n_wires_in: usize,
    pub(crate) n_wires_out: usize,
}
