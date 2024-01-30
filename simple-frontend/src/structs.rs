use ff::Field;
use goldilocks::SmallField;
use serde::Serialize;
use std::{hash::Hash, marker::PhantomData};

// We make use of the following identifiers.
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
pub enum ConstantType<Ext: SmallField> {
    Field(Ext::BaseField),
    /// ChallengeConst is an extension field element represents a power of ChallengeId.
    /// The usize here denotes the `usize`-th base field element of the const.
    Challenge(ChallengeConst, usize),
    ChallengeScaled(ChallengeConst, usize, Ext::BaseField),
}

/// Represent a gate in the circuit. The inner variables denote the input
/// indices and scalar.
#[derive(Clone, Debug)]
pub enum GateType<Ext: SmallField> {
    AddC(ConstantType<Ext>),
    Add(CellId, ConstantType<Ext>),
    Mul2(CellId, CellId, ConstantType<Ext>),
    Mul3(CellId, CellId, CellId, ConstantType<Ext>),
}

/// Store wire structure of the circuit.
#[derive(Clone, Debug)]
pub struct Cell<Ext: SmallField> {
    /// The layer of the cell.
    pub layer: Option<LayerId>,
    /// The value of the cell is the sum of all gates.
    pub gates: Vec<GateType<Ext>>,
    /// The value of the cell should equal to a constant.
    pub assert_const: Option<Ext::BaseField>,
    /// The type of the cell, e.g., public input, witness, challenge, etc.
    pub cell_type: Option<CellType>,
}

/// An ExtCell consists DEGREE number of cells.
#[derive(Clone, Debug)]
pub struct ExtCellId<Ext: SmallField> {
    pub cells: Vec<CellId>,
    pub phantom: PhantomData<Ext>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug, Serialize)]
pub enum InType {
    /// Constant keeps the same for all instances.
    Constant(i64),
    /// Constant(num_vars) acts like a counter (0, 1, 2, ...) through all
    /// instances. Each instance holds 1 << num_vars of them.
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

/// A MixedCell can be a constant, a cell, or a Cell Expression
#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum MixedCell<Ext: SmallField> {
    Constant(Ext::BaseField),
    Cell(CellId),
    CellExpr(CellId, Ext::BaseField, Ext::BaseField),
}

impl<Ext: SmallField> From<CellId> for MixedCell<Ext> {
    fn from(cell_id: CellId) -> Self {
        MixedCell::Cell(cell_id)
    }
}

impl<Ext: SmallField> MixedCell<Ext> {
    pub fn add(&self, shift: Ext::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c + shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, Ext::BaseField::ONE, shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh + shift),
        }
    }
    pub fn sub(&self, shift: Ext::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c - shift),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, Ext::BaseField::ONE, -shift),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s, *sh - shift),
        }
    }
    pub fn mul(&self, scalar: Ext::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scalar),
            MixedCell::Cell(c) => MixedCell::CellExpr(*c, scalar, Ext::BaseField::ZERO),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scalar, *sh * scalar),
        }
    }
    pub fn expr(&self, scalar: Ext::BaseField, shift: Ext::BaseField) -> Self {
        match self {
            MixedCell::Constant(c) => MixedCell::Constant(*c * scalar + shift),
            MixedCell::Cell(c) => MixedCell::Cell(*c),
            MixedCell::CellExpr(c, s, sh) => MixedCell::CellExpr(*c, *s * scalar, *sh * shift),
        }
    }
}

pub struct CircuitBuilder<Ext: SmallField> {
    pub cells: Vec<Cell<Ext>>,

    /// Number of layers in the circuit.
    pub n_layers: Option<u32>,

    pub(crate) n_wires_in: usize,
    pub(crate) n_wires_out: usize,
}
