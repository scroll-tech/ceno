use crate::error::UtilError;
use simple_frontend::structs::CellId;

/// Unsigned integer with `M` total bits. `C` denotes the cell bit width.
pub struct UInt<const M: usize, const C: usize> {
    // TODO: handle access control
    pub values: Vec<CellId>,
}

// do we need another try from for the Vec<CellId>??
// we convert the slice to a vec
// won't make sense to do that for a Vec also
// input vec expected Self(vec)
// input slice expected slice -> vec -> Self(vec)
// hence the vec can come first

// TODO: add documentation + test
impl<const M: usize, const C: usize> TryFrom<Vec<CellId>> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: Vec<CellId>) -> Result<Self, Self::Error> {
        if values.len() != Self::N_OPERAND_CELLS {
            // TODO: think about error handling, might need something more specific
            return Err(UtilError::UIntError);
        }

        Ok(Self { values })
    }
}

// TODO: add documentation + test
impl<const M: usize, const C: usize> TryFrom<&[CellId]> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: &[CellId]) -> Result<Self, Self::Error> {
        values.to_vec().try_into()
    }
}
