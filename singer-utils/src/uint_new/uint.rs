use crate::constants::{BYTE_BIT_WIDTH, RANGE_CHIP_BIT_WIDTH};
use crate::error::UtilError;
use crate::uint_new::util::{convert_decomp, pad_cells};
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder};

/// Unsigned integer with `M` total bits. `C` denotes the cell bit width.
/// Represented in little endian form.
pub struct UInt<const M: usize, const C: usize> {
    // TODO: the size of C should not be more than the size of the underlying field
    values: Vec<CellId>,
}

impl<const M: usize, const C: usize> UInt<M, C> {
    /// Return the `UInt` underlying cell id's
    fn values(&self) -> &[CellId] {
        &self.values
    }

    /// Builds a `UInt` instance from a set of cells that represent `RANGE_VALUES`
    /// assumes range_values are represented in little endian form
    fn from_range_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_values: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_different_sized_cell_values(
            circuit_builder,
            range_values,
            RANGE_CHIP_BIT_WIDTH,
            true,
        )
    }

    /// Builds a `UInt` instance from a set of cells that represent big-endian `BYTE_VALUES`
    fn from_bytes_big_endian<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, false)
    }

    /// Builds a `UInt` instance from a set of cells that represent little-endian `BYTE_VALUES`
    fn from_bytes_little_endian<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, true)
    }

    /// Builds a `UInt` instance from a set of cells that represent `BYTE_VALUES`
    fn from_bytes<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
        is_little_endian: bool,
    ) -> Result<Self, UtilError> {
        Self::from_different_sized_cell_values(
            circuit_builder,
            bytes,
            BYTE_BIT_WIDTH,
            is_little_endian,
        )
    }

    /// Builds a `UInt` instance from a set of cell values of a certain `CELL_WIDTH`
    fn from_different_sized_cell_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        cell_values: &[CellId],
        cell_width: usize,
        is_little_endian: bool,
    ) -> Result<Self, UtilError> {
        let max_cell_width = M.min(C);
        let mut values = convert_decomp(
            circuit_builder,
            cell_values,
            cell_width,
            max_cell_width,
            is_little_endian,
        )?;
        // TODO: is this safe, do we need to ensure that the padded cells are always 0?
        pad_cells(circuit_builder, &mut values, Self::N_OPERAND_CELLS);
        values.try_into()
    }
}

/// Construct `UInt` from `Vec<CellId>`
impl<const M: usize, const C: usize> TryFrom<Vec<CellId>> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: Vec<CellId>) -> Result<Self, Self::Error> {
        if values.len() != Self::N_OPERAND_CELLS {
            return Err(UtilError::UIntError(format!(
                "cannot construct UInt<{}, {}> from {} cells, requires {} cells",
                M,
                C,
                values.len(),
                Self::N_OPERAND_CELLS
            )));
        }

        Ok(Self { values })
    }
}

/// Construct `UInt` from `$[CellId]`
impl<const M: usize, const C: usize> TryFrom<&[CellId]> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: &[CellId]) -> Result<Self, Self::Error> {
        values.to_vec().try_into()
    }
}

#[cfg(test)]
mod tests {
    use crate::uint_new::uint::UInt;

    #[test]
    fn test_uint_from_cell_ids() {
        // 33 total bits and each cells holds just 4 bits
        // to hold all 33 bits without truncations, we'd need 9 cells
        // 9 * 4 = 36 > 33
        type UInt64 = UInt<33, 4>;
        assert!(UInt64::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).is_ok());
        assert!(UInt64::try_from(vec![1, 2, 3]).is_err());
    }

    #[test]
    fn test_uint_from_range_values() {
        // TODO: implement test
        //  first test without padding then test with padding, same for from_bytes
    }

    #[test]
    fn test_uint_from_bytes() {
        // TODO: implement test
    }
}
