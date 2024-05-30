use crate::error::UtilError;
use simple_frontend::structs::CellId;

/// Unsigned integer with `M` total bits. `C` denotes the cell bit width.
pub struct UInt<const M: usize, const C: usize> {
    values: Vec<CellId>,
}

impl<const M: usize, const C: usize> UInt<M, C> {
    // TODO: add documentation
    fn values(&self) -> &[CellId] {
        &self.values
    }

    // TODO: add documentation
    fn from_range_values() {
        // need to implement bit fitting (into new cell types)
        todo!()
    }

    // TODO: add documentation
    fn from_bytes_bit_endian() {
        // need to implement bit fitting (into new cell types first)
        todo!()
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
}
