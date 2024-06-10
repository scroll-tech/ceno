use crate::error::UtilError;
use crate::uint_new::uint::UInt;
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder};

// TODO: test
impl<const M: usize, const C: usize> UInt<M, C> {
    /// Little-endian addition.
    /// Assumes users will check the correct range of the result themselves.
    // Addition of A + B with limbs [a, b, c] and [d, e, f] respectively
    //
    // cell_modulo = 2^C
    // addend_0 - a                 b                   c
    // addend_1 - d                 e                   f
    //            --------------------------------------------------
    // result   - (a + d) % 2^C    (b + e) % 2^C       (c + f) % 2^C
    // carry    - (a + d) // 2^C   (b + e) // 2^C      (c + f) % 2^C
    //
    // every limb in addend_0 and addend_1 exists in the range [0, ..., 2^C - 1]
    // after summing two limb values, the result exists in [0, ..., 2^(C+1) - 2]
    // the carry value is either 0 or 1,
    // it cannot be >= 2 as that will require result value >= 2^(C+1)
    //
    // assuming result range check, there is a unique carry vector that makes all
    // constraint pass.
    // if a + b > max_cell_value then carry must be set to 1 (if not range check fails)
    // if a + b <= max_cell_value then carry must be set to 0 (if not range check fails)
    //
    // NOTE: this function doesn't perform the required range check!
    pub fn add_unsafe<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        addend_0: &UInt<M, C>,
        addend_1: &UInt<M, C>,
        carry: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let result: UInt<M, C> = circuit_builder
            .create_cells(Self::N_OPERAND_CELLS)
            .try_into()?;

        for i in 0..Self::N_OPERAND_CELLS {
            let (a, b, result) = (addend_0.values[i], addend_1.values[i], result.values[i]);

            circuit_builder.add(result, a, E::BaseField::ONE);
            circuit_builder.add(result, b, E::BaseField::ONE);

            if i < carry.len() {
                circuit_builder.add(result, carry[i], -E::BaseField::from(1 << C));
            }

            if i > 0 && i - 1 < carry.len() {
                circuit_builder.add(result, carry[i - 1], E::BaseField::ONE);
            }
        }

        Ok(result)
    }
}
