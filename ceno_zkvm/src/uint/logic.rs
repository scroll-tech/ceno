use ff_ext::ExtensionField;
use itertools::izip;

use super::UIntLimbs;
use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, expression::ToExpr, ROMType};

// Only implemented for u8 limbs.
impl<const M: usize, E: ExtensionField> UIntLimbs<M, 8, E> {
    /// Assert `rom_type(a, b) = c` and range-check `a, b, c`.
    /// This works with a lookup for each u8 limb.
    pub fn logic(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
        a: &Self,
        b: &Self,
        c: &Self,
    ) -> Result<(), ZKVMError> {
        for (a_byte, b_byte, c_byte) in izip!(a.limbs.iter(), b.limbs.iter(), c.limbs.iter()) {
            cb.logic_u8(rom_type, a_byte.expr(), b_byte.expr(), c_byte.expr())?;
        }
        Ok(())
    }
}
