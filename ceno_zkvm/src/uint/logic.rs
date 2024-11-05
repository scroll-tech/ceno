use ff_ext::ExtensionField;
use itertools::izip;

use super::UIntLimbs;
use crate::{
    ROMType, circuit_builder::CircuitBuilder, error::ZKVMError, expression::ToExpr,
    tables::OpsTable, witness::LkMultiplicity,
};

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
        for (a_byte, b_byte, c_byte) in izip!(&a.limbs, &b.limbs, &c.limbs) {
            cb.logic_u8(rom_type, a_byte.expr(), b_byte.expr(), c_byte.expr())?;
        }
        Ok(())
    }

    pub fn logic_assign<OP: OpsTable>(lk_multiplicity: &mut LkMultiplicity, a: u64, b: u64) {
        for i in 0..M.div_ceil(8) {
            let a_byte = (a >> (i * 8)) & 0xff;
            let b_byte = (b >> (i * 8)) & 0xff;
            lk_multiplicity.logic_u8::<OP>(a_byte, b_byte);
        }
    }
}
