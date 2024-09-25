use std::mem::MaybeUninit;

use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::constants::UInt,
    set_val,
    uint::UIntLimbs,
    witness::LkMultiplicity,
    Value,
};

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// The equation is enforced `lhs - rhs == diff - (lt * range)`.
#[derive(Clone, Debug)]
pub struct LtGadget<E: ExtensionField> {
    /// `1` when `lhs < rhs`, `0` otherwise.
    lt: WitIn,
    /// `diff` equals `lhs - rhs` if `lhs >= rhs`,`lhs - rhs + range` otherwise.
    diff: UInt<E>,
}

impl<E: ExtensionField> LtGadget<E> {
    pub fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        lhs: Expression<E>,
        rhs: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        let lt = cb.create_witin(|| "lt")?;
        let diff = UIntLimbs::new(|| "diff", cb)?;
        let range = Expression::from(1 << UInt::<E>::M);

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        cb.require_equal(
            || "lhs - rhs == diff - (lt ⋅ range)",
            lhs - rhs,
            diff.value() - (lt.expr() * range),
        )?;

        Ok(LtGadget { lt, diff })
    }

    pub(crate) fn expr(&self) -> Expression<E> {
        self.lt.expr()
    }

    pub(crate) fn assign(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        lhs: E::BaseField,
        rhs: E::BaseField,
    ) -> Result<(), ZKVMError> {
        let lhs = lhs.to_canonical_u64();
        let rhs = rhs.to_canonical_u64();

        // Set `lt`
        let lt = lhs < rhs;
        set_val!(instance, self.lt, lt as u64);

        // Set `diff`
        let diff = lhs - rhs + (if lt { 1 << UInt::<E>::M } else { 0 });
        self.diff
            .assign_limbs(instance, Value::new(diff, lkm).u16_fields());

        Ok(())
    }
}
