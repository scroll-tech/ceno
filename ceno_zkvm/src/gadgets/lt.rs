use std::{
    mem::MaybeUninit,
    ops::{Add, Sub},
};

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

    pub fn expr(&self) -> Expression<E> {
        self.lt.expr()
    }

    pub fn assign(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        lhs: E::BaseField,
        rhs: E::BaseField,
    ) -> Result<(), ZKVMError> {
        // Set `lt`
        let lt = lhs.to_canonical_u64() < rhs.to_canonical_u64();
        set_val!(instance, self.lt, lt as u64);

        // Set `diff`
        let diff = lhs.sub(rhs).add(if lt {
            E::BaseField::from(1 << UInt::<E>::M)
        } else {
            E::BaseField::from(0)
        });
        self.diff.assign_limbs(
            instance,
            #[cfg(feature = "riv32")]
            Value::new(diff.to_canonical_u64() as u32, lkm).u16_fields(),
            #[cfg(feature = "riv64")]
            Value::new(diff.to_canonical_u64(), lkm).u16_fields(),
        );

        Ok(())
    }
}
