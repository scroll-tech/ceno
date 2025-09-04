use crate::{
    circuit_builder::CircuitBuilder,
    instructions::riscv::constants::{LIMB_BITS, UInt},
    witness::LkMultiplicity,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::error::CircuitBuilderError;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::marker::PhantomData;
use witness::set_val;

/// Extract the most significant bit from an expression previously constrained
/// to an 8 or 16-bit length.
///
/// Uses 1 `WitIn` value to store the bit, one `assert_bit` constraint, and one
/// `u8` or `u16` table lookup.
#[derive(Debug)]
pub struct SignedExtendConfig<E> {
    /// Most significant bit
    msb: WitIn,
    /// Number of bits of the represented value
    n_bits: usize,

    _marker: PhantomData<E>,
}

impl<E: ExtensionField> SignedExtendConfig<E> {
    pub fn construct_limb(
        cb: &mut CircuitBuilder<E>,
        val: Expression<E>,
    ) -> Result<Self, CircuitBuilderError> {
        Self::construct_circuit(cb, LIMB_BITS, val)
    }

    pub fn construct_byte(
        cb: &mut CircuitBuilder<E>,
        val: Expression<E>,
    ) -> Result<Self, CircuitBuilderError> {
        Self::construct_circuit(cb, 8, val)
    }

    pub fn expr(&self) -> Expression<E> {
        self.msb.expr()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        n_bits: usize,
        val: Expression<E>, // it's assumed that val is within [0, 2^N_BITS)
    ) -> Result<Self, CircuitBuilderError> {
        assert!(n_bits == 8 || n_bits == 16);

        let msb = cb.create_witin(|| "msb");
        // require msb is boolean
        cb.assert_bit(|| "msb is boolean", msb.expr())?;

        // assert 2*val - msb*2^N_BITS is within range [0, 2^N_BITS)
        // - if val < 2^(N_BITS-1), then 2*val < 2^N_BITS, msb can only be zero.
        // - otherwise, 2*val >= 2^N_BITS, then msb can only be one.
        cb.assert_const_range(
            || "0 <= 2*val - msb*2^N_BITS < 2^N_BITS",
            2 * val - (msb.expr() << n_bits),
            n_bits,
        )?;

        Ok(SignedExtendConfig {
            msb,
            n_bits,
            _marker: PhantomData,
        })
    }

    /// Get the signed extended value
    pub fn signed_extended_value(&self, val: Expression<E>) -> UInt<E> {
        assert_eq!(UInt::<E>::LIMB_BITS, 16);

        let limb0 = match self.n_bits {
            8 => self.msb.expr() * 0xff00 + val,
            16 => val,
            _ => unreachable!("unsupported N_BITS = {}", self.n_bits),
        };
        UInt::from_exprs_unchecked(vec![limb0, self.msb.expr() * 0xffff])
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        val: u64,
    ) -> Result<(), CircuitBuilderError> {
        let msb = val >> (self.n_bits - 1);
        lk_multiplicity.assert_const_range(2 * val - (msb << self.n_bits), self.n_bits);
        set_val!(instance, self.msb, E::BaseField::from_canonical_u64(msb));

        Ok(())
    }
}
