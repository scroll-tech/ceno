use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::constants::UInt,
    set_val,
    witness::LkMultiplicity,
};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

pub struct SignedExtendConfig {
    /// most significant bit
    msb: WitIn,
    /// number of bits contained in the value
    n_bits: usize,
}

impl SignedExtendConfig {
    pub fn construct_limb<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        val: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Self::construct_circuit(cb, 16, val)
    }

    pub fn construct_byte<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        val: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Self::construct_circuit(cb, 8, val)
    }

    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        n_bits: usize,
        val: Expression<E>, // it's assumed that val is within [0, 2^N_BITS)
    ) -> Result<Self, ZKVMError> {
        assert!(n_bits == 8 || n_bits == 16);

        let msb = cb.create_witin(|| "msb")?;
        // require msb is boolean
        cb.assert_bit(|| "msb is boolean", msb.expr())?;

        // assert 2*val - msb*2^N_BITS is within range [0, 2^N_BITS)
        // - if val < 2^(N_BITS-1), then 2*val < 2^N_BITS, msb can only be zero.
        // - otherwise, 2*val >= 2^N_BITS, then msb can only be one.
        let assert_ux = match n_bits {
            8 => CircuitBuilder::<E>::assert_ux::<_, _, 8>,
            16 => CircuitBuilder::<E>::assert_ux::<_, _, 16>,
            _ => unreachable!("unsupported n_bits = {}", n_bits),
        };
        assert_ux(
            cb,
            || "0 <= 2*val - msb*2^N_BITS < 2^N_BITS",
            2 * val - msb.expr() * (1 << n_bits),
        )?;

        Ok(SignedExtendConfig { msb, n_bits })
    }

    /// Get the signed extended value
    pub fn signed_extended_value<E: ExtensionField>(&self, val: Expression<E>) -> UInt<E> {
        assert_eq!(UInt::<E>::LIMB_BITS, 16);

        let limb0 = match self.n_bits {
            8 => self.msb.expr() * 0xff00 + val,
            16 => val,
            _ => unreachable!("unsupported N_BITS = {}", self.n_bits),
        };
        UInt::from_exprs_unchecked(vec![limb0, self.msb.expr() * 0xffff])
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        val: u64,
    ) -> Result<(), ZKVMError> {
        let msb = val >> (self.n_bits - 1);

        let assert_ux = match self.n_bits {
            8 => LkMultiplicity::assert_ux::<8>,
            16 => LkMultiplicity::assert_ux::<16>,
            _ => unreachable!("unsupported n_bits = {}", self.n_bits),
        };

        assert_ux(lk_multiplicity, 2 * val - (msb << self.n_bits));
        set_val!(instance, self.msb, E::BaseField::from(msb));

        Ok(())
    }
}
