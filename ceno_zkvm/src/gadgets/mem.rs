use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    instructions::riscv::constants::UInt,
};

use super::DivConfig;

pub struct MemByteConfig<E: ExtensionField, const INDEX: usize> {
    mem_value: UInt<E>,
}

impl<E: ExtensionField, const INDEX: usize> MemByteConfig<E, INDEX> {
    pub fn construct_circuit<NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        mem_addr: &UInt<E>,
        mem_value: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(name_fn, |cb| {
            let num_byte_limbs = UInt::<E>::M.div_ceil(u8::BITS as usize);
            assert!(INDEX < num_byte_limbs); // calculate number of byte limbs
            let mut addr_align_uint =
                UInt::from_exprs_unchecked(vec![Expression::Constant((INDEX as u64).into())])?;
            let mut addr_hi = UInt::new(|| "addr_hi", cb)?;

            // we dont check byte_addr range, since it will be check via pow2 lookup to derive pow2(byte_addr * UInt::C)
            let byte_addr = cb.create_witin(|| "byte_addr")?;
            let byte_addr_uint = UInt::from_exprs_unchecked(vec![byte_addr.expr()])?;
            // decompose mem_addr into lo || hi, where bits(lo) equals to log_2(num_byte_limbs), and bits(hi) equals to M - bits(lo)
            let addr_decompose_config = DivConfig::construct_circuit(
                cb,
                || "addr_decompose",
                &mut addr_align_uint,
                &mut addr_hi,
                &byte_addr_uint,
            )?;

            // get pow2(byte_addr * UInt::C)
            let pow2_byte_addr = cb.create_witin(|| "pow2_byte_addr")?;
            cb.lookup_pow2(
                byte_addr_uint.value() * UInt::<E>::C.into(),
                pow2_byte_addr.expr(),
            )?;

            // right shift mem value
            // mem_value := quotient || remainder => require invoking one DivConfig
            // quotient := mem_hi || mem_value => require invoking another DivConfig
            // set mem_value in config

            Ok(MemByteConfig { mem_value })
        })
    }
}
