use ff::Field;
use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::{
    constants::{RANGE_CHIP_BIT_WIDTH, STACK_TOP_BIT_WIDTH},
    error::UtilError,
    structs::{PCUInt, ROMHandler, TSUInt, UInt},
    uint::UIntAddSub,
};

use super::RangeChipOperations;

impl<F: SmallField> RangeChipOperations<F> for ROMHandler<F> {
    fn range_check_stack_top(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
    ) -> Result<(), UtilError> {
        self.small_range_check(circuit_builder, stack_top, STACK_TOP_BIT_WIDTH)
    }

    /// Check the range of stack values within [0, 1 << STACK_VALUE_BYTE_WIDTH * 8).
    /// Return the verified values.
    fn range_check_uint<const M: usize, const C: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, UtilError>
    where
        F: SmallField,
    {
        let n_cell = (M + C - 1) / C;
        if C <= RANGE_CHIP_BIT_WIDTH {
            for value in uint.values().iter().take(n_cell - 1) {
                self.small_range_check(circuit_builder, (*value).into(), C)?;
            }
            self.small_range_check(circuit_builder, uint.values()[n_cell - 1].into(), M % C)?;
            Ok((*uint).clone())
        } else if let Some(range_values) = range_value_witness {
            let range_value = UInt::<M, C>::from_range_values(circuit_builder, range_values)?;
            uint.assert_eq(circuit_builder, &range_value);
            let b: usize = M.min(C);
            let chunk_size = (b + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;
            for chunk in range_values.chunks(chunk_size) {
                for i in 0..chunk_size - 1 {
                    self.small_range_check(circuit_builder, chunk[i].into(), RANGE_CHIP_BIT_WIDTH)?;
                }
                self.small_range_check(
                    circuit_builder,
                    chunk[chunk_size - 1].into(),
                    b - (chunk_size - 1) * RANGE_CHIP_BIT_WIDTH,
                )?;
            }
            Ok(range_value)
        } else {
            Err(UtilError::ChipError)
        }
    }

    fn range_check_bytes(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        bytes: &[CellId],
    ) -> Result<(), UtilError> {
        for byte in bytes {
            self.small_range_check(circuit_builder, (*byte).into(), 8)?;
        }
        Ok(())
    }
}

impl<F: SmallField> ROMHandler<F> {
    fn small_range_check(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        value: MixedCell<F>,
        bit_width: usize,
    ) -> Result<(), UtilError> {
        if bit_width > RANGE_CHIP_BIT_WIDTH {
            return Err(UtilError::ChipError);
        }
        let out = circuit_builder.create_ext_cell();
        let items = [value.mul(F::BaseField::from(1 << (RANGE_CHIP_BIT_WIDTH - bit_width)))];
        circuit_builder.rlc_mixed(&out, &items, self.challenge.record_rlc);
        self.records.push(out);
        Ok(())
    }
}

impl<Ext: SmallField> ROMHandler<Ext> {
    pub fn add_pc_const(
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &PCUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<PCUInt, UtilError> {
        let carry = UIntAddSub::<PCUInt>::extract_unsafe_carry(witness);
        UIntAddSub::<PCUInt>::add_const_unsafe(
            circuit_builder,
            &pc,
            i64_to_base_field::<Ext>(constant),
            carry,
        )
    }

    pub fn add_ts_with_const(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        ts: &TSUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<TSUInt, UtilError> {
        let carry = UIntAddSub::<TSUInt>::extract_unsafe_carry(witness);
        UIntAddSub::<TSUInt>::add_const(
            circuit_builder,
            self,
            &ts,
            i64_to_base_field::<Ext>(constant),
            carry,
        )
    }

    pub fn non_zero(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        val: CellId,
        wit: CellId,
    ) -> Result<CellId, UtilError> {
        let prod = circuit_builder.create_cell();
        circuit_builder.mul2(prod, val, wit, Ext::BaseField::ONE);
        self.small_range_check(circuit_builder, prod.into(), 1)?;

        let statement = circuit_builder.create_cell();
        // If val != 0, then prod = 1. => assert!( val (prod - 1) = 0 )
        circuit_builder.mul2(statement, val, prod, Ext::BaseField::ONE);
        circuit_builder.add(statement, val, -Ext::BaseField::ONE);
        circuit_builder.assert_const(statement, 0);
        Ok(prod)
    }
}

fn i64_to_base_field<F: SmallField>(x: i64) -> F::BaseField {
    if x >= 0 {
        F::BaseField::from(x as u64)
    } else {
        -F::BaseField::from((-x) as u64)
    }
}
