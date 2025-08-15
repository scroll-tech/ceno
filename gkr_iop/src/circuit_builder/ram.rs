use crate::{RAMType, error::CircuitBuilderError};
use ff_ext::ExtensionField;

use crate::circuit_builder::DebugIndex;
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, power_sequence};
use p3_field::Field;

use crate::{circuit_builder::CircuitBuilder, gadgets::AssertLtConfig};

impl<E: ExtensionField> CircuitBuilder<'_, E> {
    // MAX_TS_BITS need to be smaller than prime field
    pub const MAX_TS_BITS: usize = 30;

    pub fn ram_type_read<const LIMBS: usize, NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        identifier: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: [Expression<E>; LIMBS],
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        assert!(E::BaseField::bits() > Self::MAX_TS_BITS);
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![ram_type.into()],
                vec![identifier.expr()],
                value.to_vec(),
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![ram_type.into()],
                vec![identifier.expr()],
                value.to_vec(),
                vec![ts.clone()],
            ]
            .concat();
            cb.read_record(|| "read_record", ram_type, read_record)?;
            cb.write_record(|| "write_record", ram_type, write_record)?;

            // assert prev_ts < current_ts
            let lt_cfg = AssertLtConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                Self::MAX_TS_BITS,
            )?;

            let next_ts = ts + 1;

            Ok((next_ts, lt_cfg))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ram_type_write<const LIMBS: usize, NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        identifier: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: [Expression<E>; LIMBS],
        value: [Expression<E>; LIMBS],
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        assert!(identifier.expr().degree() <= 1);
        assert!(E::BaseField::bits() > Self::MAX_TS_BITS);
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![ram_type.into()],
                vec![identifier.expr()],
                prev_values.to_vec(),
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![ram_type.into()],
                vec![identifier.expr()],
                value.to_vec(),
                vec![ts.clone()],
            ]
            .concat();
            cb.read_record(|| "read_record", ram_type, read_record)?;
            cb.write_record(|| "write_record", ram_type, write_record)?;

            let lt_cfg = AssertLtConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                Self::MAX_TS_BITS,
            )?;

            let next_ts = ts + 1;

            if matches!(ram_type, RAMType::Register) {
                let pow_u16 = power_sequence((1 << u16::BITS as u64).into());
                cb.register_debug_expr(
                    DebugIndex::RdWrite as usize,
                    izip!(value.clone(), pow_u16).map(|(v, pow)| v * pow).sum(),
                );
            } else if matches!(ram_type, RAMType::Memory) {
                let pow_u16 = power_sequence((1 << u16::BITS as u64).into());
                cb.register_debug_expr(
                    DebugIndex::MemWrite as usize,
                    izip!(value, pow_u16).map(|(v, pow)| v * pow).sum(),
                );
            }

            Ok((next_ts, lt_cfg))
        })
    }
}
