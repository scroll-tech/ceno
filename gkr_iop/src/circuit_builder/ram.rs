use crate::{RAMType, error::CircuitBuilderError};
use ff_ext::ExtensionField;

use multilinear_extensions::{Expression, ToExpr};

use crate::{circuit_builder::CircuitBuilder, gadgets::AssertLtConfig};

impl<E: ExtensionField> CircuitBuilder<'_, E> {
    pub fn ram_type_read<const LIMBS: usize, NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: [Expression<E>; LIMBS],
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![ram_type.into()],
                vec![register_id.expr()],
                value.to_vec(),
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![ram_type.into()],
                vec![register_id.expr()],
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
                LIMBS,
            )?;

            let next_ts = ts + 1;

            Ok((next_ts, lt_cfg))
        })
    }

    pub fn ram_type_write<const LIMBS: usize, NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: [Expression<E>; LIMBS],
        value: [Expression<E>; LIMBS],
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        assert!(register_id.expr().degree() <= 1);
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![ram_type.into()],
                vec![register_id.expr()],
                prev_values.to_vec(),
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![ram_type.into()],
                vec![register_id.expr()],
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
                LIMBS,
            )?;

            let next_ts = ts + 1;

            #[cfg(test)]
            {
                use crate::circuit_builder::DebugIndex;
                use itertools::izip;
                use multilinear_extensions::power_sequence;

                let pow_u16 = power_sequence((1 << u16::BITS as u64).into());
                cb.register_debug_expr(
                    DebugIndex::RdWrite as usize,
                    izip!(value, pow_u16).map(|(v, pow)| v * pow).sum(),
                );
            }

            Ok((next_ts, lt_cfg))
        })
    }
}
