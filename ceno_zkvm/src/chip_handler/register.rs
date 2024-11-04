use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    gadgets::AssertLTConfig,
    instructions::riscv::constants::UINT_LIMBS,
    structs::RAMType,
};

use super::{RegisterChipOperations, RegisterExpr};

impl<'a, E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> RegisterChipOperations<E, NR, N>
    for CircuitBuilder<'a, E>
{
    fn register_read(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![RAMType::Register.into()],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![RAMType::Register.into()],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            // assert prev_ts < current_ts
            let lt_cfg = AssertLTConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1;

            Ok((next_ts, lt_cfg))
        })
    }

    fn register_write(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: RegisterExpr<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError> {
        assert!(register_id.expr().degree() <= 1);
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![RAMType::Register.into()],
                    vec![register_id.expr()],
                    prev_values.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![RAMType::Register.into()],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            let lt_cfg = AssertLTConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1;

            #[cfg(test)]
            {
                use crate::chip_handler::{test::DebugIndex, utils::power_sequence};
                use itertools::izip;
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
