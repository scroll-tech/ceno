use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::IsLtConfig,
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
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, IsLtConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            // assert prev_ts < current_ts
            let lt_cfg = cb.less_than(
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                Some(true),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1.into();

            Ok((next_ts, lt_cfg))
        })
    }

    fn register_write(
        &mut self,
        name_fn: N,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: RegisterExpr<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, IsLtConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    prev_values.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            let lt_cfg = cb.less_than(
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                Some(true),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1.into();

            #[cfg(test)]
            {
                use crate::chip_handler::{test::DebugIndex, utils::pows_expr};
                let pow_u16 = pows_expr((1 << u16::BITS as u64).into(), value.len());
                cb.register_debug_expr(
                    DebugIndex::RdWrite as usize,
                    value
                        .into_iter()
                        .zip(pow_u16)
                        .map(|(v, pow)| pow * v)
                        .fold(Expression::ZERO, |acc, v| acc + v),
                );
            }

            Ok((next_ts, lt_cfg))
        })
    }
}
