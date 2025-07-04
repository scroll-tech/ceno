use ceno_emul::{Cycle, WriteOp};
use ff_ext::{ExtensionField, FieldInto};
use p3::field::FieldAlgebra;

use super::constants::UInt;
use crate::{
    chip_handler::{RegisterChipOperations, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    set_val,
    uint::Value,
    witness::LkMultiplicity,
};
use ceno_emul::Tracer;
use multilinear_extensions::{ToExpr, WitIn};

#[derive(Debug)]
pub struct WriteFixedRS<E: ExtensionField, const REG_ID: usize> {
    pub prev_ts: WitIn,
    pub prev_value: UInt<E>,
    pub lt_cfg: AssertLtConfig,
}

impl<E: ExtensionField, const REG_ID: usize> WriteFixedRS<E, REG_ID> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rd_written: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_rd_ts");
        let prev_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;
        let (_, lt_cfg) = circuit_builder.register_write(
            || "write_rd",
            E::BaseField::from_canonical_u64(REG_ID as u64),
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_RD,
            prev_value.register_expr(),
            rd_written,
        )?;

        Ok(WriteFixedRS {
            prev_ts,
            prev_value,
            lt_cfg,
        })
    }

    pub fn assign_op(
        &self,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        cycle: Cycle,
        op: &WriteOp,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.prev_ts, op.previous_cycle);

        // Register state
        self.prev_value.assign_limbs(
            instance,
            Value::new_unchecked(op.value.before).as_u16_limbs(),
        );

        // Register write
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            op.previous_cycle,
            cycle + Tracer::SUBCYCLE_RD,
        )?;

        Ok(())
    }
}
