use ceno_emul::{Cycle, WriteOp};
use ff_ext::{ExtensionField, FieldInto};
use p3::field::FieldAlgebra;
use witness::set_val;

use super::constants::UInt;
use crate::{
    chip_handler::{RegisterChipOperations, RegisterExpr},
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    structs::RAMType,
    uint::Value,
    witness::LkMultiplicity,
};
use ceno_emul::FullTracer;
use multilinear_extensions::{ToExpr, WitIn};

#[derive(Debug)]
pub struct OpFixedRS<E: ExtensionField, const REG_ID: usize, const RW: bool> {
    pub prev_ts: WitIn,
    pub prev_value: Option<UInt<E>>,
    pub lt_cfg: AssertLtConfig,
}

impl<E: ExtensionField, const REG_ID: usize, const RW: bool> OpFixedRS<E, REG_ID, RW> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rd_written: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_rd_ts");
        let (prev_value, lt_cfg) = if RW {
            let prev_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;
            let (_, lt_cfg) = circuit_builder.register_write(
                || "write_rd",
                E::BaseField::from_canonical_u64(REG_ID as u64),
                prev_ts.expr(),
                cur_ts.expr() + FullTracer::SUBCYCLE_RD,
                prev_value.register_expr(),
                rd_written,
            )?;
            (Some(prev_value), lt_cfg)
        } else {
            let (_, lt_cfg) = circuit_builder.register_read(
                || "read_rs",
                E::BaseField::from_canonical_u64(REG_ID as u64),
                prev_ts.expr(),
                // share same ts with RS1
                cur_ts.expr() + FullTracer::SUBCYCLE_RS1,
                rd_written,
            )?;
            (None, lt_cfg)
        };

        Ok(Self {
            prev_ts,
            prev_value,
            lt_cfg,
        })
    }

    pub fn assign_op(
        &self,
        instance: &mut [E::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        cycle: Cycle,
        op: &WriteOp,
    ) -> Result<(), ZKVMError> {
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = cycle - current_shard_offset_cycle;
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        // Register state
        if let Some(prev_value) = self.prev_value.as_ref() {
            prev_value.assign_limbs(
                instance,
                Value::new_unchecked(op.value.before).as_u16_limbs(),
            );
        }

        let (shard_cycle, cycle) = if RW {
            (
                shard_cycle + FullTracer::SUBCYCLE_RD,
                cycle + FullTracer::SUBCYCLE_RD,
            )
        } else {
            (
                shard_cycle + FullTracer::SUBCYCLE_RS1,
                cycle + FullTracer::SUBCYCLE_RS1,
            )
        };
        // Register write
        self.lt_cfg
            .assign_instance(instance, lk_multiplicity, shard_prev_cycle, shard_cycle)?;

        shard_ctx.send(
            RAMType::Register,
            op.addr,
            REG_ID as u64,
            cycle,
            op.previous_cycle,
            op.value.after,
            None,
        );

        Ok(())
    }
}
