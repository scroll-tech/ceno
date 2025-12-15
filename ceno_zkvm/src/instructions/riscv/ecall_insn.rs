use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
        general::InstFetch,
    },
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    tables::InsnRecord,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::{FullTracer, InsnKind::ECALL, PC_STEP_SIZE, Platform, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;

pub struct EcallInstructionConfig {
    pub pc: WitIn,
    pub ts: WitIn,
    prev_x5_ts: WitIn,
    lt_x5_cfg: AssertLtConfig,
}

impl EcallInstructionConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        syscall_id: RegisterExpr<E>,
        syscall_ret_value: Option<RegisterExpr<E>>,
        next_pc: Option<Expression<E>>,
    ) -> Result<Self, ZKVMError> {
        let pc = cb.create_witin(|| "pc");
        let ts = cb.create_witin(|| "cur_ts");

        cb.state_in(pc.expr(), ts.expr())?;
        cb.state_out(
            next_pc.map_or(pc.expr() + PC_STEP_SIZE, |next_pc| next_pc),
            ts.expr() + (FullTracer::SUBCYCLES_PER_INSN as usize),
        )?;

        cb.lk_fetch(&InsnRecord::new(
            pc.expr(),
            ECALL.into(),
            None,
            0.into(),
            0.into(),
            0.into(), // imm = 0
            #[cfg(feature = "u16limb_circuit")]
            0.into(), // imm_sign = 0
        ))?;

        let prev_x5_ts = cb.create_witin(|| "prev_x5_ts");

        // read syscall_id from x5 and write return value to x5
        let (_, lt_x5_cfg) = cb.register_write(
            || "write x5",
            E::BaseField::from_canonical_u64(Platform::reg_ecall() as u64),
            prev_x5_ts.expr(),
            ts.expr() + FullTracer::SUBCYCLE_RS1,
            syscall_id.clone(),
            syscall_ret_value.map_or(syscall_id, |v| v),
        )?;

        Ok(Self {
            pc,
            ts,
            prev_x5_ts,
            lt_x5_cfg,
        })
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [E::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(step.rs1().unwrap().previous_cycle);
        let shard_cycle = step.cycle() - current_shard_offset_cycle;
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        set_val!(instance, self.ts, shard_cycle);
        lk_multiplicity.fetch(step.pc().before.0);

        // the access of X5 register is stored in rs1()
        set_val!(instance, self.prev_x5_ts, shard_prev_cycle);

        self.lt_x5_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + FullTracer::SUBCYCLE_RS1,
        )?;

        // skip shard_ctx.send() as ecall_halt is the last instruction

        Ok(())
    }
}
