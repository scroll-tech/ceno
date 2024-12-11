use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::AssertLtConfig,
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind::EANY, PC_STEP_SIZE, Platform, StepRecord, Tracer};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

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
            ts.expr() + (Tracer::SUBCYCLES_PER_INSN as usize),
        )?;

        cb.lk_fetch(&InsnRecord::new(
            pc.expr(),
            EANY.into(),
            None,
            0.into(),
            0.into(),
            0.into(), // imm = 0
        ))?;

        let prev_x5_ts = cb.create_witin(|| "prev_x5_ts");

        // read syscall_id from x5 and write return value to x5
        let (_, lt_x5_cfg) = cb.register_write(
            || "write x5",
            E::BaseField::from(Platform::reg_ecall() as u64),
            prev_x5_ts.expr(),
            ts.expr() + Tracer::SUBCYCLE_RS1,
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
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        set_val!(instance, self.ts, step.cycle());
        lk_multiplicity.fetch(step.pc().before.0);

        // the access of X5 register is stored in rs1()
        set_val!(
            instance,
            self.prev_x5_ts,
            step.rs1().unwrap().previous_cycle
        );

        self.lt_x5_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS1,
        )?;

        Ok(())
    }
}
