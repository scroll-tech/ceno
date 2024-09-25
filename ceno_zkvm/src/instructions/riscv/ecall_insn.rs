use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::config::{ExprLtConfig, ExprLtInput},
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind::EANY, StepRecord, PC_STEP_SIZE};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

const X5: u64 = 5;
#[allow(dead_code)]
const X10: usize = 10;
#[allow(dead_code)]
const X11: usize = 11;

pub struct EcallInstructionConfig {
    pub pc: WitIn,
    pub ts: WitIn,
    prev_x5_ts: WitIn,
    lt_x5_cfg: ExprLtConfig,
}

impl EcallInstructionConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        syscall_id: RegisterExpr<E>,
        syscall_ret_value: Option<RegisterExpr<E>>,
        next_pc: Option<Expression<E>>,
    ) -> Result<Self, ZKVMError> {
        let pc = cb.create_witin(|| "pc")?;
        let ts = cb.create_witin(|| "cur_ts")?;

        cb.state_in(pc.expr(), ts.expr())?;

        cb.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (EANY.codes().opcode as usize).into(),
            0.into(),
            (EANY.codes().func3 as usize).into(),
            0.into(),
            0.into(),
            0.into(), // imm = 0
        ))?;

        let prev_x5_ts = cb.create_witin(|| "prev_x5_ts")?;

        // read syscall_id from x5 and write return value to x5
        let (_, lt_x5_cfg) = cb.register_write(
            || "write x5",
            E::BaseField::from(X5),
            prev_x5_ts.expr(),
            ts.expr(),
            syscall_id.clone(),
            syscall_ret_value.map_or(syscall_id, |v| v),
        )?;

        cb.state_out(
            next_pc.map_or(pc.expr() + PC_STEP_SIZE.into(), |next_pc| next_pc),
            ts.expr() + 4.into(),
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
        // the access of X10 register is stored in rs2()
        set_val!(
            instance,
            self.prev_x5_ts,
            step.rs1().unwrap().previous_cycle
        );

        ExprLtInput {
            lhs: step.rs1().unwrap().previous_cycle,
            rhs: step.cycle(),
        }
        .assign(instance, &self.lt_x5_cfg, lk_multiplicity);

        Ok(())
    }
}
