use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use super::constants::{UInt, PC_STEP_SIZE};
use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    gadgets::IsLtConfig,
    set_val,
    uint::Value,
    witness::LkMultiplicity,
};
use ceno_emul::Tracer;
use core::mem::MaybeUninit;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct StateInOut<E: ExtensionField> {
    pub pc: WitIn,
    pub next_pc: Option<WitIn>,
    pub ts: WitIn,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> StateInOut<E> {
    /// If circuit is branching, leave witness for next_pc free and return in
    /// configuration so that calling circuit can constrain its value.
    /// Otherwise, internally increment by PC_STEP_SIZE
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        branching: bool,
    ) -> Result<Self, ZKVMError> {
        let pc = circuit_builder.create_witin(|| "pc")?;
        let (next_pc_opt, next_pc_expr) = if branching {
            let next_pc = circuit_builder.create_witin(|| "next_pc")?;
            (Some(next_pc), next_pc.expr())
        } else {
            (None, pc.expr() + PC_STEP_SIZE.into())
        };
        let ts = circuit_builder.create_witin(|| "ts")?;
        let next_ts = ts.expr() + (Tracer::SUBCYCLES_PER_INSN as usize).into();
        circuit_builder.state_in(pc.expr(), ts.expr())?;
        circuit_builder.state_out(next_pc_expr, next_ts)?;

        Ok(StateInOut {
            pc,
            next_pc: next_pc_opt,
            ts,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        // lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        if let Some(n_pc) = self.next_pc {
            set_val!(instance, n_pc, step.pc().after.0 as u64);
        }
        set_val!(instance, self.ts, step.cycle());

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS1<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: IsLtConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS1<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs1_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs1_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs1",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RS1 as usize).into(),
            rs1_read,
        )?;

        Ok(ReadRS1 {
            id,
            prev_ts,
            lt_cfg,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rs1() as u64);

        // Register state
        set_val!(instance, self.prev_ts, step.rs1().unwrap().previous_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS1,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS2<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: IsLtConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS2<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs2_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs2_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs2",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RS2 as usize).into(),
            rs2_read,
        )?;

        Ok(ReadRS2 {
            id,
            prev_ts,
            lt_cfg,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rs2() as u64);

        // Register state
        set_val!(instance, self.prev_ts, step.rs2().unwrap().previous_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs2().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS2,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteRD<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub prev_value: UInt<E>,
    pub lt_cfg: IsLtConfig,
}

impl<E: ExtensionField> WriteRD<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rd_written: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rd_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rd_ts")?;
        let prev_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;
        let (_, lt_cfg) = circuit_builder.register_write(
            || "write_rd",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RD as usize).into(),
            prev_value.register_expr(),
            rd_written,
        )?;

        Ok(WriteRD {
            id,
            prev_ts,
            prev_value,
            lt_cfg,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rd() as u64);
        set_val!(instance, self.prev_ts, step.rd().unwrap().previous_cycle);

        // Register state
        self.prev_value.assign_limbs(
            instance,
            Value::new_unchecked(step.rd().unwrap().value.before).as_u16_limbs(),
        );

        // Register write
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rd().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RD,
        )?;

        Ok(())
    }
}
