use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::constants::{UInt, PC_STEP_SIZE, UINT_LIMBS};
use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::IsLtConfig,
    set_val,
    tables::InsnRecord,
    uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles the common part of I-type instructions:
/// - PC, cycle, fetch.
/// - Registers read and write.
///
/// It does not witness of the register values, nor the actual function (e.g. srli, addi, etc).
#[derive(Debug)]
pub struct IInstructionConfig<E: ExtensionField> {
    pub pc: WitIn,
    pub ts: WitIn,
    pub rs1_id: WitIn,
    pub rd_id: WitIn,
    pub prev_rd_value: UInt<E>,
    pub prev_rs1_ts: WitIn,
    pub prev_rd_ts: WitIn,
    pub lt_rs1_cfg: IsLtConfig<UINT_LIMBS>,
    pub lt_rd_cfg: IsLtConfig<UINT_LIMBS>,
}

impl<E: ExtensionField> IInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        rd_written: RegisterExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in.
        let pc = circuit_builder.create_witin(|| "pc")?;
        let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;
        circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

        // Register indexes.
        let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
        let rd_id = circuit_builder.create_witin(|| "rd_id")?;

        // Fetch the instruction.
        circuit_builder.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            rd_id.expr(),
            (insn_kind.codes().func3 as usize).into(),
            rs1_id.expr(),
            0.into(),
            imm.clone(),
        ))?;

        // Register state.
        let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let prev_rd_ts = circuit_builder.create_witin(|| "prev_rd_ts")?;
        let prev_rd_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;

        // Register read and write.
        let (next_ts, lt_rs1_cfg) = circuit_builder.register_read(
            || "read_rs1",
            &rs1_id,
            prev_rs1_ts.expr(),
            cur_ts.expr(),
            rs1_read,
        )?;
        let (next_ts, lt_rd_cfg) = circuit_builder.register_write(
            || "write_rd",
            &rd_id,
            prev_rd_ts.expr(),
            next_ts,
            prev_rd_value.register_expr(),
            rd_written,
        )?;

        // State out.
        let next_pc = pc.expr() + PC_STEP_SIZE.into();
        circuit_builder.state_out(next_pc, next_ts)?;

        Ok(IInstructionConfig {
            pc,
            ts: cur_ts,
            rs1_id,
            rd_id,
            prev_rd_value,
            prev_rs1_ts,
            prev_rd_ts,
            lt_rs1_cfg,
            lt_rd_cfg,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // State in.
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        set_val!(instance, self.ts, step.cycle());

        // Register indexes.
        set_val!(instance, self.rs1_id, step.insn().rs1() as u64);
        set_val!(instance, self.rd_id, step.insn().rd() as u64);

        // Fetch the instruction.
        lk_multiplicity.fetch(step.pc().before.0);

        // Register state.
        set_val!(
            instance,
            self.prev_rs1_ts,
            step.rs1().unwrap().previous_cycle
        );
        set_val!(instance, self.prev_rd_ts, step.rd().unwrap().previous_cycle);
        self.prev_rd_value.assign_limbs(
            instance,
            Value::new_unchecked(step.rd().unwrap().value.before).u16_fields(),
        );

        // Register read and write.
        self.lt_rs1_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().previous_cycle,
            step.cycle(),
        )?;
        self.lt_rd_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rd().unwrap().previous_cycle,
            step.cycle() + 1,
        )?;

        Ok(())
    }
}
