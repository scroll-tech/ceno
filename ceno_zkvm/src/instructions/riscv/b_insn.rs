#![allow(dead_code)] // TODO: remove after BLT, BEQ, …

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{config::ExprLtConfig, constants::PC_STEP_SIZE};
use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::config::ExprLtInput,
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

// Opcode: 1100011
// Funct3:
//   000  BEQ
//   001  BNE
//   100  BLT
//   101  BGE
//   110  BLTU
//   111  BGEU
//

/// This config handles the common part of B-type instructions (branches):
/// - PC, cycle, fetch.
/// - Registers read.
/// - Jump based on the immediate and the given `branch_taken_bit`.
///
/// It does _not_ range-check the `branch_taken_bit`.
/// It does not witness of the register values, nor the actual function (e.g. BNE).
#[derive(Debug)]
pub struct BInstructionConfig {
    pc: WitIn,
    ts: WitIn,
    rs1_id: WitIn,
    rs2_id: WitIn,
    imm: WitIn,
    prev_rs1_ts: WitIn,
    prev_rs2_ts: WitIn,
    lt_rs1_cfg: ExprLtConfig,
    lt_rs2_cfg: ExprLtConfig,
}

impl BInstructionConfig {
    pub fn construct_circuit<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        branch_taken_bit: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        // State in.
        let pc = circuit_builder.create_witin(|| "pc")?;
        let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;
        circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

        // Register indexes and immediate.
        let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
        let rs2_id = circuit_builder.create_witin(|| "rs2_id")?;
        let imm = circuit_builder.create_witin(|| "imm")?;

        // Fetch the instruction.
        circuit_builder.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            0.into(), // TODO: Make sure the program table sets rd=0.
            (insn_kind.codes().func3 as usize).into(),
            rs1_id.expr(),
            rs2_id.expr(),
            imm.expr(), // TODO: Make sure the program table sets the full immediate.
        ))?;

        // Register state.
        let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;

        // Register reads.
        let (ts, lt_rs1_cfg) = circuit_builder.register_read(
            || "read_rs1",
            &rs1_id,
            prev_rs1_ts.expr(),
            cur_ts.expr(),
            rs1_read,
        )?;
        let (_ts, lt_rs2_cfg) = circuit_builder.register_read(
            || "read_rs2",
            &rs2_id,
            prev_rs2_ts.expr(),
            ts,
            rs2_read,
        )?;

        // State out.
        let pc_offset = branch_taken_bit * (imm.expr() - PC_STEP_SIZE.into()) + PC_STEP_SIZE.into();
        let next_pc = pc.expr() + pc_offset;
        let next_ts = cur_ts.expr() + 4.into();
        circuit_builder.state_out(next_pc, next_ts)?;

        Ok(BInstructionConfig {
            pc,
            ts: cur_ts,
            rs1_id,
            rs2_id,
            imm,
            prev_rs1_ts,
            prev_rs2_ts,
            lt_rs1_cfg,
            lt_rs2_cfg,
        })
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // State in.
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        set_val!(instance, self.ts, step.cycle());

        // Register indexes and immediate.
        set_val!(instance, self.rs1_id, step.insn().rs1() as u64);
        set_val!(instance, self.rs2_id, step.insn().rs2() as u64);
        set_val!(instance, self.imm, step.insn().imm_b() as u64);

        // Fetch the instruction.
        lk_multiplicity.fetch(step.pc().before.0);

        // Register state.
        set_val!(
            instance,
            self.prev_rs1_ts,
            step.rs1().unwrap().previous_cycle
        );
        set_val!(
            instance,
            self.prev_rs2_ts,
            step.rs2().unwrap().previous_cycle
        );

        // Register read and write.
        ExprLtInput {
            lhs: step.rs1().unwrap().previous_cycle,
            rhs: step.cycle(),
        }
        .assign(instance, &self.lt_rs1_cfg, lk_multiplicity);
        ExprLtInput {
            lhs: step.rs2().unwrap().previous_cycle,
            rhs: step.cycle() + 1,
        }
        .assign(instance, &self.lt_rs2_cfg, lk_multiplicity);

        Ok(())
    }
}
