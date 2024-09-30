use crate::{
    chip_handler::{
        register_expr_to_memory_expr, GlobalStateRegisterMachineChipOperations,
        MemoryChipOperations, MemoryExpr, RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::{
        config::{ExprLtConfig, ExprLtInput},
        constants::UInt,
    },
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{InsnKind, StepRecord, PC_STEP_SIZE};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

pub struct SInstructionConfig<E: ExtensionField> {
    pc: WitIn,
    ts: WitIn,
    rs1_id: WitIn,
    rs2_id: WitIn,

    prev_memory_value: UInt<E>,

    prev_rs1_ts: WitIn,
    prev_rs2_ts: WitIn,
    prev_memory_ts: WitIn,

    lt_rs1_cfg: ExprLtConfig,
    lt_rs2_cfg: ExprLtConfig,
    lt_mem_cfg: ExprLtConfig,
}

impl<E: ExtensionField> SInstructionConfig<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
        imm: &Expression<E>,
        rs1_read: RegisterExpr<E>,
        rs2_read: RegisterExpr<E>,
        memory_addr: MemoryExpr<E>,
    ) -> Result<Self, ZKVMError> {
        // State in
        let pc = circuit_builder.create_witin(|| "pc")?;
        let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;
        circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

        // Register indexes
        let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
        let rs2_id = circuit_builder.create_witin(|| "rs2_id")?;

        // Fetch the instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (insn_kind.codes().opcode as usize).into(),
            0.into(),
            (insn_kind.codes().func3 as usize).into(),
            rs1_id.expr(),
            rs2_id.expr(),
            imm.clone(),
        ))?;

        // Register State.
        let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;

        // Memory state.
        let prev_memory_ts = circuit_builder.create_witin(|| "prev_memory_ts")?;
        let prev_memory_value = UInt::new_unchecked(|| "prev_memory_value", circuit_builder)?;

        // Register read
        let (next_ts, lt_rs1_cfg) = circuit_builder.register_read(
            || "read_rs1",
            &rs1_id,
            prev_rs1_ts.expr(),
            cur_ts.expr(),
            rs1_read,
        )?;
        let (next_ts, lt_rs2_cfg) = circuit_builder.register_read(
            || "read_rs2",
            &rs2_id,
            prev_rs2_ts.expr(),
            next_ts,
            rs2_read,
        )?;

        // Memory write
        let (next_ts, lt_mem_cfg) = circuit_builder.memory_write(
            || "write_mem",
            &memory_addr,
            prev_memory_ts.expr(),
            next_ts,
            prev_memory_value,
            register_expr_to_memory_expr(&rs2_read),
        )?;

        // State out.
        let next_pc = pc.expr() + PC_STEP_SIZE.into();
        circuit_builder.state_out(next_pc, next_ts)?;

        Ok(SInstructionConfig {
            pc,
            ts: cur_ts,
            rs1_id,
            rs2_id,
            prev_memory_value,
            prev_rs1_ts,
            prev_rs2_ts,
            prev_memory_ts,
            lt_rs1_cfg,
            lt_rs2_cfg,
            lt_mem_cfg,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // State in.
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        set_val!(instance, self.ts, step.cycle());

        // Register indexes.
        set_val!(instance, self.rs1_id, step.insn().rs1() as u64);
        set_val!(instance, self.rs2_id, step.insn().rs2() as u64);

        // Fetch the instruction
        lk_multiplicity.fetch(step.pc().before.0);

        // Register state
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

        // Memory state
        set_val!(
            instance,
            self.prev_memory_ts,
            step.memory_op().unwrap().previous_cycle
        );
        self.prev_memory_value.assign_limbs(
            instance,
            Value::new_unchecked(step.memory_op().unwrap().value.before).u16_fields(),
        );

        // Register Read
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

        // Memory Write
        ExprLtInput {
            lhs: step.memory_op().unwrap().previous_cycle,
            rhs: step.cycle() + 2,
        }
        .assign(instance, &self.lt_mem_cfg, lk_multiplicity);

        Ok(())
    }
}
