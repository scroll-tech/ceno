use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::{StepRecord, PC_STEP_SIZE};
use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::riscv::config::ExprLtInput,
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
    UIntValue,
};

use super::{config::ExprLtConfig, constants::RegUInt, RIVInstruction};

#[derive(Debug)]
pub struct RTypeInstructionConfig<E: ExtensionField> {
    pub pc: WitIn,
    pub ts: WitIn,
    pub prev_rd_value: RegUInt<E>,
    pub addend_0: RegUInt<E>,
    pub addend_1: RegUInt<E>,
    pub outcome: RegUInt<E>,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub rd_id: WitIn,
    pub prev_rs1_ts: WitIn,
    pub prev_rs2_ts: WitIn,
    pub prev_rd_ts: WitIn,
    pub lt_rs1_cfg: ExprLtConfig,
    pub lt_rs2_cfg: ExprLtConfig,
    pub lt_prev_ts_cfg: ExprLtConfig,
    phantom: PhantomData<E>,
}

pub(crate) struct RTypeGadget<E: ExtensionField>(PhantomData<E>);

impl<E: ExtensionField> RTypeGadget<E> {
    pub fn construct_circuit<IC: RIVInstruction<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        operands_fn: impl FnOnce(
            &mut CircuitBuilder<E>,
        ) -> Result<(RegUInt<E>, RegUInt<E>, RegUInt<E>), ZKVMError>,
    ) -> Result<RTypeInstructionConfig<E>, ZKVMError> {
        let pc = circuit_builder.create_witin(|| "pc")?;
        let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;

        // state in
        circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

        let next_pc = pc.expr() + PC_STEP_SIZE.into();

        // Execution result = addend0 + addend1, with carry.
        let prev_rd_value = RegUInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;

        let (addend_0, addend_1, outcome) = operands_fn(circuit_builder)?;

        let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
        let rs2_id = circuit_builder.create_witin(|| "rs2_id")?;
        let rd_id = circuit_builder.create_witin(|| "rd_id")?;

        // Fetch the instruction.
        circuit_builder.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (IC::OPCODE_TYPE.opcode as usize).into(),
            rd_id.expr(),
            (IC::OPCODE_TYPE.func3 as usize).into(),
            rs1_id.expr(),
            rs2_id.expr(),
            (IC::OPCODE_TYPE.func7 as usize).into(),
        ))?;

        let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
        let prev_rd_ts = circuit_builder.create_witin(|| "prev_rd_ts")?;

        let (ts, lt_rs1_cfg) = circuit_builder.register_read(
            || "read_rs1",
            &rs1_id,
            prev_rs1_ts.expr(),
            cur_ts.expr(),
            &addend_0,
        )?;
        let (ts, lt_rs2_cfg) = circuit_builder.register_read(
            || "read_rs2",
            &rs2_id,
            prev_rs2_ts.expr(),
            ts,
            &addend_1,
        )?;

        let (ts, lt_prev_ts_cfg) = circuit_builder.register_write(
            || "write_rd",
            &rd_id,
            prev_rd_ts.expr(),
            ts,
            &prev_rd_value,
            &outcome,
        )?;

        let next_ts = ts + 1.into();
        circuit_builder.state_out(next_pc, next_ts)?;

        Ok(RTypeInstructionConfig {
            pc,
            ts: cur_ts,
            prev_rd_value,
            addend_0,
            addend_1,
            outcome,
            rs1_id,
            rs2_id,
            rd_id,
            prev_rs1_ts,
            prev_rs2_ts,
            prev_rd_ts,
            lt_rs1_cfg,
            lt_rs2_cfg,
            lt_prev_ts_cfg,
            phantom: PhantomData,
        })
    }

    pub fn assign(
        config: &RTypeInstructionConfig<E>,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
        operands_fn: impl FnOnce(
            &RTypeInstructionConfig<E>,
            &mut [MaybeUninit<E::BaseField>],
            &mut LkMultiplicity,
            &StepRecord,
            &UIntValue<u32>, // TODO generalize to u64
        ) -> Result<(), ZKVMError>,
    ) -> Result<(), ZKVMError> {
        lk_multiplicity.fetch(step.pc().before.0);
        set_val!(instance, config.pc, step.pc().before.0 as u64);
        set_val!(instance, config.ts, step.cycle());
        let addend_1 = UIntValue::new_unchecked(step.rs2().unwrap().value);
        let rd_prev = UIntValue::new_unchecked(step.rd().unwrap().value.before);
        config
            .prev_rd_value
            .assign_limbs(instance, rd_prev.u16_fields());

        config
            .addend_1
            .assign_limbs(instance, addend_1.u16_fields());

        operands_fn(config, instance, lk_multiplicity, step, &addend_1)?;

        set_val!(instance, config.rs1_id, step.insn().rs1() as u64);
        set_val!(instance, config.rs2_id, step.insn().rs2() as u64);
        set_val!(instance, config.rd_id, step.insn().rd() as u64);
        ExprLtInput {
            lhs: step.rs1().unwrap().previous_cycle,
            rhs: step.cycle(),
        }
        .assign(instance, &config.lt_rs1_cfg, lk_multiplicity);
        ExprLtInput {
            lhs: step.rs2().unwrap().previous_cycle,
            rhs: step.cycle() + 1,
        }
        .assign(instance, &config.lt_rs2_cfg, lk_multiplicity);
        ExprLtInput {
            lhs: step.rd().unwrap().previous_cycle,
            rhs: step.cycle() + 2,
        }
        .assign(instance, &config.lt_prev_ts_cfg, lk_multiplicity);
        set_val!(
            instance,
            config.prev_rs1_ts,
            step.rs1().unwrap().previous_cycle
        );
        set_val!(
            instance,
            config.prev_rs2_ts,
            step.rs2().unwrap().previous_cycle
        );
        set_val!(
            instance,
            config.prev_rd_ts,
            step.rd().unwrap().previous_cycle
        );
        Ok(())
    }
}
