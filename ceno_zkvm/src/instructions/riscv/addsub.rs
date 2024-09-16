use std::marker::PhantomData;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    config::ExprLtConfig,
    constants::{
        OPType, OpcodeType, RegUInt, FUNCT3_ADD_SUB, FUNCT7_ADD, FUNCT7_SUB, OPCODE_OP,
        PC_STEP_SIZE,
    },
    RIVInstruction,
};
use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{riscv::config::ExprLtInput, Instruction},
    set_val,
    tables::InsnRecord,
    uint::UIntValue,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

pub struct AddInstruction<E>(PhantomData<E>);
pub struct SubInstruction<E>(PhantomData<E>);

#[derive(Debug)]
pub struct InstructionConfig<E: ExtensionField> {
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

impl<E: ExtensionField> RIVInstruction<E> for AddInstruction<E> {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0000000);
}

impl<E: ExtensionField> RIVInstruction<E> for SubInstruction<E> {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0100000);
}

fn add_sub_gadget<E: ExtensionField, const IS_ADD: bool>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = circuit_builder.create_witin(|| "pc")?;
    let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;

    // state in
    circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

    let next_pc = pc.expr() + PC_STEP_SIZE.into();

    // Execution result = addend0 + addend1, with carry.
    let prev_rd_value = RegUInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;

    let (addend_0, addend_1, outcome) = if IS_ADD {
        // outcome = addend_0 + addend_1
        let addend_0 = RegUInt::new_unchecked(|| "addend_0", circuit_builder)?;
        let addend_1 = RegUInt::new_unchecked(|| "addend_1", circuit_builder)?;
        (
            addend_0.clone(),
            addend_1.clone(),
            addend_0.add(|| "outcome", circuit_builder, &addend_1, true)?,
        )
    } else {
        // outcome + addend_1 = addend_0
        // outcome is the new value to be updated in register so we need to constrain its range
        let outcome = RegUInt::new(|| "outcome", circuit_builder)?;
        let addend_1 = RegUInt::new_unchecked(|| "addend_1", circuit_builder)?;
        (
            addend_1
                .clone()
                .add(|| "addend_0", circuit_builder, &outcome.clone(), true)?,
            addend_1,
            outcome,
        )
    };

    let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
    let rs2_id = circuit_builder.create_witin(|| "rs2_id")?;
    let rd_id = circuit_builder.create_witin(|| "rd_id")?;

    // Fetch the instruction.
    circuit_builder.lk_fetch(&InsnRecord::new(
        pc.expr(),
        OPCODE_OP.into(),
        rd_id.expr(),
        FUNCT3_ADD_SUB.into(),
        rs1_id.expr(),
        rs2_id.expr(),
        (if IS_ADD { FUNCT7_ADD } else { FUNCT7_SUB }).into(),
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
    let (ts, lt_rs2_cfg) =
        circuit_builder.register_read(|| "read_rs2", &rs2_id, prev_rs2_ts.expr(), ts, &addend_1)?;

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

    Ok(InstructionConfig {
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

fn add_sub_assignment<E: ExtensionField, const IS_ADD: bool>(
    config: &InstructionConfig<E>,
    instance: &mut [MaybeUninit<E::BaseField>],
    lk_multiplicity: &mut LkMultiplicity,
    step: &StepRecord,
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

    if IS_ADD {
        // addend_0 + addend_1 = outcome
        let addend_0 = UIntValue::new_unchecked(step.rs1().unwrap().value);
        config
            .addend_0
            .assign_limbs(instance, addend_0.u16_fields());
        let (_, outcome_carries) = addend_0.add(&addend_1, lk_multiplicity, true);
        config.outcome.assign_carries(
            instance,
            outcome_carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );
    } else {
        // addend_0 = outcome + addend_1
        let outcome = UIntValue::new(step.rd().unwrap().value.after, lk_multiplicity);
        config.outcome.assign_limbs(instance, outcome.u16_fields());
        let (_, addend_0_carries) = addend_1.add(&outcome, lk_multiplicity, true);
        config.addend_0.assign_carries(
            instance,
            addend_0_carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );
    }
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

impl<E: ExtensionField> Instruction<E> for AddInstruction<E> {
    // const NAME: &'static str = "ADD";
    fn name() -> String {
        "ADD".into()
    }
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<E, true>(circuit_builder)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<_, true>(config, instance, lk_multiplicity, step)
    }
}

impl<E: ExtensionField> Instruction<E> for SubInstruction<E> {
    // const NAME: &'static str = "ADD";
    fn name() -> String {
        "SUB".into()
    }
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<E, false>(circuit_builder)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<_, false>(config, instance, lk_multiplicity, step)
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_ADD, MOCK_PC_SUB, MOCK_PROGRAM},
    };

    use super::{AddInstruction, SubInstruction};

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_add() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                11,
                0xfffffffe,
                Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_add_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                u32::MAX - 1,
                u32::MAX - 1,
                Change::new(0, (u32::MAX - 1).wrapping_add(u32::MAX - 1)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                11,
                2,
                Change::new(0, 11_u32.wrapping_sub(2)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_sub_underflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                3,
                11,
                Change::new(0, 3_u32.wrapping_sub(11)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }
}
