use std::marker::PhantomData;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    constants::{OPType, OpcodeType, RegUInt, PC_STEP_SIZE},
    RIVInstruction,
};
use crate::{
    chip_handler::{
        general::LtWtns, GlobalStateRegisterMachineChipOperations, RegisterChipOperations,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val,
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
    pub lt_wtns_rs1: LtWtns,
    pub lt_wtns_rs2: LtWtns,
    pub lt_wtns_rd: LtWtns,
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

    // TODO remove me, this is just for testing degree > 1 sumcheck in main constraints
    circuit_builder.require_zero(
        || "test_degree > 1",
        rs1_id.expr() * rs1_id.expr() - rs1_id.expr() * rs1_id.expr(),
    )?;

    let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
    let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
    let prev_rd_ts = circuit_builder.create_witin(|| "prev_rd_ts")?;

    let ts = circuit_builder.register_read(
        || "read_rs1",
        &rs1_id,
        prev_rs1_ts.expr(),
        cur_ts.expr(),
        &addend_0,
    )?;
    let ts =
        circuit_builder.register_read(|| "read_rs2", &rs2_id, prev_rs2_ts.expr(), ts, &addend_1)?;

    let ts = circuit_builder.register_write(
        || "write_rd",
        &rd_id,
        prev_rd_ts.expr(),
        ts,
        &prev_rd_value,
        &outcome,
    )?;

    let next_ts = ts + 1.into();
    circuit_builder.state_out(next_pc, next_ts)?;

    let lt_wtns_rs1 = circuit_builder.assert_less_than(
        || "prev_rs1_ts < ts",
        prev_rs1_ts.expr(),
        cur_ts.expr(),
    )?;
    let lt_wtns_rs2 = circuit_builder.assert_less_than(
        || "prev_rs2_ts < ts",
        prev_rs2_ts.expr(),
        cur_ts.expr(),
    )?;
    let lt_wtns_rd =
        circuit_builder.assert_less_than(|| "prev_rd_ts < ts", prev_rd_ts.expr(), cur_ts.expr())?;

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
        lt_wtns_rs1,
        lt_wtns_rs2,
        lt_wtns_rd,
        phantom: PhantomData,
    })
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
        // TODO use fields from step
        set_val!(instance, config.pc, 1);
        set_val!(instance, config.ts, 3);
        let addend_0 = UIntValue::new_unchecked(step.rs1().unwrap().value);
        let addend_1 = UIntValue::new_unchecked(step.rs2().unwrap().value);
        let rd_prev = UIntValue::new_unchecked(step.rd().unwrap().value.before);
        config
            .prev_rd_value
            .assign_limbs(instance, rd_prev.u16_fields());
        config
            .addend_0
            .assign_limbs(instance, addend_0.u16_fields());
        config
            .addend_1
            .assign_limbs(instance, addend_1.u16_fields());
        let (_, carries) = addend_0.add(&addend_1, lk_multiplicity, true);
        config.outcome.assign_carries(
            instance,
            carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );
        // TODO #167
        set_val!(instance, config.rs1_id, 2);
        set_val!(instance, config.rs2_id, 2);
        set_val!(instance, config.rd_id, 2);
        set_val!(instance, config.prev_rs1_ts, 2);
        set_val!(instance, config.prev_rs2_ts, 2);
        set_val!(instance, config.prev_rd_ts, 2);

        let u16_max = u16::MAX as u64;

        set_val!(instance, config.lt_wtns_rs1.is_lt, 1);
        set_val!(instance, config.lt_wtns_rs1.diff_lo, u16_max - 2 + 1); // range - lhs + rhs
        set_val!(instance, config.lt_wtns_rs1.diff_hi, u16_max);

        set_val!(instance, config.lt_wtns_rs2.is_lt, 1);
        set_val!(instance, config.lt_wtns_rs2.diff_lo, u16_max - 3 + 2); // range - lhs + rhs
        set_val!(instance, config.lt_wtns_rs2.diff_hi, u16_max);

        set_val!(instance, config.lt_wtns_rd.is_lt, 1);
        set_val!(instance, config.lt_wtns_rd.diff_lo, u16_max - 3 + 2); // range - lhs + rhs
        set_val!(instance, config.lt_wtns_rd.diff_hi, u16_max);
        Ok(())
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
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // TODO use field from step
        set_val!(instance, config.pc, _step.pc().before.0 as u64);
        set_val!(instance, config.ts, 2);
        config.prev_rd_value.wits_in().map(|prev_rd_value| {
            set_val!(instance, prev_rd_value[0], 4);
            set_val!(instance, prev_rd_value[1], 4);
        });
        config.addend_0.wits_in().map(|addend_0| {
            set_val!(instance, addend_0[0], 4);
            set_val!(instance, addend_0[1], 4);
        });
        config.addend_1.wits_in().map(|addend_1| {
            set_val!(instance, addend_1[0], 4);
            set_val!(instance, addend_1[1], 4);
        });
        // TODO #174
        config.outcome.carries.as_ref().map(|carry| {
            set_val!(instance, carry[0], 4);
            set_val!(instance, carry[1], 0);
        });
        // TODO #167
        set_val!(instance, config.rs1_id, 2);
        set_val!(instance, config.rs2_id, 2);
        set_val!(instance, config.rd_id, 2);
        set_val!(instance, config.prev_rs1_ts, 2);
        set_val!(instance, config.prev_rs2_ts, 2);
        set_val!(instance, config.prev_rd_ts, 2);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, ReadOp, StepRecord, WriteOp};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::MockProver,
    };

    use super::AddInstruction;

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
            vec![StepRecord {
                rs1: Some(ReadOp {
                    addr: 2.into(),
                    value: 11u32,
                    previous_cycle: 0,
                }),
                rs2: Some(ReadOp {
                    addr: 3.into(),
                    value: 0xfffffffeu32,
                    previous_cycle: 0,
                }),
                rd: Some(WriteOp {
                    addr: 4.into(),
                    value: Change {
                        before: 0u32,
                        after: 9u32,
                    },
                    previous_cycle: 0,
                }),
                ..Default::default()
            }],
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
            vec![StepRecord {
                rs1: Some(ReadOp {
                    addr: 2.into(),
                    value: u32::MAX - 1,
                    previous_cycle: 0,
                }),
                rs2: Some(ReadOp {
                    addr: 3.into(),
                    value: u32::MAX - 1,
                    previous_cycle: 0,
                }),
                rd: Some(WriteOp {
                    addr: 4.into(),
                    value: Change {
                        before: 0u32,
                        after: u32::MAX - 2,
                    },
                    previous_cycle: 0,
                }),
                ..Default::default()
            }],
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
            Some([100.into(), 100000.into()]),
        );
    }
}
