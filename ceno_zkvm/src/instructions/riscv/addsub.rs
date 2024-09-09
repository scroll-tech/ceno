use std::marker::PhantomData;

use ark_std::iterable::Iterable;
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    constants::{OPType, OpcodeType, RegUInt, PC_STEP_SIZE},
    RIVInstruction,
};
use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val,
    uint::UIntValue,
};
use core::mem::MaybeUninit;

pub struct AddInstruction;
pub struct SubInstruction;

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
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for AddInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0000000);
}

impl<E: ExtensionField> RIVInstruction<E> for SubInstruction {
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
    let prev_rd_value = RegUInt::new(|| "prev_rd_value", circuit_builder)?;

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
        phantom: PhantomData,
    })
}

impl<E: ExtensionField> Instruction<E> for AddInstruction {
    // const NAME: &'static str = "ADD";
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
        step: StepRecord,
    ) -> Result<(), ZKVMError> {
        // TODO use fields from step
        set_val!(instance, config.pc, 1);
        set_val!(instance, config.ts, 2);
        let addend_0 = UIntValue::new(step.rs1().unwrap().value);
        let addend_1 = UIntValue::new(step.rs2().unwrap().value);
        config
            .prev_rd_value
            .assign_limbs(instance, [0, 0].iter().map(E::BaseField::from).collect());
        config
            .addend_0
            .assign_limbs(instance, addend_0.u16_fields());
        config
            .addend_1
            .assign_limbs(instance, addend_1.u16_fields());
        let carries = addend_0.add_u16_carries(&addend_1);
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
        Ok(())
    }
}

impl<E: ExtensionField> Instruction<E> for SubInstruction {
    // const NAME: &'static str = "ADD";
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
        _step: StepRecord,
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
    use ceno_emul::{ReadOp, StepRecord};
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

        let raw_witin = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord {
                rs1: Some(ReadOp {
                    addr: 0.into(),
                    value: 11u32,
                    previous_cycle: 0,
                }),
                rs2: Some(ReadOp {
                    addr: 0.into(),
                    value: 0xfffffffeu32,
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

        let raw_witin = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord {
                rs1: Some(ReadOp {
                    addr: 0.into(),
                    value: u32::MAX - 1,
                    previous_cycle: 0,
                }),
                rs2: Some(ReadOp {
                    addr: 0.into(),
                    value: u32::MAX - 1,
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
}
