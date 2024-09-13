use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    config::ExprLtConfig,
    constants::{OPType, OpcodeType, RegUInt, PC_STEP_SIZE},
    RIVInstruction,
};
use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{riscv::config::ExprLtInput, Instruction},
    uint::UIntValue,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

pub struct MulInstruction;

#[derive(Debug)]
pub struct InstructionConfig<E: ExtensionField> {
    // common
    pub pc: WitIn,
    pub ts: WitIn,

    // mul operation
    pub multiplier_1: RegUInt<E>,
    pub multiplier_2: RegUInt<E>,
    pub outcome: RegUInt<E>,
    pub prev_rd_value: RegUInt<E>,

    // register access
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub rd_id: WitIn,

    // register timestamp
    pub prev_rs1_ts: WitIn,
    pub prev_rs2_ts: WitIn,
    pub prev_rd_ts: WitIn,

    // timestamp comparison
    pub lt_rs1_ts_cfg: ExprLtConfig,
    pub lt_rs2_ts_cfg: ExprLtConfig,
    pub lt_rd_ts_cfg: ExprLtConfig,
}

impl<E: ExtensionField> RIVInstruction<E> for MulInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0000001);
}

fn mul_gadget<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = circuit_builder.create_witin(|| "pc")?;
    let cur_ts = circuit_builder.create_witin(|| "cur_ts")?;

    // state in
    circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

    // The value is stored in `rd`` before this operation
    let prev_rd_value = RegUInt::new(|| "prev_rd_value", circuit_builder)?;

    let mut multiplier_1 = RegUInt::new_unchecked(|| "multiplier_1", circuit_builder)?;
    let mut multiplier_2 = RegUInt::new_unchecked(|| "multiplier_2", circuit_builder)?;
    let outcome = multiplier_1.mul(|| "outcome", circuit_builder, &mut multiplier_2, true)?;

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

    let (next_ts, lt_rs1_ts_cfg) = circuit_builder.register_read(
        || "read_rs1",
        &rs1_id,
        prev_rs1_ts.expr(),
        cur_ts.expr(),
        &multiplier_1,
    )?;
    let (next_ts, lt_rs2_ts_cfg) = circuit_builder.register_read(
        || "read_rs2",
        &rs2_id,
        prev_rs2_ts.expr(),
        next_ts,
        &multiplier_2,
    )?;
    let (next_ts, lt_rd_ts_cfg) = circuit_builder.register_write(
        || "write_rd",
        &rd_id,
        prev_rd_ts.expr(),
        next_ts,
        &prev_rd_value,
        &outcome,
    )?;

    let next_pc = pc.expr() + PC_STEP_SIZE.into();
    circuit_builder.state_out(next_pc, next_ts)?;

    Ok(InstructionConfig {
        pc,
        ts: cur_ts,
        prev_rd_value,
        multiplier_1,
        multiplier_2,
        outcome,
        rs1_id,
        rs2_id,
        rd_id,
        prev_rs1_ts,
        prev_rs2_ts,
        prev_rd_ts,
        lt_rs1_ts_cfg,
        lt_rs2_ts_cfg,
        lt_rd_ts_cfg,
    })
}

impl<E: ExtensionField> Instruction<E> for MulInstruction {
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        mul_gadget::<E>(circuit_builder)
    }

    fn name() -> String {
        "MUL".into()
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .pc
            .assign::<E>(instance, E::BaseField::from(step.pc.before.0.into()));
        config
            .ts
            .assign::<E>(instance, E::BaseField::from(step.cycle));

        let multiplier_1 = UIntValue::new_unchecked(step.rs1().unwrap().value);
        let multiplier_2 = UIntValue::new_unchecked(step.rs2().unwrap().value);
        let prev_rd_value = UIntValue::new_unchecked(step.rd().unwrap().value.before);
        let outcome = UIntValue::new_unchecked(step.rd().unwrap().value.after);

        config
            .prev_rd_value
            .assign_limbs(instance, prev_rd_value.u16_fields());
        config
            .multiplier_1
            .assign_limbs(instance, multiplier_1.u16_fields());
        config
            .multiplier_2
            .assign_limbs(instance, multiplier_2.u16_fields());
        let (_, carries) = multiplier_1.mul(&multiplier_2, lk_multiplicity, true);

        config.outcome.assign_limbs(instance, outcome.u16_fields());
        config.outcome.assign_carries(
            instance,
            carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );

        config.rs1_id.assign::<E>(
            instance,
            E::BaseField::from(step.rs1().unwrap().addr.into()),
        );
        config.rs2_id.assign::<E>(
            instance,
            E::BaseField::from(step.rs2().unwrap().addr.into()),
        );
        config
            .rd_id
            .assign::<E>(instance, E::BaseField::from(step.rd().unwrap().addr.into()));

        let prev_rs1_ts = step.rs1().unwrap().previous_cycle;
        let prev_rs2_ts = step.rs2().unwrap().previous_cycle;
        let prev_rd_ts = step.rd().unwrap().previous_cycle;
        config
            .prev_rs1_ts
            .assign::<E>(instance, E::BaseField::from(prev_rs1_ts));
        config
            .prev_rs2_ts
            .assign::<E>(instance, E::BaseField::from(prev_rs2_ts));
        config
            .prev_rd_ts
            .assign::<E>(instance, E::BaseField::from(prev_rd_ts));

        ExprLtInput {
            lhs: prev_rs1_ts, // rs1_ts
            rhs: step.cycle,  // cur_ts
        }
        .assign(instance, &config.lt_rs1_ts_cfg);
        ExprLtInput {
            lhs: prev_rs2_ts,    // rs2_ts
            rhs: step.cycle + 1, // cur_ts
        }
        .assign(instance, &config.lt_rs2_ts_cfg);
        ExprLtInput {
            lhs: prev_rd_ts,     // rd_ts
            rhs: step.cycle + 2, // cur_ts
        }
        .assign(instance, &config.lt_rd_ts_cfg);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, ReadOp, StepRecord, WordAddr, WriteOp};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::MockProver,
    };

    use super::MulInstruction;

    #[test]
    fn test_opcode_mul() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let rs1 = Some(ReadOp {
            addr: WordAddr::from(1),
            value: 11u32,
            previous_cycle: 2,
        });
        let rs2 = Some(ReadOp {
            addr: WordAddr::from(2),
            value: 2u32,
            previous_cycle: 2,
        });
        let rd = Some(WriteOp {
            addr: WordAddr::from(3),
            value: Change {
                before: 0u32,
                after: 22u32,
            },
            previous_cycle: 2,
        });

        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord {
                cycle: 3,
                rs1,
                rs2,
                rd,
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
    fn test_opcode_mul_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let rs1 = Some(ReadOp {
            addr: WordAddr::from(1),
            value: u32::MAX / 2 + 1, // equals to 2^32 / 2
            previous_cycle: 2,
        });
        let rs2 = Some(ReadOp {
            addr: WordAddr::from(2),
            value: 2u32,
            previous_cycle: 2,
        });
        let rd = Some(WriteOp {
            addr: WordAddr::from(3),
            value: Change {
                before: 0u32,
                after: 0u32,
            },
            previous_cycle: 2,
        });

        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord {
                cycle: 3,
                rs1,
                rs2,
                rd,
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
    fn test_opcode_mul_overflow2() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let rs1 = Some(ReadOp {
            addr: WordAddr::from(1),
            value: 4294901760u32, // equals [0, u16::MAX]
            previous_cycle: 2,
        });
        let rs2 = Some(ReadOp {
            addr: WordAddr::from(2),
            value: 4294901760u32, // equals [0, u16::MAX]
            previous_cycle: 2,
        });
        // 429490176 * 429490176 % 2^32 = 0
        let rd = Some(WriteOp {
            addr: WordAddr::from(3),
            value: Change {
                before: 0u32,
                after: 0u32,
            },
            previous_cycle: 2,
        });

        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord {
                cycle: 3,
                rs1,
                rs2,
                rd,
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
