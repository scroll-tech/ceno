use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{constants::UInt8, r_insn::RInstructionConfig, RIVInstruction};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction, uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles R-Instructions that represent registers values as 4 * u8.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt8<E>,
    rs2_read: UInt8<E>,
    rd_written: UInt8<E>,
}

pub struct LogicInstruction<E, I>(PhantomData<(E, I)>);

pub struct AndOp;
impl RIVInstruction for AndOp {
    const INST_KIND: InsnKind = InsnKind::AND;
}
pub type AndInstruction<E> = LogicInstruction<E, AndOp>;

pub struct SubOp;
impl RIVInstruction for SubOp {
    const INST_KIND: InsnKind = InsnKind::SUB;
}
pub type SubInstruction<E> = LogicInstruction<E, SubOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LogicInstruction<E, I> {
    type InstructionConfig = LogicConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let (rs1_read, rs2_read, rd_written) = match I::INST_KIND {
            InsnKind::AND => {
                // rd_written = rs1_read + rs2_read
                let rs1_read = UInt8::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rs2_read = UInt8::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rd_written = rs1_read.add(|| "rd_written", circuit_builder, &rs2_read, true)?;
                (rs1_read, rs2_read, rd_written)
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &rs1_read,
            &rs2_read,
            &rd_written,
        )?;

        Ok(LogicConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.u16_fields());

        match I::INST_KIND {
            InsnKind::ADD => {
                // rs1_read + rs2_read = rd_written
                let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
                config
                    .rs1_read
                    .assign_limbs(instance, rs1_read.u16_fields());
                let (_, outcome_carries) = rs1_read.add(&rs2_read, lk_multiplicity, true);
                config.rd_written.assign_carries(
                    instance,
                    outcome_carries
                        .into_iter()
                        .map(|carry| E::BaseField::from(carry as u64))
                        .collect_vec(),
                );
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        Ok(())
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

    use super::*;

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_and() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "and",
                |cb| {
                    let config = AndInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AndInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                11,
                0xfffffffe,
                Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
                0,
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
