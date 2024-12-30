use std::marker::PhantomData;

use ceno_emul::{InsnKind, SWord, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    gadgets::{IsEqualConfig, IsLtConfig, SignedLtConfig},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            b_insn::BInstructionConfig,
            constants::{UINT_LIMBS, UInt},
        },
    },
    witness::LkMultiplicity,
};

pub struct BranchCircuit<E, I>(PhantomData<(E, I)>);

pub struct BranchConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,
    pub is_equal: Option<IsEqualConfig>, // For equality comparisons
    pub is_signed_lt: Option<SignedLtConfig<E>>, // For signed comparisons
    pub is_unsigned_lt: Option<IsLtConfig>, // For unsigned comparisons
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BranchCircuit<E, I> {
    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    type InstructionConfig = BranchConfig<E>;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<BranchConfig<E>, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        let (branch_taken_bit, is_equal, is_signed_lt, is_unsigned_lt) = match I::INST_KIND {
            InsnKind::BEQ => {
                let equal = IsEqualConfig::construct_circuit(
                    circuit_builder,
                    || "rs1!=rs2",
                    read_rs2.value(),
                    read_rs1.value(),
                )?;
                (equal.expr(), Some(equal), None, None)
            }
            InsnKind::BNE => {
                let equal = IsEqualConfig::construct_circuit(
                    circuit_builder,
                    || "rs1==rs2",
                    read_rs2.value(),
                    read_rs1.value(),
                )?;
                (Expression::ONE - equal.expr(), Some(equal), None, None)
            }
            InsnKind::BLT => {
                let signed_lt = SignedLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1<rs2",
                    &read_rs1,
                    &read_rs2,
                )?;
                (signed_lt.expr(), None, Some(signed_lt), None)
            }
            InsnKind::BGE => {
                let signed_lt = SignedLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1>=rs2",
                    &read_rs1,
                    &read_rs2,
                )?;
                (
                    Expression::ONE - signed_lt.expr(),
                    None,
                    Some(signed_lt),
                    None,
                )
            }
            InsnKind::BLTU => {
                let unsigned_lt = IsLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1<rs2",
                    read_rs1.value(),
                    read_rs2.value(),
                    UINT_LIMBS,
                )?;
                (unsigned_lt.expr(), None, None, Some(unsigned_lt))
            }
            InsnKind::BGEU => {
                let unsigned_lt = IsLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1 >= rs2",
                    read_rs1.value(),
                    read_rs2.value(),
                    UINT_LIMBS,
                )?;
                (
                    Expression::ONE - unsigned_lt.expr(),
                    None,
                    None,
                    Some(unsigned_lt),
                )
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            branch_taken_bit,
        )?;

        Ok(BranchConfig {
            b_insn,
            read_rs1,
            read_rs2,
            is_equal,
            is_signed_lt,
            is_unsigned_lt,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .b_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        config.read_rs1.assign_limbs(instance, rs1.as_u16_limbs());
        config.read_rs2.assign_limbs(instance, rs2.as_u16_limbs());

        if let Some(equal) = &config.is_equal {
            equal.assign_instance(
                instance,
                E::BaseField::from(rs2.as_u64()),
                E::BaseField::from(rs1.as_u64()),
            )?;
        }

        if let Some(signed_lt) = &config.is_signed_lt {
            signed_lt.assign_instance(
                instance,
                lk_multiplicity,
                step.rs1().unwrap().value as SWord,
                step.rs2().unwrap().value as SWord,
            )?;
        }

        if let Some(unsigned_lt) = &config.is_unsigned_lt {
            unsigned_lt.assign_instance(
                instance,
                lk_multiplicity,
                step.rs1().unwrap().value as u64,
                step.rs2().unwrap().value as u64,
            )?;
        }

        Ok(())
    }
}
