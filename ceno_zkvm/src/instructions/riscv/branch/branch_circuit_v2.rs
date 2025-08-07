use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::{UIntLimbsLT, UIntLimbsLTConfig},
    instructions::{
        Instruction,
        riscv::{RIVInstruction, b_insn::BInstructionConfig, constants::UInt},
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use multilinear_extensions::Expression;
use std::marker::PhantomData;

pub struct BranchCircuit<E, I>(PhantomData<(E, I)>);

pub struct BranchConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,

    pub uint_lt_config: UIntLimbsLTConfig<E>,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BranchCircuit<E, I> {
    type InstructionConfig = BranchConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        let is_signed = matches!(I::INST_KIND, InsnKind::BLT | InsnKind::BGE);
        let is_ge = matches!(I::INST_KIND, InsnKind::BGEU | InsnKind::BGE);
        let uint_lt_config =
            UIntLimbsLT::<E>::construct_circuit(circuit_builder, &read_rs1, &read_rs2, is_signed)?;
        let branch_taken_bit = if is_ge {
            Expression::ONE - uint_lt_config.is_lt()
        } else {
            uint_lt_config.is_lt()
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
            uint_lt_config,
            phantom: Default::default(),
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
        let rs1_limbs = rs1.as_u16_limbs();
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let rs2_limbs = rs2.as_u16_limbs();
        config.read_rs1.assign_limbs(instance, rs1_limbs);
        config.read_rs2.assign_limbs(instance, rs2_limbs);

        let is_signed = matches!(step.insn().kind, InsnKind::BLT | InsnKind::BGE);
        UIntLimbsLT::<E>::assign(
            &config.uint_lt_config,
            instance,
            lk_multiplicity,
            rs1_limbs,
            rs2_limbs,
            is_signed,
        )?;
        Ok(())
    }
}
