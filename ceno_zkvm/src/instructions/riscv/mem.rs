use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::IsEqualConfig,
    instructions::{
        riscv::{constants::UInt, s_insn::SInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use goldilocks::ExtensionField;
use std::mem::MaybeUninit;

struct SWConfig<E: ExtensionField> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,

    equal: IsEqualConfig,
}
pub struct SWOp;

impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}

impl<E: ExtensionField> Instruction<E> for SWOp {
    type InstructionConfig = SWConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_red", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;
        // TODO: what does this true bool stand for
        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;

        // TODO: this should be the same as rs2_read (check for equality)
        let memory_written = UInt::new_unchecked(|| "memory_written", circuit_builder)?;

        let equal = IsEqualConfig::construct_circuit(
            circuit_builder,
            rs2_read.value(),
            memory_written.value(),
        )?;

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            imm,
            rs1_read,
            rs2_read,
            memory_addr,
            memory_written,
        )?;

        Ok(SWConfig {
            s_insn,
            rs1_read,
            rs2_read,
            equal,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
