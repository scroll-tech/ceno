//! The circuit implementation of logic instructions.

use ff_ext::ExtensionField;
use gkr_iop::tables::OpsTable;
use itertools::Itertools;
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, UInt8},
            i_insn::IInstructionConfig,
            logic_imm::LogicOp,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    uint::UIntLimbs,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use multilinear_extensions::ToExpr;

/// The Instruction circuit for a given LogicOp.
pub struct LogicInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: LogicOp> Instruction<E> for LogicInstruction<E, I> {
    type InstructionConfig = LogicConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[I::INST_KIND]
    }

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let num_limbs = LIMB_BITS / 8;
        let config = LogicConfig::construct_circuit(cb, I::INST_KIND)?;
        // Constrain the registers based on the given lookup table.
        // lo
        UIntLimbs::<{ LIMB_BITS }, 8, E>::logic(
            cb,
            I::OpsTable::ROM_TYPE,
            &UIntLimbs::from_exprs_unchecked(
                config
                    .rs1_read
                    .expr()
                    .into_iter()
                    .take(num_limbs)
                    .collect_vec(),
            ),
            &config.imm_lo,
            &UIntLimbs::from_exprs_unchecked(
                config
                    .rd_written
                    .expr()
                    .into_iter()
                    .take(num_limbs)
                    .collect_vec(),
            ),
        )?;
        // hi
        UIntLimbs::<{ LIMB_BITS }, 8, E>::logic(
            cb,
            I::OpsTable::ROM_TYPE,
            &UIntLimbs::from_exprs_unchecked(
                config
                    .rs1_read
                    .expr()
                    .into_iter()
                    .skip(num_limbs)
                    .take(num_limbs)
                    .collect_vec(),
            ),
            &config.imm_hi,
            &UIntLimbs::from_exprs_unchecked(
                config
                    .rd_written
                    .expr()
                    .into_iter()
                    .skip(num_limbs)
                    .take(num_limbs)
                    .collect_vec(),
            ),
        )?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [<E as ExtensionField>::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1_lo = step.rs1().unwrap().value & LIMB_MASK;
        let rs1_hi = (step.rs1().unwrap().value >> LIMB_BITS) & LIMB_MASK;
        let imm_lo = InsnRecord::<E::BaseField>::imm_internal(&step.insn()).0 as u32 & LIMB_MASK;
        let imm_hi = (InsnRecord::<E::BaseField>::imm_signed_internal(&step.insn()).0 as u32
            >> LIMB_BITS)
            & LIMB_MASK;
        UIntLimbs::<{ LIMB_BITS }, 8, E>::logic_assign::<I::OpsTable>(
            lkm,
            rs1_lo.into(),
            imm_lo.into(),
        );
        UIntLimbs::<{ LIMB_BITS }, 8, E>::logic_assign::<I::OpsTable>(
            lkm,
            rs1_hi.into(),
            imm_hi.into(),
        );

        config.assign_instance(instance, shard_ctx, lkm, step)
    }
}

/// This config implements I-Instructions that represent registers values as 4 * u8.
/// Non-generic code shared by several circuits.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt8<E>,
    pub(crate) rd_written: UInt8<E>,
    imm_lo: UIntLimbs<{ LIMB_BITS }, 8, E>,
    imm_hi: UIntLimbs<{ LIMB_BITS }, 8, E>,
}

impl<E: ExtensionField> LogicConfig<E> {
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
    ) -> Result<Self, ZKVMError> {
        let rs1_read = UInt8::new_unchecked(|| "rs1_read", cb)?;
        let rd_written = UInt8::new_unchecked(|| "rd_written", cb)?;
        let imm_lo = UIntLimbs::<{ LIMB_BITS }, 8, E>::new_unchecked(|| "imm_lo", cb)?;
        let imm_hi = UIntLimbs::<{ LIMB_BITS }, 8, E>::new_unchecked(|| "imm_hi", cb)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            insn_kind,
            imm_lo.value(),
            imm_hi.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(Self {
            i_insn,
            rs1_read,
            imm_lo,
            imm_hi,
            rd_written,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let num_limbs = LIMB_BITS / 8;
        self.i_insn
            .assign_instance(instance, shard_ctx, lkm, step)?;

        let rs1_read = split_to_u8(step.rs1().unwrap().value);
        self.rs1_read.assign_limbs(instance, &rs1_read);

        let imm_lo =
            split_to_u8::<u16>(InsnRecord::<E::BaseField>::imm_internal(&step.insn()).0 as u32)
                [..num_limbs]
                .to_vec();
        let imm_hi = split_to_u8::<u16>(
            InsnRecord::<E::BaseField>::imm_signed_internal(&step.insn()).0 as u32,
        )[2..]
            .to_vec();
        self.imm_lo.assign_limbs(instance, &imm_lo);
        self.imm_hi.assign_limbs(instance, &imm_hi);

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        self.rd_written.assign_limbs(instance, &rd_written);

        Ok(())
    }
}
