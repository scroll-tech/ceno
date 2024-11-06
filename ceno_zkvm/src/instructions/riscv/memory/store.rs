use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction, constants::UInt, insn_base::MemAddr, memory::gadget::MemWordChange,
            s_insn::SInstructionConfig,
        },
    },
    set_val,
    tables::InsnRecord,
    utils::i64_to_base,
    witness::LkMultiplicity,
};
use ceno_emul::{ByteAddr, CENO_PLATFORM, InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct StoreConfig<E: ExtensionField, const N_ZEROS: usize> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: WitIn,
    prev_memory_value: UInt<E>,

    memory_addr: MemAddr<E>,
    word_change: Option<MemWordChange<N_ZEROS>>,
}

pub struct StoreInstruction<E, I, const N_ZEROS: usize>(PhantomData<(E, I)>);

pub struct SWOp;
impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}
pub type SwInstruction<E> = StoreInstruction<E, SWOp, 2>;

pub struct SHOp;
impl RIVInstruction for SHOp {
    const INST_KIND: InsnKind = InsnKind::SH;
}
pub type ShInstruction<E> = StoreInstruction<E, SHOp, 1>;

pub struct SBOp;
impl RIVInstruction for SBOp {
    const INST_KIND: InsnKind = InsnKind::SB;
}
pub type SbInstruction<E> = StoreInstruction<E, SBOp, 0>;

impl<E: ExtensionField, I: RIVInstruction, const N_ZEROS: usize> Instruction<E>
    for StoreInstruction<E, I, N_ZEROS>
{
    type InstructionConfig = StoreConfig<E, N_ZEROS>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let prev_memory_value = UInt::new(|| "prev_memory_value", circuit_builder)?;
        let imm = circuit_builder.create_witin(|| "imm"); // signed 12-bit value

        let memory_addr = match I::INST_KIND {
            InsnKind::SW => MemAddr::construct_align4(circuit_builder),
            InsnKind::SH => MemAddr::construct_align2(circuit_builder),
            InsnKind::SB => MemAddr::construct_unaligned(circuit_builder),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }?;

        if cfg!(feature = "forbid_overflow") {
            const MAX_RAM_ADDR: u32 = u32::MAX - 0x7FF; // max positive imm is 0x7FF
            const MIN_RAM_ADDR: u32 = 0x800; // min negative imm is -0x800
            assert!(
                !CENO_PLATFORM.can_write(MAX_RAM_ADDR + 1)
                    && !CENO_PLATFORM.can_write(MIN_RAM_ADDR - 1)
            );
        }
        circuit_builder.require_equal(
            || "memory_addr = rs1_read + imm",
            memory_addr.expr_unaligned(),
            rs1_read.value() + imm.expr(),
        )?;

        let (new_memory_value, word_change) = match I::INST_KIND {
            InsnKind::SW => (rs2_read.memory_expr(), None),
            InsnKind::SH | InsnKind::SB => {
                let change = MemWordChange::<N_ZEROS>::construct_circuit(
                    circuit_builder,
                    &memory_addr,
                    &prev_memory_value,
                    &rs2_read,
                )?;
                (prev_memory_value.value() + change.value(), Some(change))
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.expr_align4(),
            prev_memory_value.memory_expr(),
            new_memory_value,
        )?;

        Ok(StoreConfig {
            s_insn,
            rs1_read,
            rs2_read,
            imm,
            prev_memory_value,
            memory_addr,
            word_change,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let memory_op = step.memory_op().unwrap();
        let imm = InsnRecord::imm_internal(&step.insn());
        let prev_mem_value = Value::new(memory_op.value.before, lk_multiplicity);

        let addr = ByteAddr::from(step.rs1().unwrap().value.wrapping_add_signed(imm as i32));
        config
            .s_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.rs2_read.assign_value(instance, rs2);
        set_val!(instance, config.imm, i64_to_base::<E::BaseField>(imm));
        config
            .prev_memory_value
            .assign_value(instance, prev_mem_value);

        config
            .memory_addr
            .assign_instance(instance, lk_multiplicity, addr.into())?;
        if let Some(change) = config.word_change.as_ref() {
            change.assign_instance::<E>(instance, lk_multiplicity, step, addr.shift())?;
        }

        Ok(())
    }
}
