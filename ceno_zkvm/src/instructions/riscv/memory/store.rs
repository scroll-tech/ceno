use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction, constants::UInt, insn_base::MemAddr, memory::gadget::MemWordUtil,
            s_insn::SInstructionConfig,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::{ByteAddr, InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{ToExpr, WitIn};
use std::marker::PhantomData;

pub struct StoreConfig<E: ExtensionField, const N_ZEROS: usize> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: WitIn,
    prev_memory_value: UInt<E>,

    memory_addr: MemAddr<E>,
    next_memory_value: Option<MemWordUtil<E, N_ZEROS>>,
}

pub struct StoreInstruction<E, I, const N_ZEROS: usize>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction, const N_ZEROS: usize> Instruction<E>
    for StoreInstruction<E, I, N_ZEROS>
{
    type InstructionConfig = StoreConfig<E, N_ZEROS>;
    type Record = StepRecord;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        params: &ProgramParams,
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
                !params.platform.can_write(MAX_RAM_ADDR + 1)
                    && !params.platform.can_write(MIN_RAM_ADDR - 1)
            );
        }
        circuit_builder.require_equal(
            || "memory_addr = rs1_read + imm",
            memory_addr.expr_unaligned(),
            rs1_read.value() + imm.expr(),
        )?;

        let (next_memory_value, next_memory) = match I::INST_KIND {
            InsnKind::SW => (rs2_read.memory_expr(), None),
            InsnKind::SH | InsnKind::SB => {
                let next_memory = MemWordUtil::<E, N_ZEROS>::construct_circuit(
                    circuit_builder,
                    &memory_addr,
                    &prev_memory_value,
                    &rs2_read,
                )?;
                (next_memory.as_lo_hi().clone(), Some(next_memory))
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            #[cfg(feature = "u16limb_circuit")]
            0.into(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.expr_align4(),
            prev_memory_value.memory_expr(),
            next_memory_value,
        )?;

        Ok(StoreConfig {
            s_insn,
            rs1_read,
            rs2_read,
            imm,
            prev_memory_value,
            memory_addr,
            next_memory_value: next_memory,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let memory_op = step.memory_op().unwrap();
        let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn());
        let prev_mem_value = Value::new(memory_op.value.before, lk_multiplicity);

        let addr = ByteAddr::from(step.rs1().unwrap().value.wrapping_add_signed(imm.0 as i32));
        config
            .s_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.rs2_read.assign_value(instance, rs2);
        set_val!(instance, config.imm, imm.1);
        config
            .prev_memory_value
            .assign_value(instance, prev_mem_value);

        config
            .memory_addr
            .assign_instance(instance, lk_multiplicity, addr.into())?;
        if let Some(change) = config.next_memory_value.as_ref() {
            change.assign_instance(instance, lk_multiplicity, step, addr.shift())?;
        }

        Ok(())
    }
}
