use std::marker::PhantomData;

use ceno_emul::{
    Change, InsnKind, Platform, PubIoCommitSpec, StepRecord, SyscallSpec, WORD_SIZE, WriteOp,
};
use ff_ext::ExtensionField;
use multilinear_extensions::ToExpr;
use p3::field::FieldAlgebra;

use crate::{
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UInt},
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{PUBIO_COMMIT_WORDS, PubioCommitLayout},
    structs::ProgramParams,
    tables::InsnRecord,
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallPubioCommitConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    digest_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    mem_rw: [WriteMEM; PUBIO_COMMIT_WORDS],
}

pub struct PubIoCommitInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for PubIoCommitInstruction<E> {
    type InstructionConfig = EcallPubioCommitConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "Ecall_PubioCommit".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let syscall_code = PubIoCommitSpec::CODE;

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                syscall_code & LIMB_MASK,
                (syscall_code >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let digest_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let digest_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            digest_ptr_value.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        cb.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            InsnKind::ECALL.into(),
            None,
            0.into(),
            0.into(),
            0.into(),
            #[cfg(feature = "u16limb_circuit")]
            0.into(),
        ))?;

        let layout = PubioCommitLayout::construct_circuit(cb)?;
        let mem_rw: [WriteMEM; PUBIO_COMMIT_WORDS] = (0..PUBIO_COMMIT_WORDS)
            .map(|i| {
                WriteMEM::construct_circuit(
                    cb,
                    digest_ptr.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_canonical_u32((i * WORD_SIZE) as u32).expr(),
                    layout.digest_words[i].clone(),
                    layout.digest_words[i].clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("pubio read width is fixed");

        Ok(EcallPubioCommitConfig {
            vm_state,
            ecall_id,
            digest_ptr: (digest_ptr, digest_ptr_value),
            mem_rw,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let syscall_code = PubIoCommitSpec::CODE;
        let ops = step
            .syscall(shard_ctx.syscall_witnesses.as_ref())
            .expect("syscall step")
            .clone();
        assert_eq!(ops.reg_ops.len(), 1, "PUB_IO_COMMIT expects 1 reg op");
        assert_eq!(
            ops.mem_ops.len(),
            PUBIO_COMMIT_WORDS,
            "PUB_IO_COMMIT expects {} mem ops",
            PUBIO_COMMIT_WORDS
        );

        config.vm_state.assign_instance(instance, shard_ctx, step)?;

        config.ecall_id.assign_op(
            instance,
            shard_ctx,
            lk_multiplicity,
            step.cycle(),
            &WriteOp::new_register_op(
                Platform::reg_ecall(),
                Change::new(syscall_code, syscall_code),
                step.rs1().unwrap().previous_cycle,
            ),
        )?;

        config.digest_ptr.1.assign_instance(
            instance,
            lk_multiplicity,
            ops.reg_ops[0].value.after,
        )?;
        config.digest_ptr.0.assign_op(
            instance,
            shard_ctx,
            lk_multiplicity,
            step.cycle(),
            &ops.reg_ops[0],
        )?;

        for (writer, op) in config.mem_rw.iter().zip(&ops.mem_ops) {
            writer.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), op)?;
        }

        lk_multiplicity.fetch(step.pc().before.0);
        Ok(())
    }
}
