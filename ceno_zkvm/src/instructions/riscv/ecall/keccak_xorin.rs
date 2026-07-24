use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, FullTracer as Tracer, InsnKind, KECCAK_RATE_WORDS, KECCAK_XORIN, Platform,
    StepRecord, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::PrimeCharacteristicRing;
use witness::set_val;

use crate::{
    chip_handler::{MemoryExpr, general::InstFetch},
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
    structs::{ProgramParams, RAMType},
    tables::InsnRecord,
    uint::Value,
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct KeccakXorinConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    state_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    block_ptr: (OpFixedRS<E, { Platform::reg_arg1() }, true>, MemAddr<E>),
    block_words: [MemoryExpr<E>; KECCAK_RATE_WORDS],
    state_words: [MemoryExpr<E>; KECCAK_RATE_WORDS],
    block_bytes: [[WitIn; WORD_SIZE]; KECCAK_RATE_WORDS],
    state_bytes: [[WitIn; WORD_SIZE]; KECCAK_RATE_WORDS],
    output_bytes: [[WitIn; WORD_SIZE]; KECCAK_RATE_WORDS],
    mem_rw: Vec<WriteMEM>,
}

pub struct KeccakXorinInstruction<E>(PhantomData<E>);

fn new_memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}

fn create_bytes<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> [WitIn; WORD_SIZE] {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")))
}

fn constrain_word_bytes<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    word: &MemoryExpr<E>,
    bytes: &[WitIn; WORD_SIZE],
) -> Result<(), ZKVMError> {
    let byte_base = E::BaseField::from_u32(1 << 8).expr();
    cb.require_zero(
        || format!("{name}_low_limb"),
        word[0].clone() - bytes[0].expr() - byte_base.clone() * bytes[1].expr(),
    )?;
    cb.require_zero(
        || format!("{name}_high_limb"),
        word[1].clone() - bytes[2].expr() - byte_base * bytes[3].expr(),
    )?;
    Ok(())
}

fn bytes_as_memory_expr<E: ExtensionField>(bytes: &[WitIn; WORD_SIZE]) -> MemoryExpr<E> {
    let byte_base = E::BaseField::from_u32(1 << 8).expr();
    [
        bytes[0].expr() + byte_base.clone() * bytes[1].expr(),
        bytes[2].expr() + byte_base * bytes[3].expr(),
    ]
}

fn assign_memory_expr<E: ExtensionField>(
    instance: &mut [E::BaseField],
    expr: &MemoryExpr<E>,
    value: u32,
) {
    let value = Value::new_unchecked(value);
    let limbs = value.as_u16_limbs();
    for (limb_expr, limb) in expr.iter().zip_eq(limbs.iter()) {
        let Expression::WitIn(wit) = limb_expr else {
            panic!("Keccak XOR-in memory limbs must be witness columns");
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

impl<E: ExtensionField> Instruction<E> for KeccakXorinInstruction<E> {
    type InstructionConfig = KeccakXorinConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "KeccakXorin".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                KECCAK_XORIN & LIMB_MASK,
                (KECCAK_XORIN >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let state_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let state_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            state_ptr_value.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;
        let block_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let block_ptr = OpFixedRS::<_, { Platform::reg_arg1() }, true>::construct_circuit(
            cb,
            block_ptr_value.uint_unaligned().register_expr(),
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

        let block_words = array::from_fn(|i| new_memory_expr(cb, &format!("block_word_{i}")));
        let state_words = array::from_fn(|i| new_memory_expr(cb, &format!("state_word_{i}")));
        let block_bytes = array::from_fn(|i| create_bytes(cb, &format!("block_byte_{i}")));
        let state_bytes = array::from_fn(|i| create_bytes(cb, &format!("state_byte_{i}")));
        let output_bytes = array::from_fn(|i| create_bytes(cb, &format!("output_byte_{i}")));

        for word in 0..KECCAK_RATE_WORDS {
            constrain_word_bytes(
                cb,
                &format!("block_{word}"),
                &block_words[word],
                &block_bytes[word],
            )?;
            constrain_word_bytes(
                cb,
                &format!("state_{word}"),
                &state_words[word],
                &state_bytes[word],
            )?;
            for byte in 0..WORD_SIZE {
                cb.lookup_xor_byte(
                    state_bytes[word][byte].expr(),
                    block_bytes[word][byte].expr(),
                    output_bytes[word][byte].expr(),
                )?;
            }
        }

        let mut mem_rw = block_words
            .iter()
            .enumerate()
            .map(|(i, word)| {
                WriteMEM::construct_circuit(
                    cb,
                    block_ptr.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_u32(ByteAddr::from((i * WORD_SIZE) as u32).0).expr(),
                    word.clone(),
                    word.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        mem_rw.extend(
            state_words
                .iter()
                .zip(output_bytes.iter())
                .enumerate()
                .map(|(i, (before, after))| {
                    WriteMEM::construct_circuit(
                        cb,
                        state_ptr.prev_value.as_ref().unwrap().value()
                            + E::BaseField::from_u32(ByteAddr::from((i * WORD_SIZE) as u32).0)
                                .expr(),
                        before.clone(),
                        bytes_as_memory_expr(after),
                        vm_state.ts,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        Ok(KeccakXorinConfig {
            vm_state,
            ecall_id,
            state_ptr: (state_ptr, state_ptr_value),
            block_ptr: (block_ptr, block_ptr_value),
            block_words,
            state_words,
            block_bytes,
            state_bytes,
            output_bytes,
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
        let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
        let ops = step
            .syscall(&syscall_witnesses)
            .expect("Keccak XOR-in syscall step");
        assert_eq!(ops.reg_ops.len(), 2);
        assert_eq!(ops.mem_ops.len(), KECCAK_RATE_WORDS * 2);

        config.vm_state.assign_instance(instance, shard_ctx, step)?;
        config.ecall_id.assign_op(
            instance,
            shard_ctx,
            lk_multiplicity,
            step.cycle(),
            &WriteOp::new_register_op(
                Platform::reg_ecall(),
                Change::new(KECCAK_XORIN, KECCAK_XORIN),
                step.rs1().unwrap().previous_cycle,
            ),
        )?;

        config.state_ptr.1.assign_instance(
            instance,
            lk_multiplicity,
            ops.reg_ops[0].value.after,
        )?;
        config.state_ptr.0.assign_op(
            instance,
            shard_ctx,
            lk_multiplicity,
            step.cycle(),
            &ops.reg_ops[0],
        )?;
        config.block_ptr.1.assign_instance(
            instance,
            lk_multiplicity,
            ops.reg_ops[1].value.after,
        )?;
        config.block_ptr.0.assign_op(
            instance,
            shard_ctx,
            lk_multiplicity,
            step.cycle(),
            &ops.reg_ops[1],
        )?;

        for word in 0..KECCAK_RATE_WORDS {
            let block = ops.mem_ops[word].value.before;
            let state = ops.mem_ops[KECCAK_RATE_WORDS + word].value.before;
            assign_memory_expr::<E>(instance, &config.block_words[word], block);
            assign_memory_expr::<E>(instance, &config.state_words[word], state);

            for byte in 0..WORD_SIZE {
                let block_byte = block.to_le_bytes()[byte];
                let state_byte = state.to_le_bytes()[byte];
                let output_byte = block_byte ^ state_byte;
                set_val!(instance, config.block_bytes[word][byte], block_byte as u64);
                set_val!(instance, config.state_bytes[word][byte], state_byte as u64);
                set_val!(
                    instance,
                    config.output_bytes[word][byte],
                    output_byte as u64
                );
                lk_multiplicity.lookup_xor_byte(state_byte as u64, block_byte as u64);
            }
        }

        for (writer, op) in config.mem_rw.iter().zip_eq(&ops.mem_ops) {
            writer.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), op)?;
        }
        lk_multiplicity.fetch(step.pc().before.0);
        Ok(())
    }

    fn collect_lk_and_shardram(
        _config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        _lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
        let ops = step
            .syscall(&syscall_witnesses)
            .expect("Keccak XOR-in syscall step");
        assert_eq!(ops.reg_ops.len(), 2);
        assert_eq!(ops.mem_ops.len(), KECCAK_RATE_WORDS * 2);

        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + Tracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            KECCAK_XORIN,
            None,
        );
        for (reg_id, op) in [Platform::reg_arg0(), Platform::reg_arg1()]
            .into_iter()
            .zip_eq(&ops.reg_ops)
        {
            shard_ctx.send(
                RAMType::Register,
                op.addr,
                reg_id as u64,
                step.cycle() + Tracer::SUBCYCLE_RD,
                op.previous_cycle,
                op.value.after,
                None,
            );
        }
        for op in &ops.mem_ops {
            shard_ctx.send(
                RAMType::Memory,
                op.addr,
                op.addr.baddr().0 as u64,
                step.cycle() + Tracer::SUBCYCLE_MEM,
                op.previous_cycle,
                op.value.after,
                Some(op.value.before),
            );
        }
        Ok(())
    }
}
