use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorBatchedMatMul2x2V1Spec, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::{Expression, ToExpr};
use p3::field::PrimeCharacteristicRing;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::{MemoryExpr, general::InstFetch},
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UInt},
            ecall::tensor_batched_matmul::tensor_batched_matmul_state_record,
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::TensorSignedWord,
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC: usize = 8;
const VALUES: usize = 4;
const A_START: usize = DESC;
const W_START: usize = A_START + VALUES;
const Q_START: usize = W_START + VALUES;
const R_START: usize = Q_START + VALUES;
const WORDS: usize = R_START + VALUES;

#[derive(Debug)]
pub struct TensorBatchedMatMul2x2EcallConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: [MemoryExpr<E>; WORDS],
    signed_a: [TensorSignedWord<E>; VALUES],
    signed_w: [TensorSignedWord<E>; VALUES],
    signed_q: [TensorSignedWord<E>; VALUES],
    a_carries: [multilinear_extensions::WitIn; VALUES],
    w_carries: [multilinear_extensions::WitIn; VALUES],
    q_carries: [multilinear_extensions::WitIn; VALUES],
    mem_rw: Vec<WriteMEM>,
}

pub struct TensorBatchedMatMul2x2EcallInstruction<E>(PhantomData<E>);

fn memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}

fn word<E: ExtensionField>(value: &MemoryExpr<E>) -> Expression<E> {
    value[0].clone() + value[1].clone() * (1u64 << 16)
}

fn assign_memory<E: ExtensionField>(instance: &mut [E::BaseField], expr: &MemoryExpr<E>, v: u32) {
    let value = Value::new_unchecked(v);
    for (expr, limb) in expr.iter().zip(value.as_u16_limbs()) {
        let Expression::WitIn(wit) = expr else {
            unreachable!("tiny batched MatMul memory limb is not witness")
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

fn bind_twos_complement<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    mem: &MemoryExpr<E>,
    signed: &TensorSignedWord<E>,
) -> Result<multilinear_extensions::WitIn, ZKVMError> {
    let carry = cb.create_witin(|| format!("{name}_neg_carry"));
    cb.assert_bit(|| format!("{name}_neg_carry_bit"), carry.expr())?;
    let positive = E::BaseField::ONE.expr() - signed.sign.expr();
    cb.require_zero(
        || format!("{name}_positive_lo"),
        positive.clone() * (mem[0].clone() - signed.magnitude[0].expr()),
    )?;
    cb.require_zero(
        || format!("{name}_positive_hi"),
        positive * (mem[1].clone() - signed.magnitude[1].expr()),
    )?;
    cb.require_zero(
        || format!("{name}_negative_lo"),
        signed.sign.expr()
            * (mem[0].clone() + signed.magnitude[0].expr() - carry.expr() * (1u64 << 16)),
    )?;
    cb.require_zero(
        || format!("{name}_negative_hi"),
        signed.sign.expr()
            * (mem[1].clone() + signed.magnitude[1].expr() + carry.expr() - (1u64 << 16)),
    )?;
    Ok(carry)
}

fn signed_words<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    words: &[MemoryExpr<E>],
    bits: usize,
) -> Result<
    (
        [TensorSignedWord<E>; VALUES],
        [multilinear_extensions::WitIn; VALUES],
    ),
    ZKVMError,
> {
    let pairs = words
        .iter()
        .enumerate()
        .map(|(i, mem)| {
            let signed = TensorSignedWord::construct(cb, &format!("{name}_{i}"), bits)?;
            let carry = bind_twos_complement(cb, &format!("{name}_{i}"), mem, &signed)?;
            Ok((signed, carry))
        })
        .collect::<Result<Vec<_>, ZKVMError>>()?;
    let (signed, carries): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    Ok((
        signed.try_into().expect("four signed values"),
        carries.try_into().expect("four signed carries"),
    ))
}

fn assign_signed<E: ExtensionField>(
    signed: &TensorSignedWord<E>,
    carry: multilinear_extensions::WitIn,
    instance: &mut [E::BaseField],
    lkm: &mut LkMultiplicity,
    raw: u32,
) {
    let value = raw as i32;
    signed.assign(instance, lkm, value);
    set_val!(
        instance,
        carry,
        u64::from((i64::from(value).unsigned_abs() & 0xffff) != 0)
    );
}

impl<E: ExtensionField> Instruction<E> for TensorBatchedMatMul2x2EcallInstruction<E> {
    type InstructionConfig = TensorBatchedMatMul2x2EcallConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "TensorBatchedMatMul2x2Ecall".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                TensorBatchedMatMul2x2V1Spec::CODE & LIMB_MASK,
                (TensorBatchedMatMul2x2V1Spec::CODE >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;
        let ptr = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let desc_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            ptr.uint_unaligned().register_expr(),
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

        let words = array::from_fn(|i| memory_expr(cb, &format!("tensor_batched_word_{i}")));
        for (index, expected) in [
            (0, ceno_emul::tensor::TENSOR_ABI_V1),
            (1, 0),
            (6, 0),
            (7, 0),
        ] {
            cb.require_equal(
                || format!("tensor_batched_desc_{index}"),
                word(&words[index]),
                E::BaseField::from_u32(expected).expr(),
            )?;
        }
        let (signed_a, a_carries) =
            signed_words(cb, "tensor_batched_ecall_a", &words[A_START..W_START], 8)?;
        let (signed_w, w_carries) =
            signed_words(cb, "tensor_batched_ecall_w", &words[W_START..Q_START], 8)?;
        let (signed_q, q_carries) =
            signed_words(cb, "tensor_batched_ecall_q", &words[Q_START..R_START], 16)?;

        for row in 0..VALUES {
            cb.write_record(
                || format!("tensor_batched_matmul_state_{row}"),
                RAMType::Custom,
                tensor_batched_matmul_state_record(
                    vm_state.ts.expr(),
                    ptr.expr_unaligned(),
                    E::BaseField::from_u32(row as u32).expr(),
                    signed_a[row].expr(),
                    signed_w[row].expr(),
                    signed_q[row].expr(),
                    word(&words[R_START + row]),
                ),
            )?;
        }

        let bases = [
            ptr.expr_unaligned(),
            word(&words[2]),
            word(&words[3]),
            word(&words[4]),
            word(&words[5]),
        ];
        let mem_rw = words
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let (base, off, output) = if i < DESC {
                    (bases[0].clone(), i, false)
                } else if i < W_START {
                    (bases[1].clone(), i - A_START, false)
                } else if i < Q_START {
                    (bases[2].clone(), i - W_START, false)
                } else if i < R_START {
                    (bases[3].clone(), i - Q_START, true)
                } else {
                    (bases[4].clone(), i - R_START, true)
                };
                let zero = array::from_fn(|_| E::BaseField::ZERO.expr());
                WriteMEM::construct_circuit(
                    cb,
                    base + E::BaseField::from_u32(ByteAddr::from((off * WORD_SIZE) as u32).0)
                        .expr(),
                    if output { zero } else { value.clone() },
                    value.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TensorBatchedMatMul2x2EcallConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            words,
            signed_a,
            signed_w,
            signed_q,
            a_carries,
            w_carries,
            q_carries,
            mem_rw,
        })
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!()
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let mut lkm = LkMultiplicity::default();
        let mut wit =
            RowMajorMatrix::new(indices.len(), num_witin, InstancePaddingStrategy::Default);
        let mut structural = RowMajorMatrix::new(
            indices.len(),
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        for ((instance, structural), index) in
            wit.iter_mut().zip(structural.iter_mut()).zip(indices)
        {
            if num_structural_witin > 0 {
                *structural.last_mut().unwrap() = E::BaseField::ONE;
            }
            let step = &steps[*index];
            let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
            let ops = step.syscall(&syscall_witnesses).ok_or_else(|| {
                ZKVMError::InvalidWitness("tiny batched MatMul syscall missing".into())
            })?;
            if ops.mem_ops.len() != WORDS || ops.tensor_batched_matmul_2x2.is_none() {
                return Err(ZKVMError::InvalidWitness(
                    "tiny batched MatMul syscall payload mismatch".into(),
                ));
            }
            config.vm_state.assign_instance(instance, shard_ctx, step)?;
            config.ecall_id.assign_op(
                instance,
                shard_ctx,
                &mut lkm,
                step.cycle(),
                &WriteOp::new_register_op(
                    Platform::reg_ecall(),
                    Change::new(
                        TensorBatchedMatMul2x2V1Spec::CODE,
                        TensorBatchedMatMul2x2V1Spec::CODE,
                    ),
                    step.rs1().unwrap().previous_cycle,
                ),
                step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
            )?;
            config
                .desc_ptr
                .1
                .assign_instance(instance, &mut lkm, ops.reg_ops[0].value.after)?;
            config.desc_ptr.0.assign_op(
                instance,
                shard_ctx,
                &mut lkm,
                step.cycle(),
                &ops.reg_ops[0],
                ops.reg_future_access[0] != 0,
            )?;
            for (i, (writer, op)) in config.mem_rw.iter().zip(&ops.mem_ops).enumerate() {
                assign_memory::<E>(
                    instance,
                    &config.words[i],
                    if i >= Q_START {
                        op.value.after
                    } else {
                        op.value.before
                    },
                );
                writer.assign_op(
                    instance,
                    shard_ctx,
                    &mut lkm,
                    step.cycle(),
                    op,
                    ops.mem_future_access[i] != 0,
                )?;
            }
            for i in 0..VALUES {
                assign_signed(
                    &config.signed_a[i],
                    config.a_carries[i],
                    instance,
                    &mut lkm,
                    ops.mem_ops[A_START + i].value.before,
                );
                assign_signed(
                    &config.signed_w[i],
                    config.w_carries[i],
                    instance,
                    &mut lkm,
                    ops.mem_ops[W_START + i].value.before,
                );
                assign_signed(
                    &config.signed_q[i],
                    config.q_carries[i],
                    instance,
                    &mut lkm,
                    ops.mem_ops[Q_START + i].value.after,
                );
            }
            lkm.fetch(step.pc().before.0);
        }
        wit.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([wit, structural], lkm.into_finalize_result()))
    }

    fn collect_lk_and_shardram(
        _: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        _: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
        let ops = step.syscall(&syscall_witnesses).ok_or_else(|| {
            ZKVMError::InvalidWitness("tiny batched MatMul syscall missing".into())
        })?;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            TensorBatchedMatMul2x2V1Spec::CODE,
            None,
            step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
        );
        shard_ctx.send(
            RAMType::Register,
            ops.reg_ops[0].addr,
            Platform::reg_arg0() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RD,
            ops.reg_ops[0].previous_cycle,
            ops.reg_ops[0].value.after,
            None,
            ops.reg_future_access[0] != 0,
        );
        for (i, op) in ops.mem_ops.iter().enumerate() {
            shard_ctx.send(
                RAMType::Memory,
                op.addr,
                op.addr.baddr().0 as u64,
                step.cycle() + FullTracer::SUBCYCLE_MEM,
                op.previous_cycle,
                op.value.after,
                Some(op.value.before),
                ops.mem_future_access[i] != 0,
            );
        }
        Ok(())
    }
}
