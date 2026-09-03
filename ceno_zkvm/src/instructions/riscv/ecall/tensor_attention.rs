use std::{array, marker::PhantomData};

use ceno_emul::{
    ATTENTION_REDUCED_PROFILE_V1, ATTENTION_RESCALE_SHIFT_Q20_V1,
    ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1, ATTENTION_SOFTMAX_TABLE_REDUCED_V1, ByteAddr, Change,
    FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorAttentionReducedV1Spec, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::{Expression, ToExpr, WitIn};
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
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{
        ATTENTION_STATE_PHASE_INPUT, ATTENTION_STATE_PHASE_OUTPUT, TensorAttentionStateRecord,
        tensor_attention_state_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC_WORDS: usize = 32;
const QKV_WORDS: usize = 12;
const OUTPUT_WORDS: usize = 4;
const TOTAL_WORDS: usize = DESC_WORDS + QKV_WORDS + OUTPUT_WORDS;

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
            panic!("attention memory limb is not witness")
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

fn flatten<E: ExtensionField>(words: &[MemoryExpr<E>]) -> Vec<Expression<E>> {
    words.iter().flat_map(|word| word.iter().cloned()).collect()
}

#[derive(Debug)]
pub struct TensorAttentionReducedEcallConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: [MemoryExpr<E>; TOTAL_WORDS],
    mem_rw: Vec<WriteMEM>,
}

#[derive(Debug)]
pub struct TensorAttentionReducedCoreConfig<E: ExtensionField> {
    cycle: WitIn,
    call_id: WitIn,
    words: [[WitIn; 2]; TOTAL_WORDS],
    marker: PhantomData<E>,
}

pub struct TensorAttentionReducedEcallInstruction<E>(PhantomData<E>);
pub struct TensorAttentionReducedCoreInstruction<E>(PhantomData<E>);

fn expected_words() -> [u32; TOTAL_WORDS] {
    let mut words = [0u32; TOTAL_WORDS];
    words[0] = ceno_emul::tensor::TENSOR_ABI_V1;
    words[1] = ATTENTION_REDUCED_PROFILE_V1;
    words[2] = ATTENTION_RESCALE_SHIFT_Q20_V1;
    words[3] = ATTENTION_SOFTMAX_TABLE_REDUCED_V1;
    words[4..12].copy_from_slice(&ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1);
    // Descriptor pointers [12..16] are deliberately dynamic and bound by the journal.
    words[18] = 2;
    words[21] = 11;
    words[22] = 25;
    for chunk in 0..3 {
        words[DESC_WORDS + chunk * 4..DESC_WORDS + (chunk + 1) * 4].copy_from_slice(&[
            1,
            (-2i32) as u32,
            3,
            (-4i32) as u32,
        ]);
    }
    words[DESC_WORDS + QKV_WORDS..].copy_from_slice(&[1, (-2i32) as u32, 4, (-6i32) as u32]);
    words
}

impl<E: ExtensionField> TensorAttentionReducedCoreConfig<E> {
    fn construct(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let cycle = cb.create_witin(|| "tensor_attention_cycle");
        let call_id = cb.create_witin(|| "tensor_attention_call_id");
        let words = array::from_fn(|i| {
            array::from_fn(|j| cb.create_witin(|| format!("tensor_attention_core_word_{i}_{j}")))
        });
        for i in 0..TOTAL_WORDS {
            for j in 0..2 {
                cb.assert_const_range(
                    || format!("tensor_attention_core_word_{i}_{j}_u16"),
                    words[i][j].expr(),
                    16,
                )?;
            }
        }
        let expected = expected_words();
        for i in 0..TOTAL_WORDS {
            if (12..16).contains(&i) {
                continue;
            }
            cb.require_equal(
                || format!("tensor_attention_registered_word_{i}"),
                words[i][0].expr() + words[i][1].expr() * (1u64 << 16),
                E::BaseField::from_u32(expected[i]).expr(),
            )?;
        }
        let descriptor: Vec<Expression<E>> = words[..DESC_WORDS]
            .iter()
            .flat_map(|x| x.iter().map(|x| x.expr()))
            .collect();
        let qkv_output: Vec<Expression<E>> = words[DESC_WORDS..]
            .iter()
            .flat_map(|x| x.iter().map(|x| x.expr()))
            .collect();
        let record = |phase| {
            tensor_attention_state_record(TensorAttentionStateRecord {
                cycle: cycle.expr(),
                call_id: call_id.expr(),
                phase,
                descriptor: descriptor.clone(),
                qkv_output: qkv_output.clone(),
            })
        };
        cb.read_record(
            || "tensor_attention_state_in",
            RAMType::Custom,
            record(ATTENTION_STATE_PHASE_INPUT),
        )?;
        cb.write_record(
            || "tensor_attention_state_out",
            RAMType::Custom,
            record(ATTENTION_STATE_PHASE_OUTPUT),
        )?;
        Ok(Self {
            cycle,
            call_id,
            words,
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_builder::ConstraintSystem;
    use ff_ext::{BabyBearExt4, FieldFrom};
    use itertools::Itertools;
    use multilinear_extensions::utils::eval_by_expr_with_instance;
    use std::sync::Arc;

    type E = BabyBearExt4;

    fn eval(
        expr: &Expression<E>,
        wit: &[<E as ExtensionField>::BaseField],
        structural: &[<E as ExtensionField>::BaseField],
    ) -> E {
        let wit = wit.iter().copied().map(E::from).collect_vec();
        let structural = structural.iter().copied().map(E::from).collect_vec();
        eval_by_expr_with_instance::<E>(
            &[],
            &wit,
            &structural,
            &[],
            &[E::from_v(7), E::from_v(11)],
            expr,
        )
        .unwrap_right()
    }

    fn circuits() -> (
        ConstraintSystem<E>,
        TensorAttentionReducedEcallConfig<E>,
        usize,
        usize,
        ConstraintSystem<E>,
        TensorAttentionReducedCoreConfig<E>,
        usize,
        usize,
    ) {
        let mut ecall_cs = ConstraintSystem::<E>::new(|| "attention_ecall");
        let mut ecall_cb = CircuitBuilder::new(&mut ecall_cs);
        let (ecall_config, _) = TensorAttentionReducedEcallInstruction::<E>::build_gkr_iop_circuit(
            &mut ecall_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let en = ecall_cb.cs.num_witin as usize;
        let es = ecall_cb.cs.num_structural_witin as usize;
        let mut core_cs = ConstraintSystem::<E>::new(|| "attention_core");
        let mut core_cb = CircuitBuilder::new(&mut core_cs);
        let (core_config, _) = TensorAttentionReducedCoreInstruction::<E>::build_gkr_iop_circuit(
            &mut core_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let cn = core_cb.cs.num_witin as usize;
        let cs = core_cb.cs.num_structural_witin as usize;
        (ecall_cs, ecall_config, en, es, core_cs, core_config, cn, cs)
    }

    #[test]
    fn split_records_match_and_registered_relation_rejects_tampering() {
        let (step, _, syscall_witnesses) = ceno_emul::test_utils::tensor_attention_step();
        let (ecall_cs, ecall_config, en, esn, core_cs, core_config, cn, csn) = circuits();
        let steps = vec![step];
        let indices = vec![0];
        let mut ectx = ShardContext::default();
        ectx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (ermm, _) = TensorAttentionReducedEcallInstruction::<E>::assign_instances(
            &ecall_config,
            &mut ectx,
            en,
            esn,
            &steps,
            &indices,
        )
        .unwrap();
        let mut cctx = ShardContext::default();
        cctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (crmm, _) = TensorAttentionReducedCoreInstruction::<E>::assign_instances(
            &core_config,
            &mut cctx,
            cn,
            csn,
            &steps,
            &indices,
        )
        .unwrap();
        let ew = &ermm[0].values()[..en];
        let es = &ermm[1].values()[..esn.max(1)];
        let cw = &crmm[0].values()[..cn];
        let cs = &crmm[1].values()[..csn.max(1)];
        let e_in = ecall_cs
            .w_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_attention_state_in"))
            .unwrap();
        let e_out = ecall_cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_attention_state_out"))
            .unwrap();
        let c_in = core_cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_attention_state_in"))
            .unwrap();
        let c_out = core_cs
            .w_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_attention_state_out"))
            .unwrap();
        assert_eq!(
            eval(&ecall_cs.w_expressions[e_in], ew, es),
            eval(&core_cs.r_expressions[c_in], cw, cs)
        );
        assert_eq!(
            eval(&ecall_cs.r_expressions[e_out], ew, es),
            eval(&core_cs.w_expressions[c_out], cw, cs)
        );

        // Profile, table, commitment, coordinate, mask, accumulator, shift,
        // Q/K/V and output are independently rejected by the core relation.
        for index in [1usize, 3, 4, 16, 18, 19, 21, 32, 36, 40, 44] {
            let mut bad = syscall_witnesses.clone();
            if index >= 44 {
                bad[0].mem_ops[index].value.after ^= 1;
            } else {
                bad[0].mem_ops[index].value.before ^= 1;
            }
            let mut ctx = ShardContext::default();
            ctx.syscall_witnesses = Arc::new(bad);
            assert!(
                TensorAttentionReducedCoreInstruction::<E>::assign_instances(
                    &core_config,
                    &mut ctx,
                    cn,
                    csn,
                    &steps,
                    &indices
                )
                .is_err(),
                "word {index} was not rejected"
            );
        }
    }
}

impl<E: ExtensionField> Instruction<E> for TensorAttentionReducedEcallInstruction<E> {
    type InstructionConfig = TensorAttentionReducedEcallConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorAttentionReducedEcall".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                TensorAttentionReducedV1Spec::CODE & LIMB_MASK,
                (TensorAttentionReducedV1Spec::CODE >> LIMB_BITS) & LIMB_MASK,
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
        let words = array::from_fn(|i| memory_expr(cb, &format!("tensor_attention_word_{i}")));
        let expected = expected_words();
        for i in 0..DESC_WORDS {
            if (12..16).contains(&i) {
                continue;
            }
            cb.require_equal(
                || format!("tensor_attention_desc_{i}"),
                word(&words[i]),
                E::BaseField::from_u32(expected[i]).expr(),
            )?;
        }
        let descriptor = flatten(&words[..DESC_WORDS]);
        let qkv_output = flatten(&words[DESC_WORDS..]);
        let record = |phase| {
            tensor_attention_state_record(TensorAttentionStateRecord {
                cycle: vm_state.ts.expr(),
                call_id: ptr.expr_unaligned(),
                phase,
                descriptor: descriptor.clone(),
                qkv_output: qkv_output.clone(),
            })
        };
        cb.write_record(
            || "tensor_attention_state_in",
            RAMType::Custom,
            record(ATTENTION_STATE_PHASE_INPUT),
        )?;
        cb.read_record(
            || "tensor_attention_state_out",
            RAMType::Custom,
            record(ATTENTION_STATE_PHASE_OUTPUT),
        )?;
        let mut mem_rw = Vec::with_capacity(TOTAL_WORDS);
        for i in 0..TOTAL_WORDS {
            let (base, off, before, after) = if i < DESC_WORDS {
                (ptr.expr_unaligned(), i, words[i].clone(), words[i].clone())
            } else if i < DESC_WORDS + QKV_WORDS {
                let group = (i - DESC_WORDS) / 4;
                (
                    word(&words[12 + group]),
                    (i - DESC_WORDS) % 4,
                    words[i].clone(),
                    words[i].clone(),
                )
            } else {
                (
                    word(&words[15]),
                    i - DESC_WORDS - QKV_WORDS,
                    array::from_fn(|_| E::BaseField::ZERO.expr()),
                    words[i].clone(),
                )
            };
            mem_rw.push(WriteMEM::construct_circuit(
                cb,
                base + E::BaseField::from_u32(ByteAddr::from((off * WORD_SIZE) as u32).0).expr(),
                before,
                after,
                vm_state.ts,
            )?);
        }
        Ok(TensorAttentionReducedEcallConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            words,
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
            *structural.last_mut().unwrap() = E::BaseField::ONE;
            let step = &steps[*index];
            let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
            let ops = step
                .syscall(&syscall_witnesses)
                .ok_or_else(|| ZKVMError::InvalidWitness("attention syscall missing".into()))?;
            if ops.mem_ops.len() != TOTAL_WORDS {
                return Err(ZKVMError::InvalidWitness(
                    "attention syscall memory count".into(),
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
                        TensorAttentionReducedV1Spec::CODE,
                        TensorAttentionReducedV1Spec::CODE,
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
                let value = if i >= DESC_WORDS + QKV_WORDS {
                    op.value.after
                } else {
                    op.value.before
                };
                assign_memory::<E>(instance, &config.words[i], value);
                writer.assign_op(
                    instance,
                    shard_ctx,
                    &mut lkm,
                    step.cycle(),
                    op,
                    ops.mem_future_access[i] != 0,
                )?;
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
        let ops = step
            .syscall(&syscall_witnesses)
            .ok_or_else(|| ZKVMError::InvalidWitness("attention syscall missing".into()))?;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            TensorAttentionReducedV1Spec::CODE,
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

impl<E: ExtensionField> Instruction<E> for TensorAttentionReducedCoreInstruction<E> {
    type InstructionConfig = TensorAttentionReducedCoreConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorAttentionReducedCore".into()
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        TensorAttentionReducedCoreConfig::construct(cb)
    }
    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let ops = step
            .syscall(&shard_ctx.syscall_witnesses)
            .ok_or_else(|| ZKVMError::InvalidWitness("attention syscall missing".into()))?;
        if ops.mem_ops.len() != TOTAL_WORDS {
            return Err(ZKVMError::InvalidWitness(
                "attention syscall memory count".into(),
            ));
        }
        set_val!(
            instance,
            config.cycle,
            step.cycle() - shard_ctx.current_shard_offset_cycle()
        );
        set_val!(instance, config.call_id, ops.reg_ops[0].value.after as u64);
        let expected = expected_words();
        for i in 0..TOTAL_WORDS {
            let raw = if i >= DESC_WORDS + QKV_WORDS {
                ops.mem_ops[i].value.after
            } else {
                ops.mem_ops[i].value.before
            };
            if !(12..16).contains(&i) && raw != expected[i] {
                return Err(ZKVMError::InvalidWitness(
                    format!("attention registered relation mismatch at word {i}").into(),
                ));
            }
            set_val!(instance, config.words[i][0], u64::from(raw & 0xffff));
            set_val!(instance, config.words[i][1], u64::from(raw >> 16));
            lkm.assert_const_range(u64::from(raw & 0xffff), 16);
            lkm.assert_const_range(u64::from(raw >> 16), 16);
        }
        Ok(())
    }
}
