use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorRmsLookupV1Spec, WORD_SIZE, WriteOp,
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
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{
        RESIDUAL_LOOKUP_PACKED_REDUCED_V1, RESIDUAL_TABLE_REDUCED_V1, RMS_INV_LOOKUP_V1,
        RMS_INV_TABLE_REDUCED_V1, RMS_STATE_PHASE_INPUT, RMS_STATE_PHASE_OUTPUT,
        ROPE_LOOKUP_Q16_REDUCED_V1, ROPE_TABLE_REDUCED_V1, SWIGLU_LOOKUP_V1,
        SWIGLU_TABLE_REDUCED_V1, TensorRmsLookupCoreConfig, TensorRmsStateRecord, TensorSignedWord,
        tensor_rms_state_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC: usize = 8;
const INPUT: usize = 8;
const OUTPUT: usize = 9;

#[derive(Debug)]
pub struct TensorRmsLookupEcallConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: [MemoryExpr<E>; 10],
    input: TensorSignedWord<E>,
    output: TensorSignedWord<E>,
    input_carry: multilinear_extensions::WitIn,
    output_carry: multilinear_extensions::WitIn,
    mem_rw: Vec<WriteMEM>,
}

pub struct TensorRmsLookupEcallInstruction<E>(PhantomData<E>);
pub struct TensorRmsLookupCoreInstruction<E>(PhantomData<E>);

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
            panic!("RMS memory limb is not witness")
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
    let carry = cb.create_witin(|| format!("{name}_carry"));
    cb.assert_bit(|| format!("{name}_carry_bit"), carry.expr())?;
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

impl<E: ExtensionField> Instruction<E> for TensorRmsLookupEcallInstruction<E> {
    type InstructionConfig = TensorRmsLookupEcallConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorRmsLookupEcall".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                TensorRmsLookupV1Spec::CODE & LIMB_MASK,
                (TensorRmsLookupV1Spec::CODE >> LIMB_BITS) & LIMB_MASK,
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
        let words = array::from_fn(|i| memory_expr(cb, &format!("tensor_rms_word_{i}")));
        for (index, expected) in [
            (0, ceno_emul::tensor::TENSOR_ABI_V1),
            (5, 0),
            (6, 0),
            (7, 0),
        ] {
            cb.require_equal(
                || format!("tensor_rms_desc_{index}"),
                word(&words[index]),
                E::BaseField::from_u32(expected).expr(),
            )?;
        }
        let input = TensorSignedWord::construct(cb, "tensor_rms_ecall_input", 18)?;
        let output = TensorSignedWord::construct(cb, "tensor_rms_ecall_output", 18)?;
        let input_carry =
            bind_twos_complement(cb, "tensor_rms_ecall_input", &words[INPUT], &input)?;
        let output_carry =
            bind_twos_complement(cb, "tensor_rms_ecall_output", &words[OUTPUT], &output)?;
        let record = |phase| {
            tensor_rms_state_record(TensorRmsStateRecord {
                cycle: vm_state.ts.expr(),
                call_id: ptr.expr_unaligned(),
                phase,
                profile: word(&words[1]),
                table_id: word(&words[2]),
                input: input.expr(),
                output: output.expr(),
            })
        };
        cb.write_record(
            || "tensor_rms_state_in",
            RAMType::Custom,
            record(RMS_STATE_PHASE_INPUT),
        )?;
        cb.read_record(
            || "tensor_rms_state_out",
            RAMType::Custom,
            record(RMS_STATE_PHASE_OUTPUT),
        )?;
        let mut mem_rw = Vec::with_capacity(10);
        for i in 0..10 {
            let (base, off, before, after) = if i < DESC {
                (ptr.expr_unaligned(), i, words[i].clone(), words[i].clone())
            } else if i == INPUT {
                (word(&words[3]), 0, words[i].clone(), words[i].clone())
            } else {
                (
                    word(&words[4]),
                    0,
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
        Ok(TensorRmsLookupEcallConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            words,
            input,
            output,
            input_carry,
            output_carry,
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
                .ok_or_else(|| ZKVMError::InvalidWitness("RMS syscall missing".into()))?;
            if ops.mem_ops.len() != 10 {
                return Err(ZKVMError::InvalidWitness("RMS syscall memory count".into()));
            }
            config.vm_state.assign_instance(instance, shard_ctx, step)?;
            config.ecall_id.assign_op(
                instance,
                shard_ctx,
                &mut lkm,
                step.cycle(),
                &WriteOp::new_register_op(
                    Platform::reg_ecall(),
                    Change::new(TensorRmsLookupV1Spec::CODE, TensorRmsLookupV1Spec::CODE),
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
                    if i == OUTPUT {
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
            assign_signed(
                &config.input,
                config.input_carry,
                instance,
                &mut lkm,
                ops.mem_ops[INPUT].value.before,
            );
            assign_signed(
                &config.output,
                config.output_carry,
                instance,
                &mut lkm,
                ops.mem_ops[OUTPUT].value.after,
            );
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
            .ok_or_else(|| ZKVMError::InvalidWitness("RMS syscall missing".into()))?;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            TensorRmsLookupV1Spec::CODE,
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

impl<E: ExtensionField> Instruction<E> for TensorRmsLookupCoreInstruction<E> {
    type InstructionConfig = TensorRmsLookupCoreConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorRmsLookupCore".into()
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        TensorRmsLookupCoreConfig::construct(cb)
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
            .ok_or_else(|| ZKVMError::InvalidWitness("RMS syscall missing".into()))?;
        let profile = ops.mem_ops[1].value.before;
        let table_id = ops.mem_ops[2].value.before;
        if !matches!(
            (profile, table_id),
            (RMS_INV_LOOKUP_V1, RMS_INV_TABLE_REDUCED_V1)
                | (SWIGLU_LOOKUP_V1, SWIGLU_TABLE_REDUCED_V1)
                | (ROPE_LOOKUP_Q16_REDUCED_V1, ROPE_TABLE_REDUCED_V1)
                | (RESIDUAL_LOOKUP_PACKED_REDUCED_V1, RESIDUAL_TABLE_REDUCED_V1)
        ) {
            return Err(ZKVMError::InvalidWitness(
                "unsupported RMS profile/table identity".into(),
            ));
        }
        let input = ops.mem_ops[INPUT].value.before as i32;
        let journal_output = ops.mem_ops[OUTPUT].value.after as i32;
        set_val!(
            instance,
            config.cycle,
            step.cycle() - shard_ctx.current_shard_offset_cycle()
        );
        set_val!(instance, config.call_id, ops.reg_ops[0].value.after as u64);
        let output = config
            .lookup
            .assign(instance, lkm, profile, table_id, input)
            .map_err(|e| ZKVMError::InvalidWitness(e.into_boxed_str()))?;
        if output != journal_output {
            return Err(ZKVMError::InvalidWitness(
                "RMS journal output mismatch".into(),
            ));
        }
        Ok(())
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

    #[test]
    fn split_records_match_and_tampering_fails() {
        let (step, _, syscall_witnesses) = ceno_emul::test_utils::tensor_rms_step();
        let steps = vec![step];
        let indices = vec![0];
        let mut ecall_cs = ConstraintSystem::<E>::new(|| "rms_ecall");
        let mut ecall_cb = CircuitBuilder::new(&mut ecall_cs);
        let (ecall_config, _) = TensorRmsLookupEcallInstruction::<E>::build_gkr_iop_circuit(
            &mut ecall_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let mut core_cs = ConstraintSystem::<E>::new(|| "rms_core");
        let mut core_cb = CircuitBuilder::new(&mut core_cs);
        let (core_config, _) = TensorRmsLookupCoreInstruction::<E>::build_gkr_iop_circuit(
            &mut core_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let mut ecall_ctx = ShardContext::default();
        ecall_ctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (ecall_rmms, _) = TensorRmsLookupEcallInstruction::<E>::assign_instances(
            &ecall_config,
            &mut ecall_ctx,
            ecall_cb.cs.num_witin as usize,
            ecall_cb.cs.num_structural_witin as usize,
            &steps,
            &indices,
        )
        .unwrap();
        let mut core_ctx = ShardContext::default();
        core_ctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (core_rmms, _) = TensorRmsLookupCoreInstruction::<E>::assign_instances(
            &core_config,
            &mut core_ctx,
            core_cb.cs.num_witin as usize,
            core_cb.cs.num_structural_witin as usize,
            &steps,
            &indices,
        )
        .unwrap();
        let ew = &ecall_rmms[0].values()[..ecall_cb.cs.num_witin as usize];
        let es = &ecall_rmms[1].values()[..(ecall_cb.cs.num_structural_witin as usize).max(1)];
        let cw = &core_rmms[0].values()[..core_cb.cs.num_witin as usize];
        let cs = &core_rmms[1].values()[..(core_cb.cs.num_structural_witin as usize).max(1)];
        let e_in = ecall_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_rms_state_in"))
            .unwrap();
        let e_out = ecall_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_rms_state_out"))
            .unwrap();
        let c_in = core_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_rms_state_in"))
            .unwrap();
        let c_out = core_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_rms_state_out"))
            .unwrap();
        assert_eq!(
            eval(&ecall_cb.cs.w_expressions[e_in], ew, es),
            eval(&core_cb.cs.r_expressions[c_in], cw, cs)
        );
        assert_eq!(
            eval(&ecall_cb.cs.r_expressions[e_out], ew, es),
            eval(&core_cb.cs.w_expressions[c_out], cw, cs)
        );

        for index in [1usize, 2, INPUT, OUTPUT] {
            let mut bad = syscall_witnesses.clone();
            if index == OUTPUT {
                bad[0].mem_ops[index].value.after ^= 1;
            } else {
                bad[0].mem_ops[index].value.before ^= 1;
            }
            let mut bad_ctx = ShardContext::default();
            bad_ctx.syscall_witnesses = Arc::new(bad);
            assert!(
                TensorRmsLookupCoreInstruction::<E>::assign_instances(
                    &core_config,
                    &mut bad_ctx,
                    core_cb.cs.num_witin as usize,
                    core_cb.cs.num_structural_witin as usize,
                    &steps,
                    &indices
                )
                .is_err(),
                "tamper index {index} must fail"
            );
        }
    }
}
