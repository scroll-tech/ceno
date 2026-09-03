use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorMatMulV1Spec, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr};
use p3::field::{Field, PrimeCharacteristicRing};
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
        TENSOR_GATE2_OUTPUTS, TENSOR_STATE_PHASE_INPUT, TENSOR_STATE_PHASE_OUTPUT,
        TensorMatMulCoreConfig, TensorSignedWord, TensorStateRecord, assign_gate2_core_witness,
        tensor_state_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC: usize = 16;
const INPUTS: usize = 6;
const ROOT: usize = 8;
const OUTPUTS: usize = 4;
const PROFILE: usize = 1;
const SIGNATURE: usize = 2;
const INPUT_PTR: usize = 4;
const OUTPUT_PTR: usize = 5;
const TENSOR_ID: usize = 11;
const TILE_ID: usize = 12;

#[derive(Debug)]
pub struct TensorMatMulEcallConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: [MemoryExpr<E>; DESC + INPUTS + ROOT + OUTPUTS],
    signed_inputs: [TensorSignedWord<E>; INPUTS],
    signed_outputs: [TensorSignedWord<E>; OUTPUTS],
    input_carries: [multilinear_extensions::WitIn; INPUTS],
    output_carries: [multilinear_extensions::WitIn; OUTPUTS],
    commitment_delta_hi: [multilinear_extensions::WitIn; ROOT],
    commitment_delta_zero: [multilinear_extensions::WitIn; ROOT],
    commitment_delta_inverse: [multilinear_extensions::WitIn; ROOT],
    mem_rw: Vec<WriteMEM>,
}

pub struct TensorMatMulEcallInstruction<E>(PhantomData<E>);
pub struct TensorMatMulCoreInstruction<E>(PhantomData<E>);

fn memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}

fn word<E: ExtensionField>(value: &MemoryExpr<E>) -> Expression<E> {
    value[0].clone() + value[1].clone() * (1u64 << 16)
}

fn assign_memory<E: ExtensionField>(instance: &mut [E::BaseField], expr: &MemoryExpr<E>, v: u32) {
    let value = Value::new_unchecked(v);
    let limbs = value.as_u16_limbs();
    for (expr, limb) in expr.iter().zip(limbs) {
        let Expression::WitIn(wit) = expr else {
            panic!("tensor memory limb is not witness")
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

fn assign_signed<E: ExtensionField>(
    signed: &TensorSignedWord<E>,
    carry_column: multilinear_extensions::WitIn,
    instance: &mut [E::BaseField],
    lkm: &mut LkMultiplicity,
    raw: u32,
) {
    let value = raw as i32;
    signed.assign(instance, lkm, value);
    let magnitude = i64::from(value).unsigned_abs();
    let carry = u64::from((magnitude & 0xffff) != 0);
    // carry is allocated immediately after the signed word's inverse.
    set_val!(instance, carry_column, carry);
}

impl<E: ExtensionField> Instruction<E> for TensorMatMulEcallInstruction<E> {
    type InstructionConfig = TensorMatMulEcallConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorMatMulEcall".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                TensorMatMulV1Spec::CODE & LIMB_MASK,
                (TensorMatMulV1Spec::CODE >> LIMB_BITS) & LIMB_MASK,
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

        let words = array::from_fn(|i| memory_expr(cb, &format!("tensor_word_{i}")));
        for (index, expected) in [
            (0, ceno_emul::tensor::TENSOR_ABI_V1),
            (1, ceno_emul::tensor::GATE2_LINEAR_COMMITMENT_V1),
            (2, ceno_emul::TENSOR_SIGNATURE_2X3X2),
            (3, ceno_emul::tensor::ZKLLM_FIXED_V1),
            (6, 2),
            (7, 3),
            (8, 2),
            (9, 3),
            (10, 2),
            (14, 0),
            (15, 0),
        ] {
            cb.require_equal(
                || format!("tensor_desc_{index}"),
                word(&words[index]),
                E::BaseField::from_u32(expected).expr(),
            )?;
        }

        let input_pairs = (0..INPUTS)
            .map(|i| {
                let signed =
                    TensorSignedWord::construct(cb, &format!("tensor_ecall_input_{i}"), 9)?;
                let carry = bind_twos_complement(
                    cb,
                    &format!("tensor_ecall_input_{i}"),
                    &words[DESC + i],
                    &signed,
                )?;
                Ok::<_, ZKVMError>((signed, carry))
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        let (signed_inputs, input_carries): (Vec<_>, Vec<_>) = input_pairs.into_iter().unzip();
        let signed_inputs: [TensorSignedWord<E>; INPUTS] =
            signed_inputs.try_into().expect("six inputs");
        let input_carries: [_; INPUTS] = input_carries.try_into().expect("six input carries");
        let output_pairs = (0..OUTPUTS)
            .map(|i| {
                let signed =
                    TensorSignedWord::construct(cb, &format!("tensor_ecall_output_{i}"), 16)?;
                let carry = bind_twos_complement(
                    cb,
                    &format!("tensor_ecall_output_{i}"),
                    &words[DESC + INPUTS + ROOT + i],
                    &signed,
                )?;
                Ok::<_, ZKVMError>((signed, carry))
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        let (signed_outputs, output_carries): (Vec<_>, Vec<_>) = output_pairs.into_iter().unzip();
        let signed_outputs: [TensorSignedWord<E>; OUTPUTS] =
            signed_outputs.try_into().expect("four outputs");
        let output_carries: [_; OUTPUTS] = output_carries.try_into().expect("four output carries");
        let commitment = array::from_fn(|i| word(&words[DESC + INPUTS + i]));
        let mut commitment_delta_hi = Vec::with_capacity(ROOT);
        let mut commitment_delta_zero = Vec::with_capacity(ROOT);
        let mut commitment_delta_inverse = Vec::with_capacity(ROOT);
        for i in 0..ROOT {
            let delta = cb.create_witin(|| format!("tensor_commitment_{i}_delta_hi"));
            let zero = cb.create_witin(|| format!("tensor_commitment_{i}_delta_zero"));
            let inverse = cb.create_witin(|| format!("tensor_commitment_{i}_delta_inverse"));
            cb.assert_const_range(
                || format!("tensor_commitment_{i}_delta_range"),
                delta.expr(),
                15,
            )?;
            cb.assert_bit(
                || format!("tensor_commitment_{i}_delta_zero_bit"),
                zero.expr(),
            )?;
            cb.require_equal(
                || format!("tensor_commitment_{i}_high_bound"),
                words[DESC + INPUTS + i][1].clone() + delta.expr(),
                E::BaseField::from_u32(30_720).expr(),
            )?;
            cb.require_zero(
                || format!("tensor_commitment_{i}_delta_zero_product"),
                delta.expr() * zero.expr(),
            )?;
            cb.require_zero(
                || format!("tensor_commitment_{i}_delta_inverse_or_zero"),
                delta.expr() * inverse.expr() - (E::BaseField::ONE.expr() - zero.expr()),
            )?;
            cb.require_zero(
                || format!("tensor_commitment_{i}_modulus_edge"),
                zero.expr() * words[DESC + INPUTS + i][0].clone(),
            )?;
            commitment_delta_hi.push(delta);
            commitment_delta_zero.push(zero);
            commitment_delta_inverse.push(inverse);
        }
        let zeros4 = || array::from_fn(|_| E::BaseField::ZERO.expr());
        let record = |phase, outputs| {
            tensor_state_record(TensorStateRecord {
                cycle: vm_state.ts.expr(),
                call_id: ptr.expr_unaligned(),
                phase,
                profile: word(&words[PROFILE]),
                signature_id: word(&words[SIGNATURE]),
                tensor_id: word(&words[TENSOR_ID]),
                tile_id: word(&words[TILE_ID]),
                values: array::from_fn(|i| signed_inputs[i].expr()),
                commitment: commitment.clone(),
                outputs,
                remainders: zeros4(),
            })
        };
        cb.write_record(
            || "tensor_state_in",
            RAMType::Custom,
            record(TENSOR_STATE_PHASE_INPUT, zeros4()),
        )?;
        cb.read_record(
            || "tensor_state_out",
            RAMType::Custom,
            record(
                TENSOR_STATE_PHASE_OUTPUT,
                array::from_fn(|i| signed_outputs[i].expr()),
            ),
        )?;

        let base_desc = ptr.expr_unaligned();
        let input_base = word(&words[INPUT_PTR]);
        let root_base = word(&words[13]);
        let output_base = word(&words[OUTPUT_PTR]);
        let mem_rw = words
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let (base, off, before, after) = if i < DESC {
                    (base_desc.clone(), i, value.clone(), value.clone())
                } else if i < DESC + INPUTS {
                    (input_base.clone(), i - DESC, value.clone(), value.clone())
                } else if i < DESC + INPUTS + ROOT {
                    (
                        root_base.clone(),
                        i - DESC - INPUTS,
                        value.clone(),
                        value.clone(),
                    )
                } else {
                    let z = array::from_fn(|_| E::BaseField::ZERO.expr());
                    (
                        output_base.clone(),
                        i - DESC - INPUTS - ROOT,
                        z,
                        value.clone(),
                    )
                };
                WriteMEM::construct_circuit(
                    cb,
                    base + E::BaseField::from_u32(ByteAddr::from((off * WORD_SIZE) as u32).0)
                        .expr(),
                    before,
                    after,
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TensorMatMulEcallConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            words,
            signed_inputs,
            signed_outputs,
            input_carries,
            output_carries,
            commitment_delta_hi: commitment_delta_hi
                .try_into()
                .expect("eight commitment deltas"),
            commitment_delta_zero: commitment_delta_zero
                .try_into()
                .expect("eight commitment zero flags"),
            commitment_delta_inverse: commitment_delta_inverse
                .try_into()
                .expect("eight commitment inverses"),
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
                .ok_or_else(|| ZKVMError::InvalidWitness("tensor syscall missing".into()))?;
            if ops.mem_ops.len() != DESC + INPUTS + ROOT + OUTPUTS {
                return Err(ZKVMError::InvalidWitness(
                    "tensor syscall memory count".into(),
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
                    Change::new(TensorMatMulV1Spec::CODE, TensorMatMulV1Spec::CODE),
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
                let raw = if i >= DESC + INPUTS + ROOT {
                    op.value.after
                } else {
                    op.value.before
                };
                assign_memory::<E>(instance, &config.words[i], raw);
                writer.assign_op(
                    instance,
                    shard_ctx,
                    &mut lkm,
                    step.cycle(),
                    op,
                    ops.mem_future_access[i] != 0,
                )?;
            }
            for ((cfg, carry), op) in config
                .signed_inputs
                .iter()
                .zip(config.input_carries)
                .zip(&ops.mem_ops[DESC..DESC + INPUTS])
            {
                assign_signed(cfg, carry, instance, &mut lkm, op.value.before);
            }
            for ((cfg, carry), op) in config
                .signed_outputs
                .iter()
                .zip(config.output_carries)
                .zip(&ops.mem_ops[DESC + INPUTS + ROOT..])
            {
                assign_signed(cfg, carry, instance, &mut lkm, op.value.after);
            }
            for i in 0..ROOT {
                let raw = ops.mem_ops[DESC + INPUTS + i].value.before;
                if raw >= 2_013_265_921 {
                    return Err(ZKVMError::InvalidWitness(
                        "non-canonical tensor commitment word".into(),
                    ));
                }
                let high = (raw >> 16) as u64;
                let delta = 30_720 - high;
                let zero = u64::from(delta == 0);
                set_val!(instance, config.commitment_delta_hi[i], delta);
                set_val!(instance, config.commitment_delta_zero[i], zero);
                set_val!(
                    instance,
                    config.commitment_delta_inverse[i],
                    E::BaseField::from_u64(delta)
                        .try_inverse()
                        .unwrap_or(E::BaseField::ZERO)
                );
                lkm.assert_const_range(delta, 15);
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
            .ok_or_else(|| ZKVMError::InvalidWitness("tensor syscall missing".into()))?;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            TensorMatMulV1Spec::CODE,
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

impl<E: ExtensionField> Instruction<E> for TensorMatMulCoreInstruction<E> {
    type InstructionConfig = TensorMatMulCoreConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorMatMulCore".into()
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        TensorMatMulCoreConfig::construct(cb)
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
            .ok_or_else(|| ZKVMError::InvalidWitness("tensor syscall missing".into()))?;
        let desc = &ops.mem_ops[..DESC];
        let input: [i32; INPUTS] = ops.mem_ops[DESC..DESC + INPUTS]
            .iter()
            .map(|op| op.value.before as i32)
            .collect_vec()
            .try_into()
            .unwrap();
        let commitment: [u32; ROOT] = ops.mem_ops[DESC + INPUTS..DESC + INPUTS + ROOT]
            .iter()
            .map(|op| op.value.before)
            .collect_vec()
            .try_into()
            .unwrap();
        let provider = shard_ctx
            .tensor_proof_context
            .as_ref()
            .map(|ctx| ctx.provider());
        let witness = assign_gate2_core_witness(
            provider,
            desc[PROFILE].value.before,
            desc[TENSOR_ID].value.before,
            desc[TILE_ID].value.before,
            &commitment,
            &input,
        )
        .map_err(|e| ZKVMError::InvalidWitness(e.into_boxed_str()))?;
        set_val!(
            instance,
            config.cycle,
            step.cycle() - shard_ctx.current_shard_offset_cycle()
        );
        set_val!(instance, config.call_id, ops.reg_ops[0].value.after as u64);
        set_val!(instance, config.profile, desc[PROFILE].value.before as u64);
        set_val!(
            instance,
            config.signature_id,
            desc[SIGNATURE].value.before as u64
        );
        set_val!(
            instance,
            config.tensor_id,
            desc[TENSOR_ID].value.before as u64
        );
        set_val!(instance, config.tile_id, desc[TILE_ID].value.before as u64);
        lkm.assert_const_range(desc[TENSOR_ID].value.before as u64, 16);
        lkm.assert_const_range(desc[TILE_ID].value.before as u64, 16);
        config
            .air
            .assign(instance, lkm, &input, &witness)
            .map_err(|error| ZKVMError::InvalidWitness(error.into_boxed_str()))?;
        let journal_output: [i32; TENSOR_GATE2_OUTPUTS] = ops.mem_ops[DESC + INPUTS + ROOT..]
            .iter()
            .map(|op| op.value.after as i32)
            .collect_vec()
            .try_into()
            .unwrap();
        if journal_output != witness.outputs {
            return Err(ZKVMError::InvalidWitness(
                "tensor journal output mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_builder::ConstraintSystem, e2e::TensorProofContext};
    use ceno_emul::tensor::{DeterministicTileProvider, encode_i32_le};
    use ff_ext::{BabyBearExt4, FieldFrom};
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
        let challenges = [E::from_v(7), E::from_v(11)];
        eval_by_expr_with_instance::<E>(&[], &wit, &structural, &[], &challenges, expr)
            .unwrap_right()
    }

    #[test]
    fn split_records_match_and_missing_context_fails_closed() {
        let (step, _, syscall_witnesses) = ceno_emul::test_utils::tensor_matmul_step();
        let steps = vec![step];
        let indices = vec![0];
        let mut ecall_cs = ConstraintSystem::<E>::new(|| "tensor_ecall");
        let mut ecall_cb = CircuitBuilder::new(&mut ecall_cs);
        let (ecall_config, _) = TensorMatMulEcallInstruction::<E>::build_gkr_iop_circuit(
            &mut ecall_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let mut core_cs = ConstraintSystem::<E>::new(|| "tensor_core");
        let mut core_cb = CircuitBuilder::new(&mut core_cs);
        let (core_config, _) = TensorMatMulCoreInstruction::<E>::build_gkr_iop_circuit(
            &mut core_cb,
            &ProgramParams::default(),
        )
        .unwrap();

        let mut missing = ShardContext::default();
        missing.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let err = TensorMatMulCoreInstruction::<E>::assign_instances(
            &core_config,
            &mut missing,
            core_cb.cs.num_witin as usize,
            core_cb.cs.num_structural_witin as usize,
            &steps,
            &indices,
        )
        .err()
        .expect("missing context must fail");
        assert!(matches!(err, ZKVMError::InvalidWitness(_)));

        let weights = [65_536, 0, 0, 65_536, 65_536, 65_536];
        let provider =
            Arc::new(DeterministicTileProvider::new(41, vec![encode_i32_le(&weights)]).unwrap());
        let mut ecall_ctx = ShardContext::default();
        ecall_ctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (ecall_rmms, _) = TensorMatMulEcallInstruction::<E>::assign_instances(
            &ecall_config,
            &mut ecall_ctx,
            ecall_cb.cs.num_witin as usize,
            ecall_cb.cs.num_structural_witin as usize,
            &steps,
            &indices,
        )
        .unwrap();
        let mut core_ctx = ShardContext::default();
        core_ctx.syscall_witnesses = Arc::new(syscall_witnesses);
        core_ctx.tensor_proof_context = Some(Arc::new(TensorProofContext::new(provider)));
        let (core_rmms, core_lkm) = TensorMatMulCoreInstruction::<E>::assign_instances(
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
            .position(|n| n.contains("tensor_state_in"))
            .unwrap();
        let e_out = ecall_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_state_out"))
            .unwrap();
        let c_in = core_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_state_in"))
            .unwrap();
        let c_out = core_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|n| n.contains("tensor_state_out"))
            .unwrap();
        assert_eq!(
            eval(&ecall_cb.cs.w_expressions[e_in], ew, es),
            eval(&core_cb.cs.r_expressions[c_in], cw, cs)
        );
        assert_eq!(
            eval(&ecall_cb.cs.r_expressions[e_out], ew, es),
            eval(&core_cb.cs.w_expressions[c_out], cw, cs)
        );
        let _ = core_lkm;

        let mut bad_witnesses = (*core_ctx.syscall_witnesses).clone();
        let tensor_syscall = bad_witnesses.first_mut().expect("tensor syscall witness");
        tensor_syscall.mem_ops[DESC + INPUTS + ROOT].value.after ^= 1;
        let mut bad_ctx = ShardContext::default();
        bad_ctx.syscall_witnesses = Arc::new(bad_witnesses);
        bad_ctx.tensor_proof_context = core_ctx.tensor_proof_context.clone();
        assert!(
            TensorMatMulCoreInstruction::<E>::assign_instances(
                &core_config,
                &mut bad_ctx,
                core_cb.cs.num_witin as usize,
                core_cb.cs.num_structural_witin as usize,
                &steps,
                &indices,
            )
            .is_err(),
            "tampered guest output must fail core assignment"
        );
    }
}
