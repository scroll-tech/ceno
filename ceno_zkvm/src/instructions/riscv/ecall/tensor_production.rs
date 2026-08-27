//! Development-only production-width MatMul split chips.
//!
//! These chips prove ordered raw-hint reads and exact arithmetic. They do not
//! authenticate weights to the descriptor's model root; that relation is
//! intentionally deferred to CommittedHintsMerkleV1.

use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use itertools::Itertools;
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
        TENSOR_STATE_PHASE_OUTPUT, TensorProductionFinalizeCoreConfig,
        TensorProductionTileCoreConfig, TensorSignedWord, production_raw_state_record,
        production_tile_input_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC: usize = 16;
const ROOT: usize = 8;
const PROFILE: usize = 1;
const SIGNATURE: usize = 3;
const INPUT_PTR: usize = 4;
const OUTPUT_PTR: usize = 5;
const TENSOR_ID: usize = 6;
const FIRST_TILE: usize = 7;
const ROOT_PTR: usize = 10;

fn production_tile_bounds<const K: usize>(
    position: usize,
) -> Result<(usize, usize, usize), ZKVMError> {
    let tile = ceno_emul::tensor::production::PRODUCTION_K_TILE;
    let start = position
        .checked_mul(tile)
        .ok_or_else(|| ZKVMError::InvalidWitness("production tile offset overflow".into()))?;
    if start >= K {
        return Err(ZKVMError::InvalidWitness(
            "production tile position outside logical K".into(),
        ));
    }
    let end = start.saturating_add(tile).min(K);
    Ok((start, end, tile - (end - start)))
}

fn production_tile_positions(
    signature: ceno_emul::tensor::production::ProductionMatMulSignature,
) -> std::ops::Range<usize> {
    0..signature.atomic_tiles() as usize
}

pub struct TensorProductionEcallConfig<E: ExtensionField, const K: usize> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: Vec<MemoryExpr<E>>,
    signed_output: TensorSignedWord<E>,
    output_carry: WitIn,
    mem_rw: Vec<WriteMEM>,
}

pub struct TensorProductionEcallInstruction<E, const K: usize, const CODE: u32>(PhantomData<E>);
pub struct TensorProductionTileInstruction<E>(PhantomData<E>);
pub struct TensorProductionFinalizeInstruction<
    E,
    const K: usize,
    const CODE: u32,
    const TILES: usize,
>(PhantomData<E>);

pub type TensorMatMulHiddenEcallInstruction<E> =
    TensorProductionEcallInstruction<E, 4096, { ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1 }>;
pub type TensorMatMulIntermediateEcallInstruction<E> = TensorProductionEcallInstruction<
    E,
    11008,
    { ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1 },
>;
pub type TensorMatMulHiddenFinalizeInstruction<E> =
    TensorProductionFinalizeInstruction<E, 4096, { ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1 }, 4>;
pub type TensorMatMulIntermediateFinalizeInstruction<E> = TensorProductionFinalizeInstruction<
    E,
    11008,
    { ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1 },
    11,
>;

fn memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}
fn word<E: ExtensionField>(value: &MemoryExpr<E>) -> Expression<E> {
    value[0].clone() + value[1].clone() * (1u64 << 16)
}
fn assign_memory<E: ExtensionField>(instance: &mut [E::BaseField], expr: &MemoryExpr<E>, v: u32) {
    for (expr, limb) in expr.iter().zip(Value::new_unchecked(v).as_u16_limbs()) {
        let Expression::WitIn(wit) = expr else {
            panic!("memory limb")
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

impl<E: ExtensionField, const K: usize, const CODE: u32> Instruction<E>
    for TensorProductionEcallInstruction<E, K, CODE>
{
    type InstructionConfig = TensorProductionEcallConfig<E, K>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        format!("TensorProductionRawEcallK{K}")
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![CODE & LIMB_MASK, (CODE >> LIMB_BITS) & LIMB_MASK])
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
        let words = (0..DESC + K + ROOT + 1)
            .map(|i| memory_expr(cb, &format!("production_word_{i}")))
            .collect::<Vec<_>>();
        let signature = if K == 4096 {
            ceno_emul::tensor::production::PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1
        } else if K == 11008 {
            ceno_emul::tensor::production::PRODUCTION_MATMUL_INTERMEDIATE_SIGNATURE_V1
        } else {
            return Err(ZKVMError::InvalidWitness("unsupported production K".into()));
        };
        let tiles = K.div_ceil(ceno_emul::tensor::production::PRODUCTION_K_TILE) as u32;
        for (index, expected) in [
            (0, ceno_emul::tensor::TENSOR_ABI_V1),
            (
                1,
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            ),
            (
                2,
                ceno_emul::tensor::production::ZKLLM_FIXED_V1_QUANTIZATION,
            ),
            (3, signature),
            (8, tiles),
            (9, 16),
            (11, 1),
            (12, 1),
            (13, 0),
            (14, 0),
            (15, 0),
        ] {
            cb.require_equal(
                || format!("production_desc_{index}"),
                word(&words[index]),
                E::BaseField::from_u32(expected).expr(),
            )?;
        }
        let signed_output = TensorSignedWord::construct(cb, "production_ecall_output", 32)?;
        let output_carry = cb.create_witin(|| "production_output_neg_carry");
        cb.assert_bit(|| "production output carry bit", output_carry.expr())?;
        let output_mem = &words[DESC + K + ROOT];
        let positive = E::BaseField::ONE.expr() - signed_output.sign.expr();
        cb.require_zero(
            || "production output positive lo",
            positive.clone() * (output_mem[0].clone() - signed_output.magnitude[0].expr()),
        )?;
        cb.require_zero(
            || "production output positive hi",
            positive * (output_mem[1].clone() - signed_output.magnitude[1].expr()),
        )?;
        cb.require_zero(
            || "production output negative lo",
            signed_output.sign.expr()
                * (output_mem[0].clone() + signed_output.magnitude[0].expr()
                    - output_carry.expr() * (1u64 << 16)),
        )?;
        cb.require_zero(
            || "production output negative hi",
            signed_output.sign.expr()
                * (output_mem[1].clone() + signed_output.magnitude[1].expr() + output_carry.expr()
                    - (1u64 << 16)),
        )?;
        for position in 0..tiles as usize {
            let (logical_start, logical_end, padding) = production_tile_bounds::<K>(position)?;
            let start = DESC + logical_start;
            let end = DESC + logical_end;
            cb.write_record(
                || format!("production tile input {position}"),
                RAMType::Custom,
                production_tile_input_record(
                    vm_state.ts.expr(),
                    ptr.expr_unaligned(),
                    word(&words[PROFILE]),
                    word(&words[SIGNATURE]),
                    word(&words[TENSOR_ID]),
                    word(&words[FIRST_TILE]),
                    word(&words[FIRST_TILE]) + E::BaseField::from_usize(position).expr(),
                    E::BaseField::from_usize(position).expr(),
                    words[start..end]
                        .iter()
                        .flat_map(|mem| mem.iter().cloned())
                        .chain(std::iter::repeat_n(E::BaseField::ZERO.expr(), padding * 2)),
                ),
            )?;
        }
        let output_record = production_raw_state_record(
            vm_state.ts.expr(),
            ptr.expr_unaligned(),
            TENSOR_STATE_PHASE_OUTPUT,
            word(&words[PROFILE]),
            word(&words[SIGNATURE]),
            word(&words[TENSOR_ID]),
            word(&words[FIRST_TILE]),
            std::iter::empty(),
            signed_output.expr(),
        );
        cb.read_record(
            || "production_raw_state_out",
            RAMType::Custom,
            output_record,
        )?;
        let bases = [
            ptr.expr_unaligned(),
            word(&words[INPUT_PTR]),
            word(&words[ROOT_PTR]),
            word(&words[OUTPUT_PTR]),
        ];
        let mem_rw = words
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let (base, off, before, after) = if i < DESC {
                    (bases[0].clone(), i, value.clone(), value.clone())
                } else if i < DESC + K {
                    (bases[1].clone(), i - DESC, value.clone(), value.clone())
                } else if i < DESC + K + ROOT {
                    (bases[2].clone(), i - DESC - K, value.clone(), value.clone())
                } else {
                    (
                        bases[3].clone(),
                        0,
                        array::from_fn(|_| E::BaseField::ZERO.expr()),
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
        Ok(TensorProductionEcallConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            words,
            signed_output,
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
                .ok_or_else(|| ZKVMError::InvalidWitness("production syscall missing".into()))?;
            if ops.mem_ops.len() != DESC + K + ROOT + 1 {
                return Err(ZKVMError::InvalidWitness(
                    "production syscall memory count".into(),
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
                    Change::new(CODE, CODE),
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
                let raw = if i == DESC + K + ROOT {
                    op.value.after
                } else {
                    op.value.before
                };
                assign_memory(instance, &config.words[i], raw);
                writer.assign_op(
                    instance,
                    shard_ctx,
                    &mut lkm,
                    step.cycle(),
                    op,
                    ops.mem_future_access[i] != 0,
                )?;
            }
            let output = ops.mem_ops[DESC + K + ROOT].value.after as i32;
            config.signed_output.assign(instance, &mut lkm, output);
            set_val!(
                instance,
                config.output_carry,
                u64::from((output.unsigned_abs() & 0xffff) != 0)
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
            .ok_or_else(|| ZKVMError::InvalidWitness("production syscall missing".into()))?;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            CODE,
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

impl<E: ExtensionField> Instruction<E> for TensorProductionTileInstruction<E> {
    type InstructionConfig = TensorProductionTileCoreConfig<E>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        "TensorProductionTileK1024".into()
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        TensorProductionTileCoreConfig::construct(cb)
    }
    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("production tiles expand one logical ecall into multiple rows")
    }
    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let mut work = Vec::new();
        for &index in indices {
            let step = &steps[index];
            let ops = step
                .syscall(&shard_ctx.syscall_witnesses)
                .ok_or_else(|| ZKVMError::InvalidWitness("production syscall missing".into()))?;
            let signature = ceno_emul::tensor::production::ProductionMatMulSignature::from_id(
                ops.mem_ops
                    .get(SIGNATURE)
                    .ok_or_else(|| {
                        ZKVMError::InvalidWitness("production descriptor missing".into())
                    })?
                    .value
                    .before,
            )
            .ok_or_else(|| ZKVMError::InvalidWitness("production signature invalid".into()))?;
            for position in production_tile_positions(signature) {
                work.push((index, position));
            }
        }
        let mut lkm = LkMultiplicity::default();
        let mut wit = RowMajorMatrix::new(work.len(), num_witin, InstancePaddingStrategy::Default);
        let mut structural = RowMajorMatrix::new(
            work.len(),
            num_structural_witin.max(1),
            InstancePaddingStrategy::Default,
        );
        for ((instance, structural), &(index, position)) in
            wit.iter_mut().zip(structural.iter_mut()).zip(&work)
        {
            *structural.last_mut().unwrap() = E::BaseField::ONE;
            let step = &steps[index];
            let ops = step.syscall(&shard_ctx.syscall_witnesses).unwrap();
            let guest = ceno_emul::tensor::TensorProductionMatMulDescV1 {
                abi_version: ops.mem_ops[0].value.before,
                commitment_profile: ops.mem_ops[1].value.before,
                quantization_id: ops.mem_ops[2].value.before,
                signature_id: ops.mem_ops[3].value.before,
                input_ptr: ops.mem_ops[4].value.before,
                output_ptr: ops.mem_ops[5].value.before,
                weight_tensor_id: ops.mem_ops[6].value.before,
                first_weight_tile: ops.mem_ops[7].value.before,
                weight_tile_count: ops.mem_ops[8].value.before,
                rescale_shift: ops.mem_ops[9].value.before,
                model_root_ptr: ops.mem_ops[10].value.before,
                input_stride: ops.mem_ops[11].value.before,
                output_stride: ops.mem_ops[12].value.before,
                reserved: [
                    ops.mem_ops[13].value.before,
                    ops.mem_ops[14].value.before,
                    ops.mem_ops[15].value.before,
                ],
            };
            let desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::from_guest(&guest)
                .map_err(|e| ZKVMError::InvalidWitness(e.to_string().into_boxed_str()))?;
            let k = desc.signature.k();
            if ops.mem_ops.len() != DESC + k + ROOT + 1 {
                return Err(ZKVMError::InvalidWitness(
                    "production syscall memory count".into(),
                ));
            }
            let input = ops.mem_ops[DESC..DESC + k]
                .iter()
                .map(|op| op.value.before as i32)
                .collect_vec();
            let start = position * ceno_emul::tensor::production::PRODUCTION_K_TILE;
            let end = (start + ceno_emul::tensor::production::PRODUCTION_K_TILE).min(k);
            let mut tile_input = input[start..end].to_vec();
            tile_input.resize(ceno_emul::tensor::production::PRODUCTION_K_TILE, 0);
            config
                .assign(
                    instance,
                    &mut lkm,
                    shard_ctx
                        .tensor_proof_context
                        .as_ref()
                        .map(|ctx| ctx.provider()),
                    desc,
                    position,
                    step.cycle() - shard_ctx.current_shard_offset_cycle(),
                    ops.reg_ops[0].value.after,
                    &tile_input,
                )
                .map_err(|e| ZKVMError::InvalidWitness(e.into_boxed_str()))?;
        }
        wit.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([wit, structural], lkm.into_finalize_result()))
    }
}

impl<E: ExtensionField, const K: usize, const CODE: u32, const TILES: usize> Instruction<E>
    for TensorProductionFinalizeInstruction<E, K, CODE, TILES>
{
    type InstructionConfig = TensorProductionFinalizeCoreConfig<E, TILES>;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        format!("TensorProductionFinalizeK{K}")
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        TensorProductionFinalizeCoreConfig::construct(cb, 16)
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
            .ok_or_else(|| ZKVMError::InvalidWitness("production syscall missing".into()))?;
        if ops.mem_ops.len() != DESC + K + ROOT + 1 {
            return Err(ZKVMError::InvalidWitness(
                "production syscall memory count".into(),
            ));
        }
        let guest = ceno_emul::tensor::TensorProductionMatMulDescV1 {
            abi_version: ops.mem_ops[0].value.before,
            commitment_profile: ops.mem_ops[1].value.before,
            quantization_id: ops.mem_ops[2].value.before,
            signature_id: ops.mem_ops[3].value.before,
            input_ptr: ops.mem_ops[4].value.before,
            output_ptr: ops.mem_ops[5].value.before,
            weight_tensor_id: ops.mem_ops[6].value.before,
            first_weight_tile: ops.mem_ops[7].value.before,
            weight_tile_count: ops.mem_ops[8].value.before,
            rescale_shift: ops.mem_ops[9].value.before,
            model_root_ptr: ops.mem_ops[10].value.before,
            input_stride: ops.mem_ops[11].value.before,
            output_stride: ops.mem_ops[12].value.before,
            reserved: [
                ops.mem_ops[13].value.before,
                ops.mem_ops[14].value.before,
                ops.mem_ops[15].value.before,
            ],
        };
        let desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::from_guest(&guest)
            .map_err(|e| ZKVMError::InvalidWitness(e.to_string().into_boxed_str()))?;
        let input = ops.mem_ops[DESC..DESC + K]
            .iter()
            .map(|op| op.value.before as i32)
            .collect_vec();
        let provider = shard_ctx
            .tensor_proof_context
            .as_ref()
            .map(|ctx| ctx.provider());
        let (output, _) = config
            .assign(
                instance,
                lkm,
                provider,
                desc,
                step.cycle() - shard_ctx.current_shard_offset_cycle(),
                ops.reg_ops[0].value.after,
                &input,
            )
            .map_err(|e| ZKVMError::InvalidWitness(e.into_boxed_str()))?;
        if ops.mem_ops[DESC + K + ROOT].value.after as i32 != output {
            return Err(ZKVMError::InvalidWitness(
                "production journal output mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{production_tile_bounds, production_tile_positions};

    #[test]
    fn k11008_last_tile_is_768_words_plus_deterministic_zero_padding() {
        let tile = ceno_emul::tensor::production::PRODUCTION_K_TILE;
        for position in 0..10 {
            assert_eq!(
                production_tile_bounds::<11008>(position).unwrap(),
                (position * tile, (position + 1) * tile, 0)
            );
        }
        assert_eq!(
            production_tile_bounds::<11008>(10).unwrap(),
            (10_240, 11_008, 256)
        );
        assert!(production_tile_bounds::<11008>(11).is_err());
        assert_eq!(production_tile_bounds::<4096>(3).unwrap(), (3072, 4096, 0));
        assert!(production_tile_bounds::<4096>(4).is_err());
    }

    #[test]
    fn dynamic_tile_schema_expands_hidden_and_intermediate_rows() {
        use ceno_emul::tensor::production::ProductionMatMulSignature;

        assert_eq!(
            production_tile_positions(ProductionMatMulSignature::HiddenK4096).count(),
            4
        );
        assert_eq!(
            production_tile_positions(ProductionMatMulSignature::IntermediateK11008).count(),
            11
        );
    }
}
