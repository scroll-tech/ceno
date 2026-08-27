//! Split AIR for Gate-4's statically registered reduced fused blocks.
//!
//! The syscall chip owns guest memory. The core owns authenticated private
//! tiles and the arithmetic relation. Their only connection is the ordered
//! custom-RAM record below, matching the existing tensor split design.

use std::{array, marker::PhantomData};

use ceno_emul::{
    BLOCK_REDUCED_PROFILE_V1, ByteAddr, Change, FullTracer, InsnKind, Platform, StepIndex,
    StepRecord, SyscallSpec, TENSOR_SIGNATURE_2X3X2, TensorAttentionBlockReducedV1Spec,
    TensorFfnBlockReducedV1Spec, WORD_SIZE, WriteOp, tensor::GATE2_LINEAR_COMMITMENT_V1,
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
        BLOCK_STATE_PHASE_INPUT, BLOCK_STATE_PHASE_OUTPUT, TensorGate2AirConfig,
        assign_gate2_core_witness, tensor_block_state_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::{LkMultiplicity, set_val},
};

const DESC_WORDS: usize = 32;
const VALUE_WORDS: usize = 4;
const ATTN_ROOT_WORDS: usize = 32;
const FFN_ROOT_WORDS: usize = 24;
const ATTN_TOTAL: usize = 72;
const FFN_TOTAL: usize = 64;
const REGISTERED_TENSOR_ID: u32 = 73;

fn memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: &str) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}
fn word<E: ExtensionField>(v: &MemoryExpr<E>) -> Expression<E> {
    v[0].clone() + v[1].clone() * (1u64 << 16)
}
fn flatten<E: ExtensionField>(words: &[MemoryExpr<E>]) -> Vec<Expression<E>> {
    words.iter().flat_map(|x| x.iter().cloned()).collect()
}
fn assign_memory<E: ExtensionField>(instance: &mut [E::BaseField], expr: &MemoryExpr<E>, v: u32) {
    let value = Value::new_unchecked(v);
    for (expr, limb) in expr.iter().zip(value.as_u16_limbs()) {
        let Expression::WitIn(wit) = expr else {
            panic!("block memory limb is not witness")
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

trait BlockSpec: Send + Sync + 'static {
    type Syscall: SyscallSpec;
    const NAME: &'static str;
    const CORE_NAME: &'static str;
    const TOTAL: usize;
    const ROOT_WORDS: usize;
    const TILE_START: u32;
    const TILES: usize;
    fn registered_words() -> Vec<u32>;
    fn tile_inputs(tile: usize) -> [i32; 6];
    fn final_output() -> [i32; 4];
}

struct AttentionBlock;
struct FfnBlock;

fn descriptor(table: u32, commitment: [u32; 8]) -> [u32; DESC_WORDS] {
    let mut d = [0; DESC_WORDS];
    d[0] = ceno_emul::tensor::TENSOR_ABI_V1;
    d[1] = BLOCK_REDUCED_PROFILE_V1;
    d[2] = TENSOR_SIGNATURE_2X3X2;
    d[3] = ceno_emul::tensor::ZKLLM_FIXED_V1;
    d[7] = REGISTERED_TENSOR_ID;
    d[8] = table;
    d[9..17].copy_from_slice(&commitment);
    d
}

impl BlockSpec for AttentionBlock {
    type Syscall = TensorAttentionBlockReducedV1Spec;
    const NAME: &'static str = "TensorAttentionBlockReducedEcall";
    const CORE_NAME: &'static str = "TensorAttentionBlockReducedCore";
    const TOTAL: usize = ATTN_TOTAL;
    const ROOT_WORDS: usize = ATTN_ROOT_WORDS;
    const TILE_START: u32 = 0;
    const TILES: usize = 4;
    fn registered_words() -> Vec<u32> {
        let mut w = descriptor(
            ceno_emul::ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
            ceno_emul::ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1,
        )
        .to_vec();
        w.extend([1i32, -2, 3, -4].map(|x| x as u32));
        let weights = [65_536, 0, 0, 65_536, 0, 0];
        for tile in 0..4 {
            w.extend(ceno_emul::tensor::gate2_linear_commitment_v1(
                REGISTERED_TENSOR_ID,
                tile,
                &weights,
            ));
        }
        w.extend([2i32, -4, 7, -10].map(|x| x as u32));
        w
    }
    fn tile_inputs(tile: usize) -> [i32; 6] {
        if tile < 3 {
            [1, -2, 0, 3, -4, 0]
        } else {
            [1, -2, 0, 4, -6, 0]
        }
    }
    fn final_output() -> [i32; 4] {
        [2, -4, 7, -10]
    }
}

impl BlockSpec for FfnBlock {
    type Syscall = TensorFfnBlockReducedV1Spec;
    const NAME: &'static str = "TensorFfnBlockReducedEcall";
    const CORE_NAME: &'static str = "TensorFfnBlockReducedCore";
    const TOTAL: usize = FFN_TOTAL;
    const ROOT_WORDS: usize = FFN_ROOT_WORDS;
    const TILE_START: u32 = 4;
    const TILES: usize = 3;
    fn registered_words() -> Vec<u32> {
        let mut w = descriptor(
            ceno_emul::FFN_TABLE_REDUCED_V1,
            ceno_emul::FFN_TABLE_COMMITMENT_V1,
        )
        .to_vec();
        w.extend([2i32, -4, 7, -10].map(|x| x as u32));
        let weights = [65_536, 0, 0, 65_536, 0, 0];
        for tile in 4..7 {
            w.extend(ceno_emul::tensor::gate2_linear_commitment_v1(
                REGISTERED_TENSOR_ID,
                tile,
                &weights,
            ));
        }
        w.extend([2i32, -4, 7, -10].map(|x| x as u32));
        w
    }
    fn tile_inputs(tile: usize) -> [i32; 6] {
        if tile < 2 {
            [2, -4, 0, 7, -10, 0]
        } else {
            [0; 6]
        }
    }
    fn final_output() -> [i32; 4] {
        [2, -4, 7, -10]
    }
}

#[derive(Debug)]
pub struct TensorBlockEcallConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    words: Vec<MemoryExpr<E>>,
    mem_rw: Vec<WriteMEM>,
}

#[derive(Debug)]
pub struct TensorBlockCoreConfig<E: ExtensionField> {
    cycle: WitIn,
    call_id: WitIn,
    words: Vec<[WitIn; 2]>,
    tiles: Vec<TensorGate2AirConfig<E>>,
}

pub struct TensorAttentionBlockReducedEcallInstruction<E>(PhantomData<E>);
pub struct TensorAttentionBlockReducedCoreInstruction<E>(PhantomData<E>);
pub struct TensorFfnBlockReducedEcallInstruction<E>(PhantomData<E>);
pub struct TensorFfnBlockReducedCoreInstruction<E>(PhantomData<E>);

fn construct_core<E: ExtensionField, B: BlockSpec>(
    cb: &mut CircuitBuilder<E>,
) -> Result<TensorBlockCoreConfig<E>, ZKVMError> {
    let cycle = cb.create_witin(|| format!("{}_cycle", B::CORE_NAME));
    let call_id = cb.create_witin(|| format!("{}_call_id", B::CORE_NAME));
    let words = (0..B::TOTAL)
        .map(|i| array::from_fn(|j| cb.create_witin(|| format!("{}_word_{i}_{j}", B::CORE_NAME))))
        .collect::<Vec<_>>();
    for (i, limbs) in words.iter().enumerate() {
        for (j, limb) in limbs.iter().enumerate() {
            cb.assert_const_range(
                || format!("{}_word_{i}_{j}_u16", B::CORE_NAME),
                limb.expr(),
                16,
            )?;
        }
    }
    let registered = B::registered_words();
    for (i, expected) in registered.iter().enumerate() {
        if matches!(i, 4 | 5 | 6) {
            continue;
        }
        cb.require_equal(
            || format!("{}_registered_{i}", B::CORE_NAME),
            words[i][0].expr() + words[i][1].expr() * (1u64 << 16),
            E::BaseField::from_u32(*expected).expr(),
        )?;
    }
    let tensor_id = words[7][0].expr() + words[7][1].expr() * (1u64 << 16);
    let mut tiles = Vec::with_capacity(B::TILES);
    for tile in 0..B::TILES {
        let air = TensorGate2AirConfig::construct(
            cb,
            tensor_id.clone(),
            E::BaseField::from_u32(B::TILE_START + tile as u32).expr(),
        )?;
        let root_start = DESC_WORDS + VALUE_WORDS + tile * 8;
        for lane in 0..8 {
            cb.require_equal(
                || format!("{}_tile_{tile}_root_{lane}", B::CORE_NAME),
                air.commitment[lane].expr(),
                words[root_start + lane][0].expr()
                    + words[root_start + lane][1].expr() * (1u64 << 16),
            )?;
        }
        let expected_input = B::tile_inputs(tile);
        for (i, value) in expected_input.iter().enumerate() {
            cb.require_equal(
                || format!("{}_tile_{tile}_input_{i}", B::CORE_NAME),
                air.inputs[i].expr(),
                E::BaseField::from_i64(i64::from(*value)).expr(),
            )?;
        }
        tiles.push(air);
    }
    let record = |phase| {
        tensor_block_state_record(
            cycle.expr(),
            call_id.expr(),
            phase,
            B::Syscall::CODE,
            words
                .iter()
                .flat_map(|x| x.iter().map(|x| x.expr()))
                .collect::<Vec<_>>(),
        )
    };
    cb.read_record(
        || format!("{}_state_in", B::CORE_NAME),
        RAMType::Custom,
        record(BLOCK_STATE_PHASE_INPUT),
    )?;
    cb.write_record(
        || format!("{}_state_out", B::CORE_NAME),
        RAMType::Custom,
        record(BLOCK_STATE_PHASE_OUTPUT),
    )?;
    Ok(TensorBlockCoreConfig {
        cycle,
        call_id,
        words,
        tiles,
    })
}

fn construct_ecall<E: ExtensionField, B: BlockSpec>(
    cb: &mut CircuitBuilder<E>,
) -> Result<TensorBlockEcallConfig<E>, ZKVMError> {
    let vm_state = StateInOut::construct_circuit(cb, false)?;
    let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
        cb,
        UInt::from_const_unchecked(vec![
            B::Syscall::CODE & LIMB_MASK,
            (B::Syscall::CODE >> LIMB_BITS) & LIMB_MASK,
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
    let words = (0..B::TOTAL)
        .map(|i| memory_expr(cb, &format!("{}_word_{i}", B::NAME)))
        .collect::<Vec<_>>();
    let registered = B::registered_words();
    for i in 0..DESC_WORDS {
        if !matches!(i, 4 | 5 | 6) {
            cb.require_equal(
                || format!("{}_desc_{i}", B::NAME),
                word(&words[i]),
                E::BaseField::from_u32(registered[i]).expr(),
            )?;
        }
    }
    let record = |phase| {
        tensor_block_state_record(
            vm_state.ts.expr(),
            ptr.expr_unaligned(),
            phase,
            B::Syscall::CODE,
            flatten(&words),
        )
    };
    cb.write_record(
        || format!("{}_state_in", B::NAME),
        RAMType::Custom,
        record(BLOCK_STATE_PHASE_INPUT),
    )?;
    cb.read_record(
        || format!("{}_state_out", B::NAME),
        RAMType::Custom,
        record(BLOCK_STATE_PHASE_OUTPUT),
    )?;
    let mut mem_rw = Vec::with_capacity(B::TOTAL);
    for i in 0..B::TOTAL {
        let (base, off, before, after) = if i < DESC_WORDS {
            (ptr.expr_unaligned(), i, words[i].clone(), words[i].clone())
        } else if i < DESC_WORDS + VALUE_WORDS {
            (
                word(&words[4]),
                i - DESC_WORDS,
                words[i].clone(),
                words[i].clone(),
            )
        } else if i < DESC_WORDS + VALUE_WORDS + B::ROOT_WORDS {
            (
                word(&words[6]),
                i - DESC_WORDS - VALUE_WORDS,
                words[i].clone(),
                words[i].clone(),
            )
        } else {
            (
                word(&words[5]),
                i - (DESC_WORDS + VALUE_WORDS + B::ROOT_WORDS),
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
    Ok(TensorBlockEcallConfig {
        vm_state,
        ecall_id,
        desc_ptr: (desc_ptr, ptr),
        words,
        mem_rw,
    })
}

fn assign_core<E: ExtensionField, B: BlockSpec>(
    config: &TensorBlockCoreConfig<E>,
    shard_ctx: &mut ShardContext,
    instance: &mut [E::BaseField],
    lkm: &mut LkMultiplicity,
    step: &StepRecord,
) -> Result<(), ZKVMError> {
    let ops = step
        .syscall(&shard_ctx.syscall_witnesses)
        .ok_or_else(|| ZKVMError::InvalidWitness("fused tensor syscall missing".into()))?;
    if ops.mem_ops.len() != B::TOTAL {
        return Err(ZKVMError::InvalidWitness(
            "fused tensor syscall memory count".into(),
        ));
    }
    set_val!(
        instance,
        config.cycle,
        step.cycle() - shard_ctx.current_shard_offset_cycle()
    );
    set_val!(instance, config.call_id, ops.reg_ops[0].value.after as u64);
    let registered = B::registered_words();
    for i in 0..B::TOTAL {
        let raw = if i >= B::TOTAL - VALUE_WORDS {
            ops.mem_ops[i].value.after
        } else {
            ops.mem_ops[i].value.before
        };
        if !matches!(i, 4 | 5 | 6) && raw != registered[i] {
            return Err(ZKVMError::InvalidWitness(
                format!("{} registered relation mismatch at word {i}", B::CORE_NAME).into(),
            ));
        }
        set_val!(instance, config.words[i][0], u64::from(raw & 0xffff));
        set_val!(instance, config.words[i][1], u64::from(raw >> 16));
        lkm.assert_const_range(u64::from(raw & 0xffff), 16);
        lkm.assert_const_range(u64::from(raw >> 16), 16);
    }
    let provider = shard_ctx
        .tensor_proof_context
        .as_ref()
        .map(|c| c.provider());
    let tensor_id = ops.mem_ops[7].value.before;
    for tile in 0..B::TILES {
        let root_start = DESC_WORDS + VALUE_WORDS + tile * 8;
        let root = array::from_fn(|lane| ops.mem_ops[root_start + lane].value.before);
        let input = B::tile_inputs(tile);
        let witness = assign_gate2_core_witness(
            provider,
            GATE2_LINEAR_COMMITMENT_V1,
            tensor_id,
            B::TILE_START + tile as u32,
            &root,
            &input,
        )
        .map_err(|e| ZKVMError::InvalidWitness(e.into()))?;
        config.tiles[tile]
            .assign(instance, lkm, &input, &witness)
            .map_err(|error| ZKVMError::InvalidWitness(error.into_boxed_str()))?;
    }
    let actual = array::from_fn(|i| ops.mem_ops[B::TOTAL - VALUE_WORDS + i].value.after as i32);
    if actual != B::final_output() {
        return Err(ZKVMError::InvalidWitness(
            "fused block output mismatch".into(),
        ));
    }
    Ok(())
}

fn assign_ecalls<E: ExtensionField, B: BlockSpec>(
    config: &TensorBlockEcallConfig<E>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    indices: &[StepIndex],
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    let mut lkm = LkMultiplicity::default();
    let mut wit = RowMajorMatrix::new(indices.len(), num_witin, InstancePaddingStrategy::Default);
    let mut structural = RowMajorMatrix::new(
        indices.len(),
        num_structural_witin,
        InstancePaddingStrategy::Default,
    );
    for ((instance, structural), index) in wit.iter_mut().zip(structural.iter_mut()).zip(indices) {
        *structural.last_mut().unwrap() = E::BaseField::ONE;
        let step = &steps[*index];
        let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
        let ops = step
            .syscall(&syscall_witnesses)
            .ok_or_else(|| ZKVMError::InvalidWitness("fused tensor syscall missing".into()))?;
        if ops.mem_ops.len() != B::TOTAL {
            return Err(ZKVMError::InvalidWitness(
                "fused tensor memory count".into(),
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
                Change::new(B::Syscall::CODE, B::Syscall::CODE),
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
            let value = if i >= B::TOTAL - VALUE_WORDS {
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

fn collect<E: ExtensionField, B: BlockSpec>(
    shard_ctx: &mut ShardContext,
    step: &StepRecord,
) -> Result<(), ZKVMError> {
    let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
    let ops = step
        .syscall(&syscall_witnesses)
        .ok_or_else(|| ZKVMError::InvalidWitness("fused tensor syscall missing".into()))?;
    shard_ctx.send(
        RAMType::Register,
        Platform::register_vma(Platform::reg_ecall()).into(),
        Platform::reg_ecall() as u64,
        step.cycle() + FullTracer::SUBCYCLE_RS1,
        step.rs1().unwrap().previous_cycle,
        B::Syscall::CODE,
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

macro_rules! impl_block {
    ($ecall:ident,$core:ident,$kind:ty) => {
        impl<E: ExtensionField> Instruction<E> for $ecall<E> {
            type InstructionConfig = TensorBlockEcallConfig<E>;
            type InsnType = InsnKind;
            fn inst_kinds() -> &'static [InsnKind] {
                &[InsnKind::ECALL]
            }
            fn name() -> String {
                <$kind>::NAME.into()
            }
            fn construct_circuit(
                cb: &mut CircuitBuilder<E>,
                _: &ProgramParams,
            ) -> Result<Self::InstructionConfig, ZKVMError> {
                construct_ecall::<E, $kind>(cb)
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
                c: &Self::InstructionConfig,
                s: &mut ShardContext,
                n: usize,
                ns: usize,
                steps: &[StepRecord],
                idx: &[StepIndex],
            ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
                assign_ecalls::<E, $kind>(c, s, n, ns, steps, idx)
            }
            fn collect_lk_and_shardram(
                _: &Self::InstructionConfig,
                s: &mut ShardContext,
                _: &mut LkMultiplicity,
                step: &StepRecord,
            ) -> Result<(), ZKVMError> {
                collect::<E, $kind>(s, step)
            }
        }
        impl<E: ExtensionField> Instruction<E> for $core<E> {
            type InstructionConfig = TensorBlockCoreConfig<E>;
            type InsnType = InsnKind;
            fn inst_kinds() -> &'static [InsnKind] {
                &[InsnKind::ECALL]
            }
            fn name() -> String {
                <$kind>::CORE_NAME.into()
            }
            fn construct_circuit(
                cb: &mut CircuitBuilder<E>,
                _: &ProgramParams,
            ) -> Result<Self::InstructionConfig, ZKVMError> {
                construct_core::<E, $kind>(cb)
            }
            fn assign_instance(
                c: &Self::InstructionConfig,
                s: &mut ShardContext,
                i: &mut [E::BaseField],
                l: &mut LkMultiplicity,
                step: &StepRecord,
            ) -> Result<(), ZKVMError> {
                assign_core::<E, $kind>(c, s, i, l, step)
            }
        }
    };
}
impl_block!(
    TensorAttentionBlockReducedEcallInstruction,
    TensorAttentionBlockReducedCoreInstruction,
    AttentionBlock
);
impl_block!(
    TensorFfnBlockReducedEcallInstruction,
    TensorFfnBlockReducedCoreInstruction,
    FfnBlock
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_builder::ConstraintSystem, e2e::TensorProofContext};
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
    fn fused_core_costs_are_circuit_derived() {
        for attention in [true, false] {
            let mut cs = ConstraintSystem::<E>::new(|| "fused");
            let mut cb = CircuitBuilder::new(&mut cs);
            if attention {
                construct_core::<E, AttentionBlock>(&mut cb).unwrap();
            } else {
                construct_core::<E, FfnBlock>(&mut cb).unwrap();
            }
            assert!(cb.cs.num_witin > 100);
            assert!(!cb.cs.r_expressions.is_empty());
            assert!(!cb.cs.w_expressions.is_empty());
        }
    }

    fn assignment<B: BlockSpec, I: Instruction<E, InstructionConfig = TensorBlockCoreConfig<E>>>(
        attention: bool,
    ) {
        let (step, _, syscall_witnesses, provider) =
            ceno_emul::test_utils::tensor_block_step(attention);
        let steps = vec![step];
        let indices = vec![0];
        let mut cs = ConstraintSystem::<E>::new(|| "fused_assignment");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = construct_core::<E, B>(&mut cb).unwrap();
        let n = cb.cs.num_witin as usize;
        let ns = cb.cs.num_structural_witin as usize;
        let mut missing = ShardContext::default();
        missing.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        assert!(I::assign_instances(&config, &mut missing, n, ns, &steps, &indices).is_err());

        let context = Arc::new(TensorProofContext::new(provider));
        let mut valid = ShardContext::default();
        valid.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        valid.tensor_proof_context = Some(context.clone());
        let (core_rmms, _) =
            I::assign_instances(&config, &mut valid, n, ns, &steps, &indices).unwrap();

        let mut ecall_cs = ConstraintSystem::<E>::new(|| "fused_ecall_assignment");
        let mut ecall_cb = CircuitBuilder::new(&mut ecall_cs);
        let ecall_config = construct_ecall::<E, B>(&mut ecall_cb).unwrap();
        let en = ecall_cb.cs.num_witin as usize;
        let esn = (ecall_cb.cs.num_structural_witin as usize).max(1);
        let mut ecall_ctx = ShardContext::default();
        ecall_ctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
        let (ecall_rmms, _) =
            assign_ecalls::<E, B>(&ecall_config, &mut ecall_ctx, en, esn, &steps, &indices)
                .unwrap();
        let ew = &ecall_rmms[0].values()[..en];
        let es = &ecall_rmms[1].values()[..esn.max(1)];
        let cw = &core_rmms[0].values()[..n];
        let cws = &core_rmms[1].values()[..ns.max(1)];
        let e_in = ecall_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|name| name.contains("state_in"))
            .unwrap();
        let e_out = ecall_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|name| name.contains("state_out"))
            .unwrap();
        let c_in = cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|name| name.contains("state_in"))
            .unwrap();
        let c_out = cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|name| name.contains("state_out"))
            .unwrap();
        assert_eq!(
            eval(&ecall_cb.cs.w_expressions[e_in], ew, es),
            eval(&cb.cs.r_expressions[c_in], cw, cws)
        );
        assert_eq!(
            eval(&ecall_cb.cs.r_expressions[e_out], ew, es),
            eval(&cb.cs.w_expressions[c_out], cw, cws)
        );

        // Independently cover descriptor identities, X, every root/opening,
        // Y, and table commitment. Pointer words are separately constrained
        // by ecall memory routing rather than fixed fixture values.
        let mut tamper = vec![0usize, 1, 2, 3, 7, 8, 9, 16, 17, DESC_WORDS];
        tamper.extend(DESC_WORDS + VALUE_WORDS..DESC_WORDS + VALUE_WORDS + B::ROOT_WORDS);
        tamper.push(B::TOTAL - 1);
        for index in tamper {
            let mut bad = syscall_witnesses.clone();
            if index >= B::TOTAL - VALUE_WORDS {
                bad[0].mem_ops[index].value.after ^= 1;
            } else {
                bad[0].mem_ops[index].value.before ^= 1;
            }
            let mut ctx = ShardContext::default();
            ctx.syscall_witnesses = Arc::new(bad);
            ctx.tensor_proof_context = Some(context.clone());
            assert!(
                I::assign_instances(&config, &mut ctx, n, ns, &steps, &indices).is_err(),
                "fused word {index} was not rejected"
            );
        }
        for corrupt_tile in B::TILE_START as usize..B::TILE_START as usize + B::TILES {
            let good = ceno_emul::tensor::encode_i32_le(&[65_536, 0, 0, 65_536, 0, 0]);
            let mut tiles = (0..7).map(|_| good.clone()).collect::<Vec<_>>();
            tiles[corrupt_tile][0] ^= 1;
            let bad_provider = Arc::new(
                ceno_emul::tensor::DeterministicTileProvider::new(REGISTERED_TENSOR_ID, tiles)
                    .unwrap(),
            );
            let mut ctx = ShardContext::default();
            ctx.syscall_witnesses = Arc::new(syscall_witnesses.clone());
            ctx.tensor_proof_context = Some(Arc::new(TensorProofContext::new(bad_provider)));
            assert!(
                I::assign_instances(&config, &mut ctx, n, ns, &steps, &indices).is_err(),
                "private opening for tile {corrupt_tile} was not rejected"
            );
        }
    }

    #[test]
    fn fused_attention_authenticates_all_tiles_and_fails_closed() {
        assignment::<AttentionBlock, TensorAttentionBlockReducedCoreInstruction<E>>(true);
    }

    #[test]
    fn fused_ffn_authenticates_all_tiles_and_fails_closed() {
        assignment::<FfnBlock, TensorFfnBlockReducedCoreInstruction<E>>(false);
    }
}
