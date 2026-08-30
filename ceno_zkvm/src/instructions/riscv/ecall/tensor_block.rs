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
        if matches!(i, 4 | 5 | 6 | 17) {
            continue;
        }
        cb.require_equal(
            || format!("{}_registered_{i}", B::CORE_NAME),
            words[i][0].expr() + words[i][1].expr() * (1u64 << 16),
            E::BaseField::from_u32(*expected).expr(),
        )?;
    }
    cb.assert_const_range(
        || format!("{}_layer_u5", B::CORE_NAME),
        words[17][0].expr() + words[17][1].expr() * (1u64 << 16),
        5,
    )?;
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
        if !matches!(i, 4 | 5 | 6 | 17) {
            cb.require_equal(
                || format!("{}_desc_{i}", B::NAME),
                word(&words[i]),
                E::BaseField::from_u32(registered[i]).expr(),
            )?;
        }
    }
    cb.assert_const_range(|| format!("{}_layer_u5", B::NAME), word(&words[17]), 5)?;
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
    let trace_lk = std::env::var_os("CENO_TENSOR_E2E_LOGUP_TRACE").is_some();
    let mut manual_lkm = LkMultiplicity::default();
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
        if !matches!(i, 4 | 5 | 6 | 17) && raw != registered[i] {
            return Err(ZKVMError::InvalidWitness(
                format!("{} registered relation mismatch at word {i}", B::CORE_NAME).into(),
            ));
        }
        set_val!(instance, config.words[i][0], u64::from(raw & 0xffff));
        set_val!(instance, config.words[i][1], u64::from(raw >> 16));
        let target = if trace_lk { &mut manual_lkm } else { &mut *lkm };
        target.assert_const_range(u64::from(raw & 0xffff), 16);
        target.assert_const_range(u64::from(raw >> 16), 16);
    }
    if ops.mem_ops[17].value.before >= 32 {
        return Err(ZKVMError::InvalidWitness(
            "fused block layer outside registered model".into(),
        ));
    }
    // Mirrors the dedicated u5 AIR lookup on the fused block layer word.
    // The word's two u16 limbs above do not satisfy this separate relation.
    let layer_target = if trace_lk { &mut manual_lkm } else { &mut *lkm };
    layer_target.assert_const_range(u64::from(ops.mem_ops[17].value.before), 5);
    if trace_lk {
        let counts = manual_lkm.into_finalize_result();
        tracing::info!(
            core = B::CORE_NAME,
            site = "descriptor_u16_limbs",
            buckets = ?counts.iter().enumerate().map(|(table, entries)| (table, entries.len(), entries.values().sum::<usize>())).collect::<Vec<_>>(),
            "Gate-5 Tensor core lookup site"
        );
        *lkm += counts;
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
        let mut tile_lkm = LkMultiplicity::default();
        let target = if trace_lk { &mut tile_lkm } else { &mut *lkm };
        config.tiles[tile]
            .assign(instance, target, &input, &witness)
            .map_err(|error| ZKVMError::InvalidWitness(error.into_boxed_str()))?;
        if trace_lk {
            let counts = tile_lkm.into_finalize_result();
            tracing::info!(
                core = B::CORE_NAME,
                site = tile,
                buckets = ?counts.iter().enumerate().map(|(table, entries)| (table, entries.len(), entries.values().sum::<usize>())).collect::<Vec<_>>(),
                "Gate-5 Tensor core lookup site"
            );
            *lkm += counts;
        }
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
        // `construct_ecall` additionally range-constrains the dynamic layer
        // descriptor to five bits.  Memory assignment populates its limbs but
        // does not account for that distinct Dynamic-table relation.
        lkm.assert_const_range(u64::from(ops.mem_ops[17].value.before), 5);
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
    use ff_ext::{BabyBearExt4, FieldFrom, SmallField};
    use itertools::Itertools;
    use multilinear_extensions::utils::eval_by_expr_with_instance;
    use p3::matrix::Matrix;
    use std::sync::Arc;
    type E = BabyBearExt4;

    // The production instruction is intentionally K1024.  Gate 5's compact
    // reproducer instead needs to register the same K32 relation used to
    // create its 31/32 padded trace; registering the production instruction
    // against that trace would make `num_witin` disagree before PCS is
    // reached.  Keep this test-only instruction local so it cannot affect the
    // program registry or the production circuit identity.
    const MINIATURE_TILE_K: usize = ceno_emul::tensor::production::mini_llama_10m::PROOF_TILE_K;
    struct MiniatureTensorProductionTileInstruction<E>(PhantomData<E>);

    impl<E: ExtensionField> Instruction<E> for MiniatureTensorProductionTileInstruction<E> {
        type InstructionConfig =
            crate::precompiles::TensorProductionTileCoreConfig<E, MINIATURE_TILE_K>;
        type InsnType = InsnKind;

        fn inst_kinds() -> &'static [InsnKind] {
            &[InsnKind::ECALL]
        }

        fn name() -> String {
            "MiniatureTensorProductionTileK32".into()
        }

        fn construct_circuit(
            cb: &mut CircuitBuilder<E>,
            _: &ProgramParams,
        ) -> Result<Self::InstructionConfig, ZKVMError> {
            crate::precompiles::TensorProductionTileCoreConfig::<E, MINIATURE_TILE_K>::construct(cb)
        }

        fn assign_instance(
            _: &Self::InstructionConfig,
            _: &mut ShardContext,
            _: &mut [E::BaseField],
            _: &mut LkMultiplicity,
            _: &StepRecord,
        ) -> Result<(), ZKVMError> {
            unreachable!("the compact PCS harness assigns its K32 rows directly")
        }

        fn assign_instances(
            _: &Self::InstructionConfig,
            _: &mut ShardContext,
            _: usize,
            _: usize,
            _: &[StepRecord],
            _: &[StepIndex],
        ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
            unreachable!("the compact PCS harness assigns its K32 rows directly")
        }
    }

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
        let mut tamper = vec![0usize, 1, 2, 3, 7, 8, 9, 16, DESC_WORDS];
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
        for layer in [1, 31] {
            let mut layered = syscall_witnesses.clone();
            layered[0].mem_ops[17].value.before = layer;
            let mut ctx = ShardContext::default();
            ctx.syscall_witnesses = Arc::new(layered);
            ctx.tensor_proof_context = Some(context.clone());
            I::assign_instances(&config, &mut ctx, n, ns, &steps, &indices)
                .unwrap_or_else(|error| panic!("registered layer {layer} rejected: {error:?}"));
        }
        let mut outside = syscall_witnesses.clone();
        outside[0].mem_ops[17].value.before = 32;
        let mut outside_ctx = ShardContext::default();
        outside_ctx.syscall_witnesses = Arc::new(outside);
        outside_ctx.tensor_proof_context = Some(context.clone());
        assert!(
            I::assign_instances(&config, &mut outside_ctx, n, ns, &steps, &indices).is_err(),
            "layer 32 must be rejected"
        );
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

    #[test]
    fn fused_topology_batches_all_32_layers_in_each_chip() {
        use ceno_emul::{CENO_PLATFORM, FullTracer, SyscallWitness, VMState};

        let mut vm = VMState::<FullTracer>::new_from_elf_with_tracer(
            CENO_PLATFORM.clone(),
            ceno_examples::llama_10m_topology_v1,
        )
        .unwrap();
        let tile = ceno_emul::tensor::encode_i32_le(&[65_536, 0, 0, 65_536, 0, 0]);
        let provider = Arc::new(
            ceno_emul::tensor::DeterministicTileProvider::new(
                REGISTERED_TENSOR_ID,
                (0..7).map(|_| tile.clone()).collect(),
            )
            .unwrap(),
        );
        vm.set_tensor_witness_provider(provider.clone());
        vm.iter_until_halt().collect::<Result<Vec<_>, _>>().unwrap();
        let steps = vm.tracer().recorded_steps();
        let syscall_witnesses = Arc::new(vm.tracer().syscall_witnesses().to_vec());

        fn check<B, I>(
            steps: &[StepRecord],
            syscall_witnesses: Arc<Vec<SyscallWitness>>,
            provider: Arc<ceno_emul::tensor::DeterministicTileProvider>,
        ) where
            B: BlockSpec,
            I: Instruction<E, InstructionConfig = TensorBlockCoreConfig<E>>,
        {
            let indices = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| {
                    (step.insn.kind == InsnKind::ECALL
                        && step.rs1().is_some_and(|op| op.value == B::Syscall::CODE))
                    .then_some(index)
                })
                .collect_vec();
            assert_eq!(indices.len(), 32);
            let mut cs = ConstraintSystem::<E>::new(|| "fused_32_layer_assignment");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = construct_core::<E, B>(&mut cb).unwrap();
            let mut shard = ShardContext::default();
            shard.syscall_witnesses = syscall_witnesses;
            shard.tensor_proof_context = Some(Arc::new(TensorProofContext::new(provider)));
            let (rmms, _) = I::assign_instances(
                &config,
                &mut shard,
                usize::from(cs.num_witin),
                usize::from(cs.num_structural_witin),
                steps,
                &indices,
            )
            .unwrap();
            assert_eq!(rmms[0].num_instances(), 32);
            assert_eq!(rmms[0].height(), 32);
            for (layer, row) in rmms[0].rows().take(32).enumerate() {
                let row = row.collect_vec();
                let lo = row[usize::from(config.words[17][0].id)].to_canonical_u64();
                let hi = row[usize::from(config.words[17][1].id)].to_canonical_u64();
                assert_eq!(lo + (hi << 16), layer as u64);
            }
        }

        check::<AttentionBlock, TensorAttentionBlockReducedCoreInstruction<E>>(
            steps,
            syscall_witnesses.clone(),
            provider.clone(),
        );
        check::<FfnBlock, TensorFfnBlockReducedCoreInstruction<E>>(
            steps,
            syscall_witnesses,
            provider,
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires a CUDA device; Gate-5 miniature PCS isolation"]
    fn miniature_assigned_matrices_gpu_basefold_open_and_verify() {
        use crate::scheme::{
            create_backend, create_prover,
            hal::{MainConstraintResult, MainSumcheckEvals, OpeningProver, TraceCommitter},
            prover::collect_main_constraint_openings,
        };
        use ceno_emul::{CENO_PLATFORM, FullTracer, SyscallWitness, VMState};
        use ceno_gpu::{Buffer, CudaHal};
        use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme, SecurityLevel};
        use std::collections::BTreeMap;
        use transcript::{BasicTranscript, Transcript};

        type Pcs = Basefold<E, BasefoldRSParams>;
        type B = <E as ExtensionField>::BaseField;

        fn assigned_fused<BSpec, I>(
            steps: &[StepRecord],
            syscall_witnesses: Arc<Vec<SyscallWitness>>,
            provider: Arc<ceno_emul::tensor::DeterministicTileProvider>,
        ) -> RowMajorMatrix<B>
        where
            BSpec: BlockSpec,
            I: Instruction<E, InstructionConfig = TensorBlockCoreConfig<E>>,
        {
            let indices = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| {
                    (step.insn.kind == InsnKind::ECALL
                        && step
                            .rs1()
                            .is_some_and(|op| op.value == BSpec::Syscall::CODE))
                    .then_some(index)
                })
                .collect_vec();
            let mut cs = ConstraintSystem::<E>::new(|| "miniature_gpu_fused_assignment");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = construct_core::<E, BSpec>(&mut cb).unwrap();
            let mut shard = ShardContext::default();
            shard.syscall_witnesses = syscall_witnesses;
            shard.tensor_proof_context = Some(Arc::new(TensorProofContext::new(provider)));
            let [witness, _structural] = I::assign_instances(
                &config,
                &mut shard,
                usize::from(cs.num_witin),
                usize::from(cs.num_structural_witin),
                steps,
                &indices,
            )
            .unwrap()
            .0;
            witness
        }

        let mut vm = VMState::<FullTracer>::new_from_elf_with_tracer(
            CENO_PLATFORM.clone(),
            ceno_examples::llama_10m_topology_v1,
        )
        .unwrap();
        let tile = ceno_emul::tensor::encode_i32_le(&[65_536, 0, 0, 65_536, 0, 0]);
        let provider = Arc::new(
            ceno_emul::tensor::DeterministicTileProvider::new(
                REGISTERED_TENSOR_ID,
                (0..7).map(|_| tile.clone()).collect(),
            )
            .unwrap(),
        );
        vm.set_tensor_witness_provider(provider.clone());
        vm.iter_until_halt().collect::<Result<Vec<_>, _>>().unwrap();
        let steps = vm.tracer().recorded_steps();
        let syscall_witnesses = Arc::new(vm.tracer().syscall_witnesses().to_vec());
        let attention = assigned_fused::<
            AttentionBlock,
            TensorAttentionBlockReducedCoreInstruction<E>,
        >(steps, syscall_witnesses.clone(), provider.clone());
        let ffn = assigned_fused::<FfnBlock, TensorFfnBlockReducedCoreInstruction<E>>(
            steps,
            syscall_witnesses,
            provider,
        );

        const K: usize = ceno_emul::tensor::production::mini_llama_10m::PROOF_TILE_K;
        let tensor_id = 10_056;
        let input = (0..K)
            .map(|i| if i % 6 == 0 { i as i32 - 19 } else { 0 })
            .collect_vec();
        let weights = (0..K)
            .map(|i| if i % 5 == 0 { -65_536 } else { 0 })
            .collect_vec();
        let compact = weights[..16].to_vec();
        let tile_provider = ceno_emul::tensor::DeterministicTileProvider::new(
            tensor_id,
            (0..13)
                .map(|_| ceno_emul::tensor::encode_i32_le(&weights))
                .chain(std::iter::once(ceno_emul::tensor::encode_i32_le(&compact)))
                .collect(),
        )
        .unwrap();
        let desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::new(
            ceno_emul::tensor::production::ProductionMatMulSignature::MiniIntermediateK432,
            tensor_id,
            0,
            16,
        )
        .unwrap();
        let mut tile_cs = ConstraintSystem::<E>::new(|| "miniature_gpu_k32_assignment");
        let mut tile_cb = CircuitBuilder::new(&mut tile_cs);
        let tile_config =
            crate::precompiles::TensorProductionTileCoreConfig::<E, K>::construct(&mut tile_cb)
                .unwrap();
        let mut k32 = RowMajorMatrix::new(
            // Keep one logical row out of the physical power-of-two domain.
            // This is the direct regression for the range/view hypothesis:
            // commitment and opening must agree on the zero-padded row 31.
            31,
            usize::from(tile_cs.num_witin),
            InstancePaddingStrategy::Default,
        );
        for (row_index, row) in k32.iter_mut().enumerate() {
            let mut lkm = LkMultiplicity::default();
            tile_config
                .assign(
                    row,
                    &mut lkm,
                    Some(&tile_provider),
                    desc,
                    if row_index == 30 { 13 } else { row_index % 13 },
                    row_index as u64,
                    0x7000 + row_index as u32 * 4,
                    &input,
                )
                .unwrap();
        }

        let mut short_prefix = RowMajorMatrix::new(7, 17, InstancePaddingStrategy::Default);
        for (row_idx, row) in short_prefix.iter_mut().enumerate() {
            for (col_idx, value) in row.iter_mut().enumerate() {
                *value = B::from_u64((row_idx * 17 + col_idx + 1) as u64);
            }
        }
        // The global trace cache mixes circuit domains of different heights.
        // This small 7/8-row trace is the next bottom-up increment: it gives
        // the production adapter a distinct three-variable opening point while
        // retaining the tensor matrices and their K32 logical/padded split.
        let matrices = vec![attention, ffn, k32.clone(), short_prefix];
        let names = ["attention_core", "ffn_core", "k32_tile", "short_prefix_7_8"];
        // This harness intentionally bypasses `setup_program` and the RV
        // registry: only these three tensor witness domains participate in the
        // Basefold commitment.  Keep the range/view boundary explicit here so
        // a future full-proof mismatch can be compared without guessing which
        // matrix (or padded suffix) was opened.
        eprintln!(
            "[direct-pcs] registry=3-tensor-domains full-rv-registry=0 shard_slice=0..{}",
            matrices
                .iter()
                .map(RowMajorMatrix::num_instances)
                .sum::<usize>()
        );
        for (name, matrix) in names.iter().zip(&matrices) {
            eprintln!(
                "[direct-pcs] matrix={name} logical_rows={} physical_rows={} columns={} logical_range=0..{} padded_range=0..{}",
                matrix.num_instances(),
                matrix.height(),
                matrix.width(),
                matrix.num_instances(),
                matrix.height(),
            );
        }
        let hal = gkr_iop::gpu::get_cuda_hal().unwrap();
        for (name, matrix) in names.iter().zip(&matrices) {
            let host = matrix.values();
            let device = hal.alloc_elems_from_host(host, None).unwrap();
            let roundtrip = device.to_vec().unwrap();
            assert_eq!(roundtrip.len(), host.len(), "{name} GPU length mismatch");
            for row in 0..matrix.height() {
                for column in 0..matrix.width() {
                    let index = row * matrix.width() + column;
                    assert_eq!(
                        roundtrip[index], host[index],
                        "{name} GPU roundtrip mismatch at column={column} row={row}"
                    );
                }
            }
        }

        let max_size = 1 << 10;
        let params = Pcs::setup(max_size, SecurityLevel::default()).unwrap();
        let (pp, vp) = Pcs::trim(params, max_size).unwrap();
        let cpu_commitment = Pcs::batch_commit(&pp, matrices.clone()).unwrap();
        let gpu_commitment = hal
            .basefold
            .batch_commit_cache_trace(&hal, matrices.clone())
            .unwrap();
        assert_eq!(cpu_commitment.commit, gpu_commitment.commit);
        eprintln!(
            "[direct-pcs] cpu_gpu_root_match=true root={:?}",
            cpu_commitment.commit
        );

        for point_kind in ["fixed", "transcript"] {
            let mut point_transcript = BasicTranscript::<E>::new(b"miniature-assigned-point");
            let points = matrices
                .iter()
                .map(|matrix| {
                    let point_len = matrix.num_vars();
                    if point_kind == "fixed" {
                        (0..point_len)
                            .map(|i| E::from_v((i + 2) as u64))
                            .collect_vec()
                    } else {
                        point_transcript.sample_and_append_vec(b"point", point_len)
                    }
                })
                .collect_vec();
            let openings = matrices
                .iter()
                .zip(&points)
                .map(|(matrix, point)| {
                    let evals = matrix
                        .to_mles()
                        .iter()
                        .map(|mle| mle.evaluate(&point))
                        .collect_vec();
                    (point.clone(), evals)
                })
                .collect_vec();
            for (((name, matrix), point), (_, evals)) in
                names.iter().zip(&matrices).zip(&points).zip(&openings)
            {
                eprintln!(
                    "[direct-pcs] opening={point_kind} matrix={name} q_point_dim={} query_mles={} view_rows=0..{} physical_rows={} columns={}",
                    point.len(),
                    evals.len(),
                    matrix.num_instances(),
                    matrix.height(),
                    matrix.width(),
                );
            }
            let mut prover_transcript = BasicTranscript::<E>::new(b"miniature-assigned-open");
            let gpu_proof = hal
                .basefold
                .batch_open(
                    &hal,
                    &pp,
                    vec![(&gpu_commitment, openings.clone())],
                    &mut prover_transcript,
                )
                .unwrap();
            let proof = mpcs::basefold::structure::BasefoldProof {
                commits: gpu_proof.commits,
                query_opening_proof: gpu_proof.query_opening_proof,
                sumcheck_proof: gpu_proof.sumcheck_proof,
                final_message: gpu_proof.final_message,
                pow_witness: gpu_proof.pow_witness,
            };
            let verifier_round = vec![(
                Pcs::get_pure_commitment(&cpu_commitment),
                openings
                    .into_iter()
                    .map(|(point, evals)| (point.len(), (point, evals)))
                    .collect_vec(),
            )];
            let mut verifier_transcript = BasicTranscript::<E>::new(b"miniature-assigned-open");
            Pcs::batch_verify(&vp, verifier_round, &proof, &mut verifier_transcript)
                .unwrap_or_else(|error| {
                    panic!("{point_kind} miniature GPU opening failed: {error:?}")
                });
        }

        // Take the identical direct matrices through Ceno's production GPU
        // ownership adapter.  The BTreeMap keys intentionally have holes and
        // do not match their insertion positions: `commit_traces` consumes
        // the ordered values, while the global prover routes opening evals by
        // that physical trace order.  This is the smallest check of that
        // ownership contract, without setup_program or the RV registry.
        let backend = create_backend::<E, Pcs>(10, SecurityLevel::default());
        let prover = create_prover(backend.clone());
        let trace_map = BTreeMap::from([
            (7usize, matrices[0].clone()),
            (41usize, matrices[1].clone()),
            (93usize, matrices[2].clone()),
            (121usize, matrices[3].clone()),
        ]);
        let (_unused_mles, adapter_data, adapter_commit) = prover.commit_traces(trace_map);
        assert_eq!(
            adapter_commit.commit, cpu_commitment.commit,
            "adapter root differs from direct commit"
        );
        let adapter_points = matrices
            .iter()
            .map(|matrix| {
                (0..matrix.num_vars())
                    .map(|i| E::from_v((i + 9) as u64))
                    .collect_vec()
            })
            .collect_vec();
        let adapter_evals = matrices
            .iter()
            .zip(&adapter_points)
            .map(|(matrix, point)| {
                vec![
                    matrix
                        .to_mles()
                        .iter()
                        .map(|mle| mle.evaluate(&point))
                        .collect_vec(),
                ]
            })
            .collect_vec();
        eprintln!(
            "[adapter-pcs] trace_ids=[7,41,93,121] physical_order=[attention_core,ffn_core,k32_tile,short_prefix_7_8] q_point_dims={:?} eval_groups={:?}",
            adapter_points.iter().map(Vec::len).collect_vec(),
            adapter_evals
                .iter()
                .map(|group| group[0].len())
                .collect_vec(),
        );
        let mut adapter_prover_transcript = BasicTranscript::<E>::new(b"miniature-adapter-open");
        let adapter_proof = prover.open(
            adapter_data,
            None,
            // Ceno's global opening adapter uses one point/eval entry per
            // physical trace.  These are intentionally the same challenge:
            // only trace routing, not Fiat-Shamir sampling, is under test.
            adapter_points.clone(),
            adapter_evals,
            &mut adapter_prover_transcript,
        );
        let verifier_round = vec![(
            adapter_commit.clone(),
            matrices
                .iter()
                .zip(&adapter_points)
                .map(|(matrix, point)| {
                    (
                        point.len(),
                        (
                            point.clone(),
                            matrix
                                .to_mles()
                                .iter()
                                .map(|mle| mle.evaluate(point))
                                .collect_vec(),
                        ),
                    )
                })
                .collect_vec(),
        )];
        let mut adapter_verifier_transcript = BasicTranscript::<E>::new(b"miniature-adapter-open");
        Pcs::batch_verify(
            &backend.vp,
            verifier_round,
            &adapter_proof,
            &mut adapter_verifier_transcript,
        )
        .expect("global GPU trace ownership adapter opening must verify");
        eprintln!("[adapter-pcs] root/opening verified=true");

        // The full proof does not hand arbitrary opening points to `open`.
        // Main-constraint/tower proving first samples one global point, then
        // `frontload_input_opening_point` takes a prefix sized for each chip.
        // Keep that exact routing shape in this tiny harness.  In particular,
        // the physical commitment order is sparse trace order, whereas the
        // source circuit id is only diagnostic metadata and must not become an
        // index into the PCS data.  This is the narrowest check of the
        // suspected split-MLE range/view bug without registering the RV
        // registry or building a MockProver.
        let main_global_point = (0..5).map(|i| E::from_v((i + 31) as u64)).collect_vec();
        let main_sources = [
            (7usize, "attention_core", "tower->main", 5usize),
            (41usize, "ffn_core", "tower->main", 5usize),
            (93usize, "k32_tile", "tower->main", 5usize),
            (121usize, "short_prefix_7_8", "tower->main", 3usize),
        ];
        let main_points = main_sources
            .iter()
            .map(|(_, _, _, num_vars)| main_global_point[..*num_vars].to_vec())
            .collect_vec();
        let main_evals = matrices
            .iter()
            .zip(&main_points)
            .map(|(matrix, point)| {
                vec![
                    matrix
                        .to_mles()
                        .iter()
                        .map(|mle| mle.evaluate(point))
                        .collect_vec(),
                ]
            })
            .collect_vec();
        // Use the exact main/tower result -> PCS producer seam, rather than
        // passing the synthetic vectors directly to `open`.  The full prover
        // obtains these results from `prove_batched_main_constraints`; this
        // control keeps its source circuit IDs deliberately sparse so an
        // accidental circuit-ID/physical-trace-index confusion is observable.
        let (producer_points, producer_evals) = collect_main_constraint_openings(
            main_sources
                .iter()
                .zip(&main_points)
                .zip(&main_evals)
                .map(
                    |(((circuit_idx, _, _, _), point), eval_groups)| MainConstraintResult {
                        circuit_idx: *circuit_idx,
                        input_opening_point: point.clone(),
                        opening_evals: MainSumcheckEvals {
                            wits_in_evals: eval_groups[0].clone(),
                            fixed_in_evals: vec![],
                        },
                    },
                )
                .collect(),
        );
        assert_eq!(producer_points, main_points);
        assert_eq!(
            producer_evals,
            main_evals
                .iter()
                .map(|eval_groups| vec![eval_groups[0].clone(), vec![]])
                .collect_vec(),
            "the production producer must retain a fixed-domain placeholder"
        );
        for ((((circuit_idx, name, source, num_vars), matrix), point), eval_groups) in main_sources
            .iter()
            .zip(&matrices)
            .zip(&main_points)
            .zip(&main_evals)
        {
            eprintln!(
                "[main-route-pcs] source={source} circuit_idx={circuit_idx} matrix={name} \
                 commit_trace_order={} logical_range=0..{} padded_range=0..{} \
                 view_rows=0..{} query_prefix={} query_dim={} mle_count={} eval_groups={}",
                main_sources
                    .iter()
                    .position(|(idx, _, _, _)| idx == circuit_idx)
                    .unwrap(),
                matrix.num_instances(),
                matrix.height(),
                matrix.num_instances(),
                num_vars,
                point.len(),
                matrix.width(),
                eval_groups.len(),
            );
            assert_eq!(point, &main_global_point[..*num_vars]);
            assert_eq!(eval_groups.len(), 1, "main route has one witness group");
            assert_eq!(eval_groups[0].len(), matrix.width());
        }
        let main_trace_map = BTreeMap::from([
            (7usize, matrices[0].clone()),
            (41usize, matrices[1].clone()),
            (93usize, matrices[2].clone()),
            (121usize, matrices[3].clone()),
        ]);
        let (_main_mles, main_data, main_commit) = prover.commit_traces(main_trace_map);
        assert_eq!(main_commit.commit, cpu_commitment.commit);
        let mut main_prover_transcript = BasicTranscript::<E>::new(b"miniature-main-route-open");
        let main_proof = prover.open(
            main_data,
            None,
            producer_points,
            producer_evals,
            &mut main_prover_transcript,
        );
        let main_round = vec![(
            main_commit,
            matrices
                .iter()
                .zip(&main_points)
                .map(|(matrix, point)| {
                    (
                        point.len(),
                        (
                            point.clone(),
                            matrix
                                .to_mles()
                                .iter()
                                .map(|mle| mle.evaluate(point))
                                .collect_vec(),
                        ),
                    )
                })
                .collect_vec(),
        )];
        let mut main_verifier_transcript = BasicTranscript::<E>::new(b"miniature-main-route-open");
        Pcs::batch_verify(
            &backend.vp,
            main_round,
            &main_proof,
            &mut main_verifier_transcript,
        )
        .expect("main-constraint/tower routed GPU opening must verify");
        eprintln!("[main-route-pcs] root/opening verified=true");

        // The full prover sends a second fixed round through the same adapter.
        // Reuse the small matrices as deterministic fixed data so the test
        // covers `evals.remove(0)` routing for both ownership domains without
        // constructing program fixed witnesses or registering RV chips.
        let fixed_trace_map = BTreeMap::from([
            (5usize, matrices[0].clone()),
            (17usize, matrices[1].clone()),
            (29usize, matrices[2].clone()),
            (53usize, matrices[3].clone()),
        ]);
        let (_fixed_mles, fixed_data, fixed_commit) = prover.commit_traces(fixed_trace_map);
        assert_eq!(
            fixed_commit.commit, cpu_commitment.commit,
            "fixed adapter root differs from direct commit"
        );
        let witness_and_fixed_evals = matrices
            .iter()
            .zip(&adapter_points)
            .map(|(matrix, point)| {
                let evals = matrix
                    .to_mles()
                    .iter()
                    .map(|mle| mle.evaluate(&point))
                    .collect_vec();
                vec![evals.clone(), evals]
            })
            .collect_vec();
        let mut mixed_prover_transcript =
            BasicTranscript::<E>::new(b"miniature-adapter-mixed-open");
        let mixed_proof = prover.open(
            // A fresh commitment is needed because `open` consumes PCS data.
            prover
                .commit_traces(BTreeMap::from([
                    (7usize, matrices[0].clone()),
                    (41usize, matrices[1].clone()),
                    (93usize, matrices[2].clone()),
                    (121usize, matrices[3].clone()),
                ]))
                .1,
            Some(Arc::new(fixed_data)),
            adapter_points.clone(),
            witness_and_fixed_evals,
            &mut mixed_prover_transcript,
        );
        let per_trace_evals = matrices
            .iter()
            .zip(&adapter_points)
            .map(|(matrix, point)| {
                matrix
                    .to_mles()
                    .iter()
                    .map(|mle| mle.evaluate(&point))
                    .collect_vec()
            })
            .collect_vec();
        let mixed_rounds = vec![
            (
                adapter_commit,
                per_trace_evals
                    .iter()
                    .zip(&adapter_points)
                    .map(|(evals, point)| (point.len(), (point.clone(), evals.clone())))
                    .collect_vec(),
            ),
            (
                fixed_commit,
                per_trace_evals
                    .iter()
                    .zip(&adapter_points)
                    .map(|(evals, point)| (point.len(), (point.clone(), evals.clone())))
                    .collect_vec(),
            ),
        ];
        let mut mixed_verifier_transcript =
            BasicTranscript::<E>::new(b"miniature-adapter-mixed-open");
        Pcs::batch_verify(
            &backend.vp,
            mixed_rounds,
            &mixed_proof,
            &mut mixed_verifier_transcript,
        )
        .expect("mixed witness/fixed global adapter opening must verify");
        eprintln!("[adapter-pcs] witness_fixed_rounds verified=true");

        // The preceding checks manufacture MainConstraintResult values.  Run
        // one *registered* tensor core through the actual GPU batched-main
        // prover as the next increment.  This deliberately keeps the full RV
        // registry and the large Llama domains out of the iteration, while
        // retaining the exact generated GKR circuit, committed trace, deferred
        // witness extraction and result-to-PCS-opening producer used in a
        // production proof.
        use crate::{
            instructions::Instruction,
            scheme::hal::{BatchedMainConstraintProver, MainConstraintJob, ProofInput},
            structs::ZKVMConstraintSystem,
        };
        use either::Either;

        let mut registered_css = ZKVMConstraintSystem::<E>::default();
        let registered_attention_config = registered_css
            .register_opcode_circuit::<TensorAttentionBlockReducedCoreInstruction<E>>();
        let registered_attention_name = TensorAttentionBlockReducedCoreInstruction::<E>::name();
        let registered_attention_cs = registered_css
            .get_cs(&registered_attention_name)
            .expect("registered attention core must exist");
        let attention_indices = steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                (step.insn.kind == InsnKind::ECALL
                    && step
                        .rs1()
                        .is_some_and(|op| op.value == <AttentionBlock as BlockSpec>::Syscall::CODE))
                .then_some(index)
            })
            .collect_vec();
        let mut registered_shard = ShardContext::default();
        registered_shard.syscall_witnesses = Arc::new(vm.tracer().syscall_witnesses().to_vec());
        // Recreate the deterministic provider so the registered assignment
        // cannot accidentally borrow state from the synthetic PCS controls.
        registered_shard.tensor_proof_context = Some(Arc::new(TensorProofContext::new(Arc::new(
            ceno_emul::tensor::DeterministicTileProvider::new(
                REGISTERED_TENSOR_ID,
                (0..7).map(|_| tile.clone()).collect(),
            )
            .unwrap(),
        ))));
        let ([registered_attention, registered_attention_structural], _) =
            TensorAttentionBlockReducedCoreInstruction::<E>::assign_instances(
                &registered_attention_config,
                &mut registered_shard,
                registered_attention_cs.num_witin(),
                registered_attention_cs.num_structural_witin(),
                steps,
                &attention_indices,
            )
            .expect("registered attention assignment");
        assert_eq!(registered_attention.num_instances(), 32);
        assert_eq!(registered_attention.height(), 32);

        let (_registered_mles, registered_pcs_data, registered_commit) =
            prover.commit_traces(BTreeMap::from([(7usize, registered_attention.clone())]));
        let mut main_transcript = BasicTranscript::<E>::new(b"miniature-registered-main");
        let main_challenges = [
            main_transcript.read_challenge().elements,
            main_transcript.read_challenge().elements,
        ];
        let (_main_sumcheck_proof, actual_main_results) = prover
            .prove_batched_main_constraints(
                vec![MainConstraintJob {
                    circuit_name: registered_attention_name.clone(),
                    circuit_idx: 7,
                    input: ProofInput {
                        // This is intentionally empty: the real GPU main
                        // prover must extract it from registered_pcs_data via
                        // witness_trace_idx, exactly as ZKVMProver does.
                        witness: Vec::new(),
                        structural_witness: Vec::new(),
                        fixed: Vec::new(),
                        pi: Vec::<Either<B, E>>::new(),
                        num_instances: [registered_attention.num_instances(), 0],
                        has_ecc_ops: false,
                    },
                    witness_trace_idx: Some(0),
                    num_witin: registered_attention_cs.num_witin(),
                    structural_rmm: Some(registered_attention_structural.clone()),
                    // The tensor core's arithmetic main constraints do not
                    // consume tower output claims.  A correctly sized zero
                    // point preserves the ordinary frontload routing without
                    // adding the tower/RV registry to this reproducer.
                    rt_tower: vec![E::ZERO; registered_attention.num_vars()],
                    main_out_evals: Vec::new(),
                    rotation: None,
                    matrix_claims: None,
                    ecc_proof: None,
                    challenges: main_challenges,
                    cs: registered_attention_cs,
                }],
                &registered_pcs_data,
                &mut main_transcript,
            )
            .expect("registered GPU main sumcheck must produce opening inputs");
        assert_eq!(actual_main_results.len(), 1);
        let (actual_points, actual_evals) = collect_main_constraint_openings(actual_main_results);
        assert_eq!(actual_points.len(), 1);
        assert_eq!(actual_evals.len(), 1);
        assert_eq!(actual_points[0].len(), registered_attention.num_vars());
        let expected_registered_evals = registered_attention
            .to_mles()
            .iter()
            .map(|mle| mle.evaluate(&actual_points[0]))
            .collect_vec();
        assert_eq!(
            actual_evals[0][0], expected_registered_evals,
            "registered main result must evaluate the committed padded trace view"
        );
        eprintln!(
            "[registered-main-pcs] circuit={} trace_idx=0 logical_range=0..{} padded_range=0..{} query_dim={} witness_mles={}",
            registered_attention_name,
            registered_attention.num_instances(),
            registered_attention.height(),
            actual_points[0].len(),
            actual_evals[0][0].len(),
        );
        let mut registered_open_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-main-open");
        let registered_opening_proof = prover.open(
            registered_pcs_data,
            None,
            actual_points.clone(),
            actual_evals.clone(),
            &mut registered_open_transcript,
        );
        let mut registered_verify_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-main-open");
        Pcs::batch_verify(
            &backend.vp,
            vec![(
                (registered_commit),
                vec![(
                    actual_points[0].len(),
                    (actual_points[0].clone(), expected_registered_evals),
                )],
            )],
            &registered_opening_proof,
            &mut registered_verify_transcript,
        )
        .expect("registered main-result GPU PCS opening must verify");
        eprintln!("[registered-main-pcs] root/opening verified=true");

        // Cross-chip increment: use the same unmodified GPU main-constraint
        // path for the two fused tensor cores plus the production K1024 tile
        // core.  This stays deliberately below the RV registry/tower layer,
        // but makes the trace-index -> committed-physical-trace ownership
        // explicit.  In particular the last domain has 31 logical rows in a
        // 32-row commitment, which is the new-chip MLE range/view boundary
        // implicated by the original RootMismatch report.
        let mut multi_css = ZKVMConstraintSystem::<E>::default();
        let multi_attention_config =
            multi_css.register_opcode_circuit::<TensorAttentionBlockReducedCoreInstruction<E>>();
        let multi_ffn_config =
            multi_css.register_opcode_circuit::<TensorFfnBlockReducedCoreInstruction<E>>();
        let _multi_tile_config =
            multi_css.register_opcode_circuit::<MiniatureTensorProductionTileInstruction<E>>();
        let multi_attention_name = TensorAttentionBlockReducedCoreInstruction::<E>::name();
        let multi_ffn_name = TensorFfnBlockReducedCoreInstruction::<E>::name();
        let multi_tile_name = MiniatureTensorProductionTileInstruction::<E>::name();
        let multi_attention_cs = multi_css
            .get_cs(&multi_attention_name)
            .expect("multi attention core must exist");
        let multi_ffn_cs = multi_css
            .get_cs(&multi_ffn_name)
            .expect("multi FFN core must exist");
        let multi_tile_cs = multi_css
            .get_cs(&multi_tile_name)
            .expect("multi K32 tile core must exist");
        let ffn_indices = steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                (step.insn.kind == InsnKind::ECALL
                    && step
                        .rs1()
                        .is_some_and(|op| op.value == <FfnBlock as BlockSpec>::Syscall::CODE))
                .then_some(index)
            })
            .collect_vec();
        let mut multi_shard = ShardContext::default();
        multi_shard.syscall_witnesses = Arc::new(vm.tracer().syscall_witnesses().to_vec());
        multi_shard.tensor_proof_context = Some(Arc::new(TensorProofContext::new(Arc::new(
            ceno_emul::tensor::DeterministicTileProvider::new(
                REGISTERED_TENSOR_ID,
                (0..7).map(|_| tile.clone()).collect(),
            )
            .unwrap(),
        ))));
        let ([multi_attention, multi_attention_structural], _) =
            TensorAttentionBlockReducedCoreInstruction::<E>::assign_instances(
                &multi_attention_config,
                &mut multi_shard,
                multi_attention_cs.num_witin(),
                multi_attention_cs.num_structural_witin(),
                steps,
                &attention_indices,
            )
            .expect("multi attention assignment");
        let ([multi_ffn, multi_ffn_structural], _) =
            TensorFfnBlockReducedCoreInstruction::<E>::assign_instances(
                &multi_ffn_config,
                &mut multi_shard,
                multi_ffn_cs.num_witin(),
                multi_ffn_cs.num_structural_witin(),
                steps,
                &ffn_indices,
            )
            .expect("multi FFN assignment");
        assert_eq!(multi_attention.num_instances(), 32);
        assert_eq!(multi_ffn.num_instances(), 32);
        assert_eq!(k32.num_instances(), 31);
        assert_eq!(k32.height(), 32);
        let mut multi_tile_structural = RowMajorMatrix::new(
            k32.num_instances(),
            multi_tile_cs.num_structural_witin().max(1),
            InstancePaddingStrategy::Default,
        );
        if multi_tile_cs.num_structural_witin() != 0 {
            for row in multi_tile_structural.iter_mut() {
                *row.last_mut().expect("nonempty structural padding row") = B::ONE;
            }
        }

        // BTreeMap order is the physical trace order extracted by the GPU
        // backend.  Keep those source IDs intentionally sparse so an index is
        // never mistaken for a circuit registration ordinal.
        let multi_trace_ids = [11usize, 47usize, 89usize];
        let multi_matrices = [&multi_attention, &multi_ffn, &k32];
        let multi_names = [
            multi_attention_name.as_str(),
            multi_ffn_name.as_str(),
            multi_tile_name.as_str(),
        ];
        let (_multi_mles, multi_pcs_data, multi_commit) = prover.commit_traces(BTreeMap::from([
            (multi_trace_ids[0], multi_attention.clone()),
            (multi_trace_ids[1], multi_ffn.clone()),
            (multi_trace_ids[2], k32.clone()),
        ]));
        for (trace_idx, ((name, matrix), source_id)) in multi_names
            .iter()
            .zip(multi_matrices)
            .zip(multi_trace_ids)
            .enumerate()
        {
            eprintln!(
                "[registered-multichip-pcs] trace_idx={trace_idx} source_id={source_id} circuit={name} logical_range=0..{} physical_range=0..{} columns={}",
                matrix.num_instances(),
                matrix.height(),
                matrix.width(),
            );
        }
        let mut multi_main_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-multichip-main");
        let multi_challenges = [
            multi_main_transcript.read_challenge().elements,
            multi_main_transcript.read_challenge().elements,
        ];
        let mk_job = |circuit_name,
                      circuit_idx,
                      num_instances,
                      witness_trace_idx,
                      num_witin,
                      structural_rmm,
                      rt_tower,
                      cs| MainConstraintJob {
            circuit_name,
            circuit_idx,
            input: ProofInput {
                witness: Vec::new(),
                structural_witness: Vec::new(),
                fixed: Vec::new(),
                pi: Vec::<Either<B, E>>::new(),
                num_instances: [num_instances, 0],
                has_ecc_ops: false,
            },
            witness_trace_idx: Some(witness_trace_idx),
            num_witin,
            structural_rmm: Some(structural_rmm),
            rt_tower,
            main_out_evals: Vec::new(),
            rotation: None,
            matrix_claims: None,
            ecc_proof: None,
            challenges: multi_challenges,
            cs,
        };
        let (_multi_main_sumcheck, multi_main_results) = prover
            .prove_batched_main_constraints(
                vec![
                    mk_job(
                        multi_attention_name.clone(),
                        401,
                        multi_attention.num_instances(),
                        0,
                        multi_attention_cs.num_witin(),
                        multi_attention_structural.clone(),
                        vec![E::ZERO; multi_attention.num_vars()],
                        multi_attention_cs,
                    ),
                    mk_job(
                        multi_ffn_name.clone(),
                        409,
                        multi_ffn.num_instances(),
                        1,
                        multi_ffn_cs.num_witin(),
                        multi_ffn_structural.clone(),
                        vec![E::ZERO; multi_ffn.num_vars()],
                        multi_ffn_cs,
                    ),
                    mk_job(
                        multi_tile_name.clone(),
                        419,
                        k32.num_instances(),
                        2,
                        multi_tile_cs.num_witin(),
                        multi_tile_structural.clone(),
                        vec![E::ZERO; k32.num_vars()],
                        multi_tile_cs,
                    ),
                ],
                &multi_pcs_data,
                &mut multi_main_transcript,
            )
            .expect("registered multichip GPU main sumcheck must produce opening inputs");
        assert_eq!(multi_main_results.len(), 3);
        let (multi_points, multi_evals) = collect_main_constraint_openings(multi_main_results);
        assert_eq!(multi_points.len(), 3);
        assert_eq!(multi_evals.len(), 3);
        let expected_multi_evals = multi_matrices
            .iter()
            .zip(&multi_points)
            .map(|(matrix, point)| {
                matrix
                    .to_mles()
                    .iter()
                    .map(|mle| mle.evaluate(point))
                    .collect_vec()
            })
            .collect_vec();
        for (idx, ((matrix, point), (evals, expected))) in multi_matrices
            .iter()
            .zip(&multi_points)
            .zip(multi_evals.iter().zip(&expected_multi_evals))
            .enumerate()
        {
            assert_eq!(point.len(), matrix.num_vars());
            assert_eq!(
                evals[0], *expected,
                "multi trace {idx} must retain its committed MLE view"
            );
            eprintln!(
                "[registered-multichip-pcs] result_idx={idx} circuit={} query_dim={} witness_mles={} fixed_mles={}",
                multi_names[idx],
                point.len(),
                evals[0].len(),
                evals[1].len(),
            );
        }
        let mut multi_open_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-multichip-open");
        let multi_opening_proof = prover.open(
            multi_pcs_data,
            None,
            multi_points.clone(),
            multi_evals,
            &mut multi_open_transcript,
        );
        let mut multi_verify_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-multichip-open");
        Pcs::batch_verify(
            &backend.vp,
            vec![(
                multi_commit,
                multi_points
                    .iter()
                    .zip(&expected_multi_evals)
                    .map(|(point, evals)| (point.len(), (point.clone(), evals.clone())))
                    .collect_vec(),
            )],
            &multi_opening_proof,
            &mut multi_verify_transcript,
        )
        .expect("registered multichip GPU PCS opening must verify");
        eprintln!("[registered-multichip-pcs] root/opening verified=true");

        // Next production boundary: unlike the preceding compact jobs, build
        // the real tower-facing witness from the committed GPU trace, run the
        // tower relation, and use its derived `rt_main` in the actual batched
        // main call.  Keeping this to one existing attention core isolates
        // tower/task routing without introducing the RV registry.
        use crate::scheme::{
            gpu::{
                extract_witness_mles_for_trace, prove_tower_relation_impl,
                transport_structural_witness_to_gpu,
            },
            utils::{WitnessBuildStage, build_main_witness},
        };
        use gkr_iop::gpu::{GpuBackend, GpuProver};

        let (_tower_mles, tower_pcs_data, tower_commit) =
            prover.commit_traces(BTreeMap::from([(211usize, registered_attention.clone())]));
        let tower_num_vars = registered_attention.num_vars();
        let mut tower_transcript = BasicTranscript::<E>::new(b"miniature-registered-tower");
        let tower_challenges = [
            tower_transcript.read_challenge().elements,
            tower_transcript.read_challenge().elements,
        ];
        let tower_input = ProofInput {
            witness: extract_witness_mles_for_trace::<E, Pcs>(
                &tower_pcs_data,
                0,
                registered_attention_cs.num_witin(),
                tower_num_vars,
            ),
            structural_witness: transport_structural_witness_to_gpu::<E>(
                &registered_attention_structural,
                registered_attention_cs.num_structural_witin(),
                tower_num_vars,
            ),
            fixed: Vec::new(),
            pi: Vec::<Either<B, E>>::new(),
            num_instances: [registered_attention.num_instances(), 0],
            has_ecc_ops: false,
        };
        let tower_records =
            build_main_witness::<E, Pcs, GpuBackend<E, Pcs>, GpuProver<GpuBackend<E, Pcs>>>(
                registered_attention_cs,
                &tower_input,
                &tower_challenges,
                WitnessBuildStage::Tower,
            );
        let tower_hal = gkr_iop::gpu::get_cuda_hal().expect("CUDA HAL for compact tower");
        let (tower_point, _tower_proof, _tower_lk, _tower_writes, _tower_reads) =
            prove_tower_relation_impl::<E, Pcs>(
                registered_attention_cs,
                &tower_input,
                &tower_records,
                &tower_challenges,
                &mut tower_transcript,
                &tower_hal,
            )
            .expect("compact registered tower must produce a main point");
        assert!(tower_point.len() >= tower_num_vars);
        let tower_rt_main = tower_point[tower_point.len() - tower_num_vars..].to_vec();
        eprintln!(
            "[registered-tower-pcs] circuit={} trace_idx=0 logical_range=0..{} physical_range=0..{} tower_point_dim={} main_point_dim={} witness_mles={} structural_mles={}",
            registered_attention_name,
            registered_attention.num_instances(),
            registered_attention.height(),
            tower_point.len(),
            tower_rt_main.len(),
            tower_input.witness.len(),
            tower_input.structural_witness.len(),
        );
        drop(tower_records);
        drop(tower_input);
        let (_tower_main_sumcheck, tower_main_results) = prover
            .prove_batched_main_constraints(
                vec![MainConstraintJob {
                    circuit_name: registered_attention_name.clone(),
                    circuit_idx: 503,
                    input: ProofInput {
                        witness: Vec::new(),
                        structural_witness: Vec::new(),
                        fixed: Vec::new(),
                        pi: Vec::<Either<B, E>>::new(),
                        num_instances: [registered_attention.num_instances(), 0],
                        has_ecc_ops: false,
                    },
                    witness_trace_idx: Some(0),
                    num_witin: registered_attention_cs.num_witin(),
                    structural_rmm: Some(registered_attention_structural),
                    rt_tower: tower_rt_main,
                    main_out_evals: Vec::new(),
                    rotation: None,
                    matrix_claims: None,
                    ecc_proof: None,
                    challenges: tower_challenges,
                    cs: registered_attention_cs,
                }],
                &tower_pcs_data,
                &mut tower_transcript,
            )
            .expect("tower-derived main job must produce opening inputs");
        let (tower_points, tower_evals) = collect_main_constraint_openings(tower_main_results);
        assert_eq!(tower_points.len(), 1);
        let tower_expected_evals = registered_attention
            .to_mles()
            .iter()
            .map(|mle| mle.evaluate(&tower_points[0]))
            .collect_vec();
        assert_eq!(tower_evals[0][0], tower_expected_evals);
        let mut tower_open_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-tower-open");
        let tower_opening = prover.open(
            tower_pcs_data,
            None,
            tower_points.clone(),
            tower_evals,
            &mut tower_open_transcript,
        );
        let mut tower_verify_transcript =
            BasicTranscript::<E>::new(b"miniature-registered-tower-open");
        Pcs::batch_verify(
            &backend.vp,
            vec![(
                tower_commit,
                vec![(
                    tower_points[0].len(),
                    (tower_points[0].clone(), tower_expected_evals),
                )],
            )],
            &tower_opening,
            &mut tower_verify_transcript,
        )
        .expect("tower-derived registered GPU PCS opening must verify");
        eprintln!("[registered-tower-pcs] root/opening verified=true");

        // Batch the same actual tower -> main transition across every compact
        // domain.  This is the last no-RV-registry increment before shard and
        // runtime orchestration: heterogeneous chip order, widths, and the
        // K32 31/32 logical/physical split all reach the production main/open
        // seam with tower-derived points.
        let (_mixed_tower_mles, mixed_tower_pcs_data, mixed_tower_commit) =
            prover.commit_traces(BTreeMap::from([
                (311usize, multi_attention.clone()),
                (347usize, multi_ffn.clone()),
                (389usize, k32.clone()),
            ]));
        let mut mixed_tower_challenge_transcript =
            BasicTranscript::<E>::new(b"miniature-mixed-tower-challenges");
        let mixed_tower_challenges = [
            mixed_tower_challenge_transcript.read_challenge().elements,
            mixed_tower_challenge_transcript.read_challenge().elements,
        ];
        let derive_mixed_tower_point =
            |trace_idx: usize,
             circuit: &str,
             matrix: &RowMajorMatrix<B>,
             cs: &crate::structs::ComposedConstrainSystem<E>,
             structural: &RowMajorMatrix<B>| {
                let num_vars = matrix.num_vars();
                let input = ProofInput {
                    witness: extract_witness_mles_for_trace::<E, Pcs>(
                        &mixed_tower_pcs_data,
                        trace_idx,
                        cs.num_witin(),
                        num_vars,
                    ),
                    structural_witness: transport_structural_witness_to_gpu::<E>(
                        structural,
                        cs.num_structural_witin(),
                        num_vars,
                    ),
                    fixed: Vec::new(),
                    pi: Vec::<Either<B, E>>::new(),
                    num_instances: [matrix.num_instances(), 0],
                    has_ecc_ops: false,
                };
                let records = build_main_witness::<
                    E,
                    Pcs,
                    GpuBackend<E, Pcs>,
                    GpuProver<GpuBackend<E, Pcs>>,
                >(
                    cs,
                    &input,
                    &mixed_tower_challenges,
                    WitnessBuildStage::Tower,
                );
                let mut transcript = BasicTranscript::<E>::new(b"miniature-mixed-tower");
                let (tower_point, _proof, _lk, _writes, _reads) =
                    prove_tower_relation_impl::<E, Pcs>(
                        cs,
                        &input,
                        &records,
                        &mixed_tower_challenges,
                        &mut transcript,
                        &tower_hal,
                    )
                    .unwrap_or_else(|err| panic!("mixed tower failed for {circuit}: {err:?}"));
                assert!(tower_point.len() >= num_vars);
                let main_point = tower_point[tower_point.len() - num_vars..].to_vec();
                eprintln!(
                    "[registered-mixed-tower-pcs] trace_idx={trace_idx} circuit={circuit} logical_range=0..{} physical_range=0..{} tower_point_dim={} main_point_dim={} witness_mles={} structural_mles={}",
                    matrix.num_instances(),
                    matrix.height(),
                    tower_point.len(),
                    main_point.len(),
                    input.witness.len(),
                    input.structural_witness.len(),
                );
                drop(records);
                drop(input);
                main_point
            };
        let mixed_tower_rt_main = vec![
            derive_mixed_tower_point(
                0,
                &multi_attention_name,
                &multi_attention,
                multi_attention_cs,
                &multi_attention_structural,
            ),
            derive_mixed_tower_point(
                1,
                &multi_ffn_name,
                &multi_ffn,
                multi_ffn_cs,
                &multi_ffn_structural,
            ),
            derive_mixed_tower_point(
                2,
                &multi_tile_name,
                &k32,
                multi_tile_cs,
                &multi_tile_structural,
            ),
        ];
        let mut mixed_tower_main_transcript =
            BasicTranscript::<E>::new(b"miniature-mixed-tower-main");
        let (_mixed_tower_main_sumcheck, mixed_tower_main_results) = prover
            .prove_batched_main_constraints(
                vec![
                    mk_job(
                        multi_attention_name.clone(),
                        601,
                        multi_attention.num_instances(),
                        0,
                        multi_attention_cs.num_witin(),
                        multi_attention_structural,
                        mixed_tower_rt_main[0].clone(),
                        multi_attention_cs,
                    ),
                    mk_job(
                        multi_ffn_name.clone(),
                        607,
                        multi_ffn.num_instances(),
                        1,
                        multi_ffn_cs.num_witin(),
                        multi_ffn_structural,
                        mixed_tower_rt_main[1].clone(),
                        multi_ffn_cs,
                    ),
                    mk_job(
                        multi_tile_name.clone(),
                        613,
                        k32.num_instances(),
                        2,
                        multi_tile_cs.num_witin(),
                        multi_tile_structural,
                        mixed_tower_rt_main[2].clone(),
                        multi_tile_cs,
                    ),
                ],
                &mixed_tower_pcs_data,
                &mut mixed_tower_main_transcript,
            )
            .expect("mixed tower-derived main jobs must produce opening inputs");
        let (mixed_tower_points, mixed_tower_evals) =
            collect_main_constraint_openings(mixed_tower_main_results);
        assert_eq!(mixed_tower_points.len(), 3);
        let mixed_tower_expected = multi_matrices
            .iter()
            .zip(&mixed_tower_points)
            .map(|(matrix, point)| {
                matrix
                    .to_mles()
                    .iter()
                    .map(|mle| mle.evaluate(point))
                    .collect_vec()
            })
            .collect_vec();
        for idx in 0..3 {
            assert_eq!(mixed_tower_evals[idx][0], mixed_tower_expected[idx]);
        }
        let mut mixed_tower_open_transcript =
            BasicTranscript::<E>::new(b"miniature-mixed-tower-open");
        let mixed_tower_opening = prover.open(
            mixed_tower_pcs_data,
            None,
            mixed_tower_points.clone(),
            mixed_tower_evals,
            &mut mixed_tower_open_transcript,
        );
        let mut mixed_tower_verify_transcript =
            BasicTranscript::<E>::new(b"miniature-mixed-tower-open");
        Pcs::batch_verify(
            &backend.vp,
            vec![(
                mixed_tower_commit,
                mixed_tower_points
                    .iter()
                    .zip(&mixed_tower_expected)
                    .map(|(point, evals)| (point.len(), (point.clone(), evals.clone())))
                    .collect_vec(),
            )],
            &mixed_tower_opening,
            &mut mixed_tower_verify_transcript,
        )
        .expect("mixed tower-derived registered GPU PCS opening must verify");
        eprintln!("[registered-mixed-tower-pcs] root/opening verified=true");
    }
}
