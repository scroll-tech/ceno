//! Row-oriented RAM/Tensor-space boundary for one exact production layer.
//!
//! Hidden input and output are two deterministic 2^23-row artifacts. They are
//! circuits inside one atomic shard, never segment or shard cuts.
//! The descriptor ECALL anchors the chain; each row owns exactly one RAM and
//! one Tensor-space relation.

use std::{array, marker::PhantomData};

use ceno_emul::{
    Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorProductionExportEndV2Spec, TensorProductionFullLayerV2Spec,
    TensorProductionImportBeginV2Spec, WORD_SIZE, WriteOp,
};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::Itertools;
use multilinear_extensions::{Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitIn};
use p3::field::PrimeCharacteristicRing;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

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
    structs::{CustomRWTag, ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value as UIntValue,
    witness::LkMultiplicity,
};

const PART_WORDS: usize = 1 << 23;
const BOUNDARY_STATE_VERSION: u32 = 8;
const TENSOR_SPACE_VERSION: u32 = 1;
const FULL_LAYER_CALL_VERSION: u32 = 9;
const DESC_WORDS: usize = 8;
const META_WORDS: usize = 4;
const HANDLE_WORDS: usize = 4;

pub type TensorProductionImportAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 0>;
pub type TensorProductionFullLayerAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 1>;
pub type TensorProductionExportAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 2>;

pub struct TensorProductionAnchorInstruction<E, const KIND: usize>(PhantomData<E>);

#[derive(Debug)]
struct AnchorMemory<E: ExtensionField> {
    before: UInt<E>,
    after: UInt<E>,
    memory: WriteMEM,
}

#[derive(Debug)]
pub struct TensorProductionAnchorConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    desc: [AnchorMemory<E>; DESC_WORDS],
    meta: [AnchorMemory<E>; META_WORDS],
    input_handle: Option<[AnchorMemory<E>; HANDLE_WORDS]>,
    output_handle: Option<[AnchorMemory<E>; HANDLE_WORDS]>,
    import_cycle: WitIn,
    key_shard_id: WitIn,
    key_local_shard_cycle: WitIn,
    key_ordinal: WitIn,
}

fn production_spec<const KIND: usize>() -> (u32, &'static str) {
    match KIND {
        0 => (
            TensorProductionImportBeginV2Spec::CODE,
            "TensorProductionImportBeginAnchor",
        ),
        1 => (
            TensorProductionFullLayerV2Spec::CODE,
            "TensorProductionFullLayerAnchor",
        ),
        2 => (
            TensorProductionExportEndV2Spec::CODE,
            "TensorProductionExportEndAnchor",
        ),
        _ => panic!("invalid production anchor kind"),
    }
}

fn anchor_memory<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    address: Expression<E>,
    cycle: WitIn,
    write: bool,
) -> Result<AnchorMemory<E>, ZKVMError> {
    let before = UInt::new_unchecked(|| format!("{name}_before"), cb)?;
    let after = if write {
        UInt::new(|| format!("{name}_after"), cb)?
    } else {
        UInt::new_unchecked(|| format!("{name}_after"), cb)?
    };
    if !write {
        for (before, after) in before.expr().into_iter().zip(after.expr()) {
            cb.require_equal(|| format!("{name}_read"), before, after)?;
        }
    }
    let memory = WriteMEM::construct_circuit(
        cb,
        address,
        before.memory_expr(),
        after.memory_expr(),
        cycle,
    )?;
    Ok(AnchorMemory {
        before,
        after,
        memory,
    })
}

fn anchor_word<E: ExtensionField>(memory: &AnchorMemory<E>, after: bool) -> Expression<E> {
    if after {
        memory.after.value()
    } else {
        memory.before.value()
    }
}

fn anchor_memory_array<E: ExtensionField, const N: usize>(
    mut make: impl FnMut(usize) -> Result<AnchorMemory<E>, ZKVMError>,
) -> Result<[AnchorMemory<E>; N], ZKVMError> {
    (0..N)
        .map(&mut make)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| ZKVMError::InvalidWitness("production anchor array width".into()))
}

fn production_full_layer_call_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    input: &[Expression<E>; HANDLE_WORDS],
    output: &[Expression<E>; HANDLE_WORDS],
    profile: Expression<E>,
    layer: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(FULL_LAYER_CALL_VERSION).expr(),
        import_cycle,
        input[0].clone(),
        input[1].clone(),
        input[2].clone(),
        output[0].clone(),
        output[1].clone(),
        output[2].clone(),
        profile,
        layer,
    ]
}

pub type TensorProductionBoundaryHiddenInputInstruction<E> =
    TensorProductionBoundaryInstruction<E, 0>;
pub type TensorProductionBoundaryHiddenOutputInstruction<E> =
    TensorProductionBoundaryInstruction<E, 1>;

pub struct TensorProductionBoundaryInstruction<E, const PART: usize>(PhantomData<E>);

#[derive(Debug)]
pub struct TensorProductionBoundaryConfig<E: ExtensionField> {
    import_cycle: WitIn,
    boundary_cycle: WitIn,
    tensor_id_lo: WitIn,
    tensor_id_hi: WitIn,
    tensor_version: WitIn,
    base_byte_address: WitIn,
    local_index: WitIn,
    physical_local_index: StructuralWitIn,
    eq_rotation_left: StructuralWitIn,
    eq_rotation_right: StructuralWitIn,
    eq_rotation: StructuralWitIn,
    selector: StructuralWitIn,
    local_index_bits: [WitIn; 23],
    signed_value: WitIn,
    sign: WitIn,
    high_magnitude_bits: [WitIn; 15],
    before: UInt<E>,
    after: UInt<E>,
    memory: WriteMEM,
}

impl<E: ExtensionField> TensorProductionBoundaryConfig<E> {
    pub(crate) fn structural_column_ids(&self) -> [usize; 5] {
        [
            self.physical_local_index.id as usize,
            self.eq_rotation_left.id as usize,
            self.eq_rotation_right.id as usize,
            self.eq_rotation.id as usize,
            self.selector.id as usize,
        ]
    }

    pub(crate) fn validate_device_layout(
        &self,
        num_structural_witin: usize,
    ) -> Result<(), ZKVMError> {
        let expected = [0, 1, 2, 3, 4];
        let actual = self.structural_column_ids();
        if num_structural_witin != expected.len() || actual != expected {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "production boundary VK structural order changed: width={num_structural_witin}, ids={actual:?}"
                )
                .into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionBoundaryColumnMap, ZKVMError> {
        use ceno_gpu::common::witgen::ProductionAttentionBoundaryColumnMap;

        self.validate_device_layout(num_structural_witin)?;
        let before = self.before.wits_in().ok_or_else(|| {
            ZKVMError::InvalidWitness(
                "production boundary before limbs are not witness cells".into(),
            )
        })?;
        let after = self.after.wits_in().ok_or_else(|| {
            ZKVMError::InvalidWitness(
                "production boundary after limbs are not witness cells".into(),
            )
        })?;
        if before.len() != 2
            || after.len() != 2
            || self.memory.lt_cfg.0.max_bits != 29
            || self.memory.lt_cfg.0.diff.len() != 2
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary UInt/WriteMEM layout changed".into(),
            ));
        }
        let id = |cell: WitIn| cell.id as u32;
        let structural_id = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionBoundaryColumnMap {
            import_cycle: id(self.import_cycle),
            boundary_cycle: id(self.boundary_cycle),
            tensor_id_lo: id(self.tensor_id_lo),
            tensor_id_hi: id(self.tensor_id_hi),
            tensor_version: id(self.tensor_version),
            base_byte_address: id(self.base_byte_address),
            local_index: id(self.local_index),
            local_index_bits: self.local_index_bits.map(id),
            signed_value: id(self.signed_value),
            sign: id(self.sign),
            high_magnitude_bits: self.high_magnitude_bits.map(id),
            before_limbs: [id(before[0]), id(before[1])],
            after_limbs: [id(after[0]), id(after[1])],
            prev_ts: id(self.memory.prev_ts),
            lt_diff: [
                id(self.memory.lt_cfg.0.diff[0]),
                id(self.memory.lt_cfg.0.diff[1]),
            ],
            physical_local_index: structural_id(self.physical_local_index),
            prefix: structural_id(self.selector),
            num_witin: u32::try_from(num_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production boundary witness width overflow".into())
            })?,
            num_structural_witin: u32::try_from(num_structural_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production boundary structural width overflow".into())
            })?,
        };
        let mut witin_ids = map
            .local_index_bits
            .iter()
            .chain(map.high_magnitude_bits.iter())
            .chain(map.before_limbs.iter())
            .chain(map.after_limbs.iter())
            .chain(map.lt_diff.iter())
            .copied()
            .chain([
                map.import_cycle,
                map.boundary_cycle,
                map.tensor_id_lo,
                map.tensor_id_hi,
                map.tensor_version,
                map.base_byte_address,
                map.local_index,
                map.signed_value,
                map.sign,
                map.prev_ts,
            ])
            .collect_vec();
        witin_ids.sort_unstable();
        if num_witin != 54
            || witin_ids != (0..54).collect_vec()
            || map.physical_local_index as usize >= num_structural_witin
            || map.prefix as usize >= num_structural_witin
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

/// Host-side metadata for deterministic device replay. It contains no matrix
/// values and cannot be used to materialize the 2^23-row witness on CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TensorProductionBoundaryReplayDescriptor {
    pub part: usize,
    pub step_index: StepIndex,
    pub syscall_cycle: u64,
    pub import_cycle: u64,
    pub tensor_id: u64,
    pub tensor_version: u32,
    pub base_byte_address: u32,
    pub mem_ops_start: usize,
    pub rows: usize,
}

impl TensorProductionBoundaryReplayDescriptor {
    fn validate(self, syscall: &ceno_emul::SyscallWitness) -> Result<Self, ZKVMError> {
        if self.rows != PART_WORDS {
            return Err(ZKVMError::InvalidWitness(
                "production boundary replay row count changed".into(),
            ));
        }
        let end = self.mem_ops_start.checked_add(self.rows).ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary RAM range overflow".into())
        })?;
        let ops = syscall
            .mem_ops
            .get(self.mem_ops_start..end)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("production boundary RAM range is incomplete".into())
            })?;
        let first = ops.first().expect("production boundary is non-empty");
        let last = ops.last().expect("production boundary is non-empty");
        let expected_last = self
            .base_byte_address
            .checked_add(((self.rows - 1) * WORD_SIZE) as u32)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("production boundary address range overflow".into())
            })?;
        if first.addr.baddr().0 != self.base_byte_address || last.addr.baddr().0 != expected_last {
            return Err(ZKVMError::InvalidWitness(
                "production boundary RAM endpoints are not canonical".into(),
            ));
        }
        Ok(self)
    }
}

pub fn collect_production_boundary_replay_descriptors(
    shard_ctx: &ShardContext,
    steps: &[StepRecord],
    indices: &[StepIndex],
) -> Result<[TensorProductionBoundaryReplayDescriptor; 2], ZKVMError> {
    let mut descriptors = Vec::with_capacity(2);
    for &index in indices {
        let step = &steps[index];
        let syscall = step.syscall(&shard_ctx.syscall_witnesses).ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary syscall missing".into())
        })?;
        let boundary = syscall.tensor_production_boundary.ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary descriptor missing".into())
        })?;
        if boundary.kind == ceno_emul::tensor::TensorProductionBoundaryKind::Import {
            {
                let part = 0;
                let mem_ops_start = boundary.value_ops_start;
                let first = syscall.mem_ops.get(mem_ops_start).ok_or_else(|| {
                    ZKVMError::InvalidWitness("production import boundary RAM start missing".into())
                })?;
                descriptors.push(
                    TensorProductionBoundaryReplayDescriptor {
                        part,
                        step_index: index,
                        syscall_cycle: shard_ctx.aligned_current_ts(step.cycle()),
                        import_cycle: shard_ctx.aligned_current_ts(boundary.import_cycle),
                        tensor_id: boundary.tensor_id,
                        tensor_version: boundary.version,
                        base_byte_address: first.addr.baddr().0,
                        mem_ops_start,
                        rows: PART_WORDS,
                    }
                    .validate(syscall)?,
                );
            }
        } else if boundary.kind == ceno_emul::tensor::TensorProductionBoundaryKind::Export {
            let first = syscall
                .mem_ops
                .get(boundary.value_ops_start)
                .ok_or_else(|| {
                    ZKVMError::InvalidWitness("production export boundary RAM start missing".into())
                })?;
            descriptors.push(
                TensorProductionBoundaryReplayDescriptor {
                    part: 1,
                    step_index: index,
                    syscall_cycle: shard_ctx.aligned_current_ts(step.cycle()),
                    import_cycle: shard_ctx.aligned_current_ts(boundary.import_cycle),
                    tensor_id: boundary.tensor_id,
                    tensor_version: boundary.version,
                    base_byte_address: first.addr.baddr().0,
                    mem_ops_start: boundary.value_ops_start,
                    rows: PART_WORDS,
                }
                .validate(syscall)?,
            );
        } else {
            return Err(ZKVMError::InvalidWitness(
                "production boundary row count changed".into(),
            ));
        }
    }
    descriptors.sort_unstable_by_key(|descriptor| descriptor.part);
    let descriptors: [TensorProductionBoundaryReplayDescriptor; 2] = descriptors
        .try_into()
        .map_err(|_| ZKVMError::InvalidWitness("production boundary cardinality".into()))?;
    for (part, descriptor) in descriptors.iter().enumerate() {
        if descriptor.part != part || descriptor.rows != PART_WORDS {
            return Err(ZKVMError::InvalidWitness(
                "production boundary partition order changed".into(),
            ));
        }
    }
    if descriptors[1].import_cycle != descriptors[0].import_cycle {
        return Err(ZKVMError::InvalidWitness(
            "production hidden output belongs to a different atomic segment".into(),
        ));
    }
    Ok(descriptors)
}

fn tensor_space_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    tensor_id_lo: Expression<E>,
    tensor_id_hi: Expression<E>,
    version: Expression<E>,
    index: Expression<E>,
    value: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(TENSOR_SPACE_VERSION).expr(),
        import_cycle,
        tensor_id_lo,
        tensor_id_hi,
        version,
        index,
        value,
    ]
}

fn boundary_state_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    tensor_id_lo: Expression<E>,
    tensor_id_hi: Expression<E>,
    version: Expression<E>,
    part: usize,
    base_byte_address: Expression<E>,
    index: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(BOUNDARY_STATE_VERSION).expr(),
        import_cycle,
        tensor_id_lo,
        tensor_id_hi,
        version,
        E::BaseField::from_usize(part).expr(),
        base_byte_address,
        index,
    ]
}

fn selected_mem_indices<const KIND: usize>() -> Vec<usize> {
    match KIND {
        0 => (0..DESC_WORDS)
            .chain(DESC_WORDS..DESC_WORDS + META_WORDS)
            .chain(
                DESC_WORDS + META_WORDS + ceno_emul::tensor::production_attention::HIDDEN_WORDS
                    ..DESC_WORDS
                        + META_WORDS
                        + ceno_emul::tensor::production_attention::HIDDEN_WORDS
                        + HANDLE_WORDS,
            )
            .collect(),
        1 => (0..DESC_WORDS + HANDLE_WORDS + META_WORDS + HANDLE_WORDS).collect(),
        2 => (0..DESC_WORDS + HANDLE_WORDS + META_WORDS).collect(),
        _ => panic!("invalid production anchor kind"),
    }
}

impl<E: ExtensionField, const KIND: usize> Instruction<E>
    for TensorProductionAnchorInstruction<E, KIND>
{
    type InstructionConfig = TensorProductionAnchorConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        production_spec::<KIND>().1.into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        assert!(KIND < 3, "invalid production anchor kind");
        let (code, _) = production_spec::<KIND>();
        let vm_state = StateInOut::construct_circuit(cb, false)?;
        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![code & LIMB_MASK, (code >> LIMB_BITS) & LIMB_MASK])
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

        let byte_offset = |word: usize| E::BaseField::from_u32((word * WORD_SIZE) as u32).expr();
        let desc = anchor_memory_array(|word| {
            anchor_memory(
                cb,
                &format!("production_anchor_desc_{word}"),
                ptr.expr_unaligned() + byte_offset(word),
                vm_state.ts,
                false,
            )
        })?;
        let desc_before = |word: usize| anchor_word(&desc[word], false);
        cb.require_equal(
            || "production_anchor_abi",
            desc_before(0),
            E::BaseField::from_u32(ceno_emul::tensor::TENSOR_ABI_V2).expr(),
        )?;
        cb.require_equal(
            || "production_anchor_flags",
            desc_before(1),
            E::BaseField::ZERO.expr(),
        )?;
        cb.require_equal(
            || "production_anchor_reserved",
            desc_before(7),
            E::BaseField::ZERO.expr(),
        )?;
        let meta_ptr = desc_before(if KIND == 2 { 5 } else { 4 });
        let meta = anchor_memory_array(|word| {
            anchor_memory(
                cb,
                &format!("production_anchor_meta_{word}"),
                meta_ptr.clone() + byte_offset(word),
                vm_state.ts,
                false,
            )
        })?;
        let input_handle = if KIND == 0 {
            None
        } else {
            Some(anchor_memory_array(|word| {
                anchor_memory(
                    cb,
                    &format!("production_anchor_input_handle_{word}"),
                    desc_before(2) + byte_offset(word),
                    vm_state.ts,
                    false,
                )
            })?)
        };
        let output_handle = if KIND == 2 {
            None
        } else {
            Some(anchor_memory_array(|word| {
                let pointer = desc_before(if KIND == 0 { 6 } else { 3 });
                anchor_memory(
                    cb,
                    &format!("production_anchor_output_handle_{word}"),
                    pointer + byte_offset(word),
                    vm_state.ts,
                    true,
                )
            })?)
        };
        let import_cycle = cb.create_witin(|| "production_anchor_import_cycle");
        if KIND == 0 {
            cb.require_equal(
                || "production_anchor_import_cycle",
                import_cycle.expr(),
                vm_state.ts.expr(),
            )?;
        }
        let key_shard_id = cb.create_witin(|| "production_anchor_key_shard_id");
        let key_local_shard_cycle = cb.create_witin(|| "production_anchor_key_local_shard_cycle");
        let key_ordinal = cb.create_witin(|| "production_anchor_key_ordinal");
        cb.require_equal(
            || "production_anchor_key_cycle",
            key_local_shard_cycle.expr(),
            vm_state.ts.expr(),
        )?;
        cb.require_equal(
            || "production_anchor_key_ordinal_zero",
            key_ordinal.expr(),
            E::BaseField::ZERO.expr(),
        )?;

        let handle_values = |memory: &[AnchorMemory<E>; HANDLE_WORDS], after: bool| {
            array::from_fn(|word| anchor_word(&memory[word], after))
        };
        let input_values = input_handle
            .as_ref()
            .map(|handle| handle_values(handle, false));
        let output_values = output_handle
            .as_ref()
            .map(|handle| handle_values(handle, true));
        if KIND == 0 {
            let output_values = output_values.as_ref().expect("import output handle");
            cb.require_equal(
                || "production_import_hidden_words",
                desc_before(3),
                E::BaseField::from_usize(ceno_emul::tensor::production_attention::HIDDEN_WORDS)
                    .expr(),
            )?;
            cb.require_equal(
                || "production_import_meta_words",
                desc_before(5),
                E::BaseField::from_usize(META_WORDS).expr(),
            )?;
            cb.write_record(
                || "production_boundary_hidden_input_start",
                RAMType::Custom,
                boundary_state_record(
                    import_cycle.expr(),
                    output_values[0].clone(),
                    output_values[1].clone(),
                    output_values[2].clone(),
                    0,
                    desc_before(2),
                    E::BaseField::ZERO.expr(),
                ),
            )?;
        } else if KIND == 1 {
            let input_values = input_values.as_ref().expect("full-layer input handle");
            let output_values = output_values.as_ref().expect("full-layer output handle");
            cb.require_equal(
                || "production_full_layer_profile",
                desc_before(6),
                E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER)
                    .expr(),
            )?;
            cb.require_equal(
                || "production_full_layer_layer_zero",
                desc_before(7),
                E::BaseField::ZERO.expr(),
            )?;
            cb.write_record(
                || "production_full_layer_call",
                RAMType::Custom,
                production_full_layer_call_record(
                    import_cycle.expr(),
                    input_values,
                    output_values,
                    desc_before(6),
                    desc_before(7),
                ),
            )?;
        } else {
            let input_values = input_values.as_ref().expect("export input handle");
            cb.require_equal(
                || "production_export_hidden_words",
                desc_before(4),
                E::BaseField::from_usize(ceno_emul::tensor::production_attention::HIDDEN_WORDS)
                    .expr(),
            )?;
            cb.require_equal(
                || "production_export_meta_words",
                desc_before(6),
                E::BaseField::from_usize(META_WORDS).expr(),
            )?;
            cb.write_record(
                || "production_boundary_hidden_output_start",
                RAMType::Custom,
                boundary_state_record(
                    import_cycle.expr(),
                    input_values[0].clone(),
                    input_values[1].clone(),
                    input_values[2].clone(),
                    1,
                    desc_before(3),
                    E::BaseField::ZERO.expr(),
                ),
            )?;
            cb.read_record(
                || "production_boundary_hidden_output_end",
                RAMType::Custom,
                boundary_state_record(
                    import_cycle.expr(),
                    input_values[0].clone(),
                    input_values[1].clone(),
                    input_values[2].clone(),
                    1,
                    desc_before(3),
                    E::BaseField::from_usize(PART_WORDS).expr(),
                ),
            )?;
        }

        if KIND != 1 {
            let mut event = vec![
                CustomRWTag::TensorBusEvent.expr::<E>(),
                E::BaseField::from_u32(code).expr(),
            ];
            event.extend(desc.iter().map(|word| anchor_word(word, false)));
            event.extend(meta.iter().map(|word| anchor_word(word, false)));
            if KIND == 0 {
                event.extend(output_values.expect("import output handle"));
            } else {
                event.extend(input_values.expect("export input handle"));
            }
            event.extend(std::iter::repeat_n(E::BaseField::ZERO.expr(), 4));
            event.extend([
                key_shard_id.expr(),
                key_local_shard_cycle.expr(),
                key_ordinal.expr(),
            ]);
            cb.write_record(|| "production_tensor_bus_event", RAMType::Custom, event)?;
        }

        Ok(TensorProductionAnchorConfig {
            vm_state,
            ecall_id,
            desc_ptr: (desc_ptr, ptr),
            desc,
            meta,
            input_handle,
            output_handle,
            import_cycle,
            key_shard_id,
            key_local_shard_cycle,
            key_ordinal,
        })
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("production anchors use selected-memory batch assignment")
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
        let selected = selected_mem_indices::<KIND>();
        for ((instance, structural), index) in
            wit.iter_mut().zip(structural.iter_mut()).zip(indices)
        {
            if num_structural_witin > 0 {
                *structural.last_mut().unwrap() = E::BaseField::ONE;
            }
            let step = &steps[*index];
            let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
            let syscall = step.syscall(&syscall_witnesses).ok_or_else(|| {
                ZKVMError::InvalidWitness("production full-layer syscall missing".into())
            })?;
            let boundary_expected = KIND != 1;
            if syscall.tensor_production_full_layer.is_some() != (KIND == 1)
                || syscall.tensor_production_boundary.is_some() != boundary_expected
            {
                return Err(ZKVMError::InvalidWitness(
                    "production full-layer anchor payload mismatch".into(),
                ));
            }
            config.vm_state.assign_instance(instance, shard_ctx, step)?;
            let code = production_spec::<KIND>().0;
            config.ecall_id.assign_op(
                instance,
                shard_ctx,
                &mut lkm,
                step.cycle(),
                &WriteOp::new_register_op(
                    Platform::reg_ecall(),
                    Change::new(code, code),
                    step.rs1().unwrap().previous_cycle,
                ),
                step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
            )?;
            config.desc_ptr.1.assign_instance(
                instance,
                &mut lkm,
                syscall.reg_ops[0].value.after,
            )?;
            config.desc_ptr.0.assign_op(
                instance,
                shard_ctx,
                &mut lkm,
                step.cycle(),
                &syscall.reg_ops[0],
                syscall.reg_future_access[0] != 0,
            )?;
            let mut memories = config.desc.iter().collect::<Vec<_>>();
            if KIND != 0 {
                memories.extend(
                    config
                        .input_handle
                        .as_ref()
                        .expect("production input handle")
                        .iter(),
                );
            }
            memories.extend(config.meta.iter());
            if KIND != 2 {
                memories.extend(
                    config
                        .output_handle
                        .as_ref()
                        .expect("production output handle")
                        .iter(),
                );
            }
            for (memory, &mem_index) in memories.iter().zip(&selected) {
                let op = &syscall.mem_ops[mem_index];
                memory
                    .before
                    .assign_value(instance, UIntValue::new_unchecked(op.value.before));
                memory
                    .after
                    .assign_value(instance, UIntValue::new(op.value.after, &mut lkm));
                memory.memory.assign_op(
                    instance,
                    shard_ctx,
                    &mut lkm,
                    step.cycle(),
                    op,
                    syscall.mem_future_access[mem_index] != 0,
                )?;
            }
            let import_cycle = if KIND == 0 {
                step.cycle()
            } else if KIND == 1 {
                syscall
                    .tensor_production_full_layer
                    .as_ref()
                    .unwrap()
                    .import_cycle
            } else {
                syscall.tensor_production_boundary.unwrap().import_cycle
            };
            set_val!(
                instance,
                config.import_cycle,
                shard_ctx.aligned_current_ts(import_cycle)
            );
            set_val!(instance, config.key_shard_id, shard_ctx.shard_id as u64);
            set_val!(
                instance,
                config.key_local_shard_cycle,
                shard_ctx.aligned_current_ts(step.cycle())
            );
            set_val!(instance, config.key_ordinal, 0_u64);
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
        let syscall = step.syscall(&syscall_witnesses).ok_or_else(|| {
            ZKVMError::InvalidWitness("production full-layer syscall missing".into())
        })?;
        let code = production_spec::<KIND>().0;
        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            code,
            None,
            step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
        );
        shard_ctx.send(
            RAMType::Register,
            syscall.reg_ops[0].addr,
            Platform::reg_arg0() as u64,
            step.cycle() + FullTracer::SUBCYCLE_RD,
            syscall.reg_ops[0].previous_cycle,
            syscall.reg_ops[0].value.after,
            None,
            syscall.reg_future_access[0] != 0,
        );
        // The ECALL owns the complete RAM journal exactly once. Compact anchor
        // columns constrain descriptor/meta/handles; boundary Core rows consume
        // the bulk entries from the same ShardRAM stream.
        for (index, op) in syscall.mem_ops.iter().enumerate() {
            shard_ctx.send(
                RAMType::Memory,
                op.addr,
                op.addr.baddr().0 as u64,
                step.cycle() + FullTracer::SUBCYCLE_MEM,
                op.previous_cycle,
                op.value.after,
                Some(op.value.before),
                syscall.mem_future_access[index] != 0,
            );
        }
        Ok(())
    }
}

impl<E: ExtensionField, const PART: usize> Instruction<E>
    for TensorProductionBoundaryInstruction<E, PART>
{
    type InstructionConfig = TensorProductionBoundaryConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        match PART {
            0 => "TensorProductionBoundaryHiddenInput",
            1 => "TensorProductionBoundaryHiddenOutput",
            _ => panic!("invalid production boundary part"),
        }
        .into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        assert!(PART < 2, "invalid production boundary part");
        let import_cycle = cb.create_witin(|| "production_boundary_import_cycle");
        let boundary_cycle = cb.create_witin(|| "production_boundary_cycle");
        let tensor_id_lo = cb.create_witin(|| "production_boundary_tensor_id_lo");
        let tensor_id_hi = cb.create_witin(|| "production_boundary_tensor_id_hi");
        let tensor_version = cb.create_witin(|| "production_boundary_tensor_version");
        let base_byte_address = cb.create_witin(|| "production_boundary_base_byte_address");
        let local_index = cb.create_witin(|| "production_boundary_local_index");
        let physical_local_index = cb.create_structural_witin(
            || "production_boundary_physical_local_index",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 23, n: 23 },
        );
        // Keep this structural order stable. Device replay derives column IDs
        // from the constructed VK/config and refuses any other layout.
        let eq_rotation_left =
            cb.create_placeholder_structural_witin(|| "production_boundary_rotation_left");
        let eq_rotation_right =
            cb.create_placeholder_structural_witin(|| "production_boundary_rotation_right");
        let eq_rotation = cb.create_placeholder_structural_witin(|| "production_boundary_rotation");
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        cb.require_equal(
            || "production_boundary_physical_index",
            local_index.expr(),
            physical_local_index.expr(),
        )?;
        let local_index_bits = std::array::from_fn(|bit| {
            cb.create_witin(|| format!("production_boundary_index_bit_{bit}"))
        });
        let signed_value = cb.create_witin(|| "production_boundary_signed_value");
        let sign = cb.create_witin(|| "production_boundary_sign");
        let high_magnitude_bits = std::array::from_fn(|bit| {
            cb.create_witin(|| format!("production_boundary_high_bit_{bit}"))
        });
        let before = UInt::new_unchecked(|| "production_boundary_before", cb)?;
        let after = UInt::new(|| "production_boundary_after", cb)?;
        cb.assert_bit(|| "production_boundary_sign_bit", sign.expr())?;
        let mut index_expr = E::BaseField::ZERO.expr();
        let mut coefficient = E::BaseField::ONE.expr();
        for (bit, column) in local_index_bits.iter().enumerate() {
            cb.assert_bit(
                || format!("production_boundary_index_bit_{bit}"),
                column.expr(),
            )?;
            index_expr = index_expr + column.expr() * coefficient.clone();
            coefficient = coefficient * E::BaseField::from_u32(2).expr();
        }
        cb.require_equal(
            || "production_boundary_binary_index",
            local_index.expr(),
            index_expr,
        )?;
        let after_limbs = after.expr();
        let mut high_without_sign = E::BaseField::ZERO.expr();
        let mut coefficient = E::BaseField::ONE.expr();
        for (bit, column) in high_magnitude_bits.iter().enumerate() {
            cb.assert_bit(
                || format!("production_boundary_high_magnitude_bit_{bit}"),
                column.expr(),
            )?;
            high_without_sign = high_without_sign + column.expr() * coefficient.clone();
            coefficient = coefficient * E::BaseField::from_u32(2).expr();
        }
        cb.require_equal(
            || "production_boundary_sign_is_high_bit",
            after_limbs[1].clone(),
            high_without_sign + sign.expr() * E::BaseField::from_u32(1 << 15).expr(),
        )?;
        let raw = after.value();
        cb.require_equal(
            || "production_boundary_signed_word",
            raw.clone(),
            signed_value.expr() + sign.expr() * E::BaseField::from_u64(1_u64 << 32).expr(),
        )?;
        if PART == 0 {
            for (left, right) in before.expr().into_iter().zip(after_limbs.iter()) {
                cb.require_equal(|| "production_import_is_ram_read", left, right.clone())?;
            }
        }
        let memory = WriteMEM::construct_circuit(
            cb,
            base_byte_address.expr() + local_index.expr() * E::BaseField::from_u32(4).expr(),
            before.memory_expr(),
            after.memory_expr(),
            boundary_cycle,
        )?;
        let global_index = local_index.expr();
        let tensor_record = tensor_space_record(
            import_cycle.expr(),
            tensor_id_lo.expr(),
            tensor_id_hi.expr(),
            tensor_version.expr(),
            global_index,
            signed_value.expr(),
        );
        if PART == 0 {
            cb.write_record(
                || "production_boundary_tensor_write",
                RAMType::Custom,
                tensor_record,
            )?;
        } else {
            cb.read_record(
                || "production_boundary_tensor_read",
                RAMType::Custom,
                tensor_record,
            )?;
        }
        let state = |index: Expression<E>| {
            boundary_state_record(
                import_cycle.expr(),
                tensor_id_lo.expr(),
                tensor_id_hi.expr(),
                tensor_version.expr(),
                PART,
                base_byte_address.expr(),
                index,
            )
        };
        cb.read_record(
            || "production_boundary_state_in",
            RAMType::Custom,
            state(local_index.expr()),
        )?;
        cb.write_record(
            || "production_boundary_state_out",
            RAMType::Custom,
            state(local_index.expr() + E::BaseField::ONE.expr()),
        )?;
        Ok(TensorProductionBoundaryConfig {
            import_cycle,
            boundary_cycle,
            tensor_id_lo,
            tensor_id_hi,
            tensor_version,
            base_byte_address,
            local_index,
            physical_local_index,
            eq_rotation_left,
            eq_rotation_right,
            eq_rotation,
            selector,
            local_index_bits,
            signed_value,
            sign,
            high_magnitude_bits,
            before,
            after,
            memory,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        let r_len = cb.cs.r_expressions.len();
        let w_len = cb.cs.w_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        cb.set_rotation_params(
            config.eq_rotation_left.expr(),
            config.eq_rotation_right.expr(),
            config.eq_rotation.expr(),
            23,
            PART_WORDS - 1,
        );
        let selector_type = SelectorType::Prefix(config.selector.expr());
        cb.cs.r_selector = Some(selector_type.clone());
        cb.cs.w_selector = Some(selector_type.clone());
        cb.cs.lk_selector = Some(selector_type.clone());
        cb.cs.zero_selector = Some(selector_type);
        let out_evals = [
            (0..r_len).collect_vec(),
            (r_len..r_len + w_len).collect_vec(),
            (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
            (0..zero_len).collect_vec(),
        ];
        let mut chip = Chip::new_from_cb(cb);
        chip.add_layer(Layer::from_circuit_builder(
            cb,
            format!("{}_main", Self::name()),
            out_evals,
        ));
        Ok((config, chip.gkr_circuit()))
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            "production boundary requires deterministic device replay assignment".into(),
        ))
    }
}
