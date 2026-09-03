//! Row-oriented RAM/Tensor-space boundary for one exact production layer.
//!
//! Hidden and Context boundaries are provider-owned ordinary witnesses. The
//! descriptor ECALL anchors each local Tensor-space relation; this intentionally
//! omits equality between attention Context slices and the post-FFN Context.

use std::{array, marker::PhantomData, sync::Arc};

use ceno_emul::{
    Change, FullTracer, InsnKind, Platform, StepIndex, StepRecord, SyscallSpec,
    TensorProductionExportEndV2Spec, TensorProductionImportBeginV2Spec,
    TensorProductionStageV2Spec, WORD_SIZE, WriteOp, tensor::TensorProductionFullLayerWitness,
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

const TENSOR_SPACE_VERSION: u32 = 1;
const FULL_LAYER_CALL_VERSION: u32 = 9;
const DESC_WORDS: usize = 8;
const META_WORDS: usize = 4;
const HANDLE_WORDS: usize = 4;

pub type TensorProductionImportAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 0>;
pub type TensorProductionStageAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 1>;
pub type TensorProductionExportAnchorInstruction<E> = TensorProductionAnchorInstruction<E, 2>;
pub type TensorProductionBoundaryHiddenInputInstruction<E> =
    TensorProductionBoundaryInstruction<E, 0, 0, 0, 0>;
pub type TensorProductionBoundaryAttentionInputInstruction<
    E,
    const PART: usize,
    const GROUP: usize,
> = TensorProductionBoundaryInstruction<E, 1, 0, PART, GROUP>;
pub type TensorProductionBoundaryAttentionOutputInstruction<E, const GROUP: usize> =
    TensorProductionBoundaryInstruction<E, 1, 1, 0, GROUP>;
pub type TensorProductionBoundaryPostInputInstruction<E, const PART: usize> =
    TensorProductionBoundaryInstruction<E, 2, 0, PART, 0>;
pub type TensorProductionBoundaryHiddenOutputInstruction<E> =
    TensorProductionBoundaryInstruction<E, 2, 1, 0, 0>;

pub struct TensorProductionAnchorInstruction<E, const KIND: usize>(PhantomData<E>);

#[derive(Debug)]
struct AnchorMemory<E: ExtensionField> {
    before: UInt<E>,
    after: UInt<E>,
    memory: WriteMEM,
    write: bool,
}

#[derive(Debug)]
pub struct TensorProductionAnchorConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    desc_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    desc: [AnchorMemory<E>; DESC_WORDS],
    input_handle: Option<[AnchorMemory<E>; HANDLE_WORDS]>,
    output_handle: Option<[AnchorMemory<E>; HANDLE_WORDS]>,
    stage: WitIn,
    head_start: WitIn,
    head_count: WitIn,
    is_projection: WitIn,
    is_attention: WitIn,
    is_post: WitIn,
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
            TensorProductionStageV2Spec::CODE,
            "TensorProductionStageAnchor",
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
        write,
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
    stage: Expression<E>,
    head_start: Expression<E>,
    head_count: Expression<E>,
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
        stage,
        head_start,
        head_count,
    ]
}

fn conditional_type<E: ExtensionField>(selector: Expression<E>) -> Expression<E> {
    E::BaseField::from_u64(RAMType::Custom as u64).expr() * selector.clone()
        + E::BaseField::from_u64(RAMType::Undefined as u64).expr()
            * (E::BaseField::ONE.expr() - selector)
}

fn conditional_rlc<E: ExtensionField>(
    cb: &CircuitBuilder<E>,
    selector: Expression<E>,
    record: &[Expression<E>],
) -> Expression<E> {
    cb.rlc_chip_record(record.to_vec()) * selector.clone() + E::BaseField::ONE.expr() - selector
}

pub struct TensorProductionBoundaryInstruction<
    E,
    const STAGE: usize,
    const DIRECTION: usize,
    const PART: usize,
    const GROUP: usize,
>(PhantomData<E>);

const fn production_boundary_rows(stage: usize, direction: usize, part: usize) -> usize {
    use ceno_emul::tensor::production_attention::{CONTEXT_WORDS, HEADS_PER_CIRCUIT, HIDDEN_WORDS};
    match (stage, direction, part) {
        (0, 0, 0) | (0, 1, 0..=2) | (2, 0, 0..=1) | (2, 1, 0) => HIDDEN_WORDS,
        (1, 0, 0..=2) | (1, 1, 0) => HEADS_PER_CIRCUIT * CONTEXT_WORDS / 32,
        _ => panic!("invalid production boundary stage/direction/part"),
    }
}

const fn production_boundary_log_rows(stage: usize, direction: usize, part: usize) -> usize {
    production_boundary_rows(stage, direction, part).trailing_zeros() as usize
}

const fn production_boundary_replay_rows(stage: usize, direction: usize, part: usize) -> usize {
    let rows = production_boundary_rows(stage, direction, part);
    if stage == 1 {
        rows / ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
    } else {
        rows
    }
}

const fn production_boundary_tensor_offset(stage: usize, direction: usize, part: usize) -> usize {
    use ceno_emul::tensor::production_attention::{CONTEXT_WORDS, HIDDEN_WORDS};
    match (stage, direction) {
        (0, 0) | (1, 1) | (2, 1) => 0,
        (0, 1) => part * CONTEXT_WORDS,
        (1, 0) => part * CONTEXT_WORDS / 32,
        (2, 0) => part * HIDDEN_WORDS,
        _ => panic!("invalid production boundary offset"),
    }
}

#[derive(Debug)]
struct TensorProductionBoundaryStructuralConfig {
    physical_local_index: StructuralWitIn,
    eq_rotation_left: StructuralWitIn,
    eq_rotation_right: StructuralWitIn,
    eq_rotation: StructuralWitIn,
    selector: StructuralWitIn,
}

#[derive(Debug)]
struct TensorProductionBoundaryMetadataConfig {
    import_cycle: WitIn,
    tensor_id_lo: WitIn,
    tensor_id_hi: WitIn,
    tensor_version: WitIn,
    base_byte_address: WitIn,
}

#[derive(Debug)]
pub struct TensorProductionBoundaryOutputConfig<E: ExtensionField> {
    layer: WitIn,
    metadata: Vec<TensorProductionBoundaryMetadataConfig>,
    value: UInt<E>,
    sign: WitIn,
    structural: TensorProductionBoundaryStructuralConfig,
}

#[derive(Debug)]
pub enum TensorProductionBoundaryConfig<E: ExtensionField> {
    Output(TensorProductionBoundaryOutputConfig<E>),
}

impl<E: ExtensionField> TensorProductionBoundaryConfig<E> {
    fn structural(&self) -> &TensorProductionBoundaryStructuralConfig {
        match self {
            Self::Output(config) => &config.structural,
        }
    }

    pub(crate) fn structural_column_ids(&self) -> [usize; 5] {
        let structural = self.structural();
        [
            structural.physical_local_index.id as usize,
            structural.eq_rotation_left.id as usize,
            structural.eq_rotation_right.id as usize,
            structural.eq_rotation.id as usize,
            structural.selector.id as usize,
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
    pub(crate) fn device_output_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionBoundaryOutputColumnMap, ZKVMError>
    {
        let maps = self.device_output_column_maps(num_witin, num_structural_witin)?;
        if maps.len() != 1 {
            return Err(ZKVMError::InvalidWitness(
                "production boundary expected one metadata slot".into(),
            ));
        }
        Ok(maps[0])
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn device_output_column_maps(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<Vec<ceno_gpu::common::witgen::ProductionAttentionBoundaryOutputColumnMap>, ZKVMError>
    {
        use ceno_gpu::common::witgen::ProductionAttentionBoundaryOutputColumnMap;

        self.validate_device_layout(num_structural_witin)?;
        let Self::Output(config) = self;
        let value = config.value.wits_in().ok_or_else(|| {
            ZKVMError::InvalidWitness(
                "production boundary value limbs are not witness cells".into(),
            )
        })?;
        if value.len() != 2 {
            return Err(ZKVMError::InvalidWitness(
                "production boundary UInt layout changed".into(),
            ));
        }
        let id = |cell: WitIn| cell.id as u32;
        let structural = self.structural();
        let num_witin_u32 = u32::try_from(num_witin).map_err(|_| {
            ZKVMError::InvalidWitness("production boundary witness width overflow".into())
        })?;
        let num_structural_witin_u32 = u32::try_from(num_structural_witin).map_err(|_| {
            ZKVMError::InvalidWitness("production boundary structural width overflow".into())
        })?;
        let maps = config
            .metadata
            .iter()
            .map(|metadata| ProductionAttentionBoundaryOutputColumnMap {
                layer: id(config.layer),
                import_cycle: id(metadata.import_cycle),
                tensor_id_lo: id(metadata.tensor_id_lo),
                tensor_id_hi: id(metadata.tensor_id_hi),
                tensor_version: id(metadata.tensor_version),
                base_byte_address: id(metadata.base_byte_address),
                value_limbs: [id(value[0]), id(value[1])],
                sign: id(config.sign),
                physical_local_index: structural.physical_local_index.id as u32,
                prefix: structural.selector.id as u32,
                num_witin: num_witin_u32,
                num_structural_witin: num_structural_witin_u32,
            })
            .collect_vec();
        let mut witin_ids = maps
            .iter()
            .flat_map(|map| {
                [
                    map.import_cycle,
                    map.tensor_id_lo,
                    map.tensor_id_hi,
                    map.tensor_version,
                    map.base_byte_address,
                ]
            })
            .chain([
                id(config.layer),
                id(value[0]),
                id(value[1]),
                id(config.sign),
            ])
            .collect_vec();
        witin_ids.sort_unstable();
        if maps.is_empty()
            || witin_ids != (0..num_witin as u32).collect_vec()
            || maps.iter().any(|map| {
                map.physical_local_index as usize >= num_structural_witin
                    || map.prefix as usize >= num_structural_witin
            })
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary output columns do not exactly cover the VK".into(),
            ));
        }
        Ok(maps)
    }
}

/// Host-side metadata for deterministic device replay. It contains no matrix
/// values and cannot be used to materialize the 2^23-row witness on CPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorProductionBoundaryReplayDescriptor {
    pub layer: u32,
    pub stage: usize,
    pub direction: usize,
    pub part: usize,
    pub group: usize,
    pub head_start: u32,
    pub head_count: u32,
    pub step_index: StepIndex,
    pub import_cycle: u64,
    pub tensor_id: u64,
    pub tensor_version: u32,
    pub base_byte_address: u32,
    pub tensor_index_start: usize,
    pub values: Arc<[i32]>,
    pub rows: usize,
    pub log_rows: usize,
}

pub fn validate_production_attention_group(
    calls: &[&TensorProductionFullLayerWitness],
) -> Result<(), ZKVMError> {
    let first = calls.first().ok_or_else(|| {
        ZKVMError::InvalidWitness("production attention ECALL group is empty".into())
    })?;
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    if calls.len() != heads
        || first.head_start as usize % heads != 0
        || calls.iter().enumerate().any(|(slot, item)| {
            item.stage != 1
                || item.head_count != 1
                || item.head_start != first.head_start + slot as u32
                || item.layer != first.layer
                || item.profile != first.profile
                || item.input_tensor_id != first.input_tensor_id
                || item.input_version != first.input_version
                || item.output_tensor_id != first.output_tensor_id
                || item.output_version != first.output_version
                || item.projected_qkv_tensor_id != item.input_tensor_id
                || item.projected_qkv_version != item.input_version
                || item.attention_output_tensor_id != item.output_tensor_id
                || item.attention_output_version != item.output_version
        })
    {
        return Err(ZKVMError::InvalidWitness(
            "production attention ECALL group is not canonical and adjacent".into(),
        ));
    }
    Ok(())
}

pub fn validate_production_boundary_group(
    descriptors: &[TensorProductionBoundaryReplayDescriptor],
) -> Result<(), ZKVMError> {
    let first = descriptors.first().ok_or_else(|| {
        ZKVMError::InvalidWitness("production boundary descriptor group is empty".into())
    })?;
    if (first.stage, first.direction, first.part) == (0, 0, 0) {
        let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
        let first_end = first
            .tensor_index_start
            .checked_add(first.rows)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness(
                    "production HiddenInput broadcast value range overflow".into(),
                )
            })?;
        let first_values = first
            .values
            .get(first.tensor_index_start..first_end)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness(
                    "production HiddenInput broadcast value range is incomplete".into(),
                )
            })?;
        if descriptors.len() != heads
            || first.head_start as usize % heads != 0
            || descriptors.iter().enumerate().any(|(slot, item)| {
                let values = item
                    .tensor_index_start
                    .checked_add(item.rows)
                    .and_then(|end| item.values.get(item.tensor_index_start..end));
                item.stage != first.stage
                    || item.direction != first.direction
                    || item.part != first.part
                    || item.group != first.group
                    || item.layer != first.layer
                    || item.rows != first.rows
                    || item.log_rows != first.log_rows
                    || item.tensor_index_start != first.tensor_index_start
                    || item.head_count != 1
                    || item.head_start != first.head_start + slot as u32
                    || values != Some(first_values)
            })
        {
            return Err(ZKVMError::InvalidWitness(
                "production HiddenInput broadcast is not canonical and identical".into(),
            ));
        }
        return Ok(());
    }
    if first.stage != 1 {
        if descriptors.len() != 1 {
            return Err(ZKVMError::InvalidWitness(
                "non-attention production boundary descriptor was grouped".into(),
            ));
        }
        return Ok(());
    }
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    let expected_start = first.group.checked_mul(heads).ok_or_else(|| {
        ZKVMError::InvalidWitness("production boundary head group overflow".into())
    })?;
    if descriptors.len() != heads
        || first.head_start as usize != expected_start
        || descriptors.iter().enumerate().any(|(slot, item)| {
            item.stage != first.stage
                || item.direction != first.direction
                || item.part != first.part
                || item.group != first.group
                || item.layer != first.layer
                || item.rows != first.rows
                || item.head_count != 1
                || item.head_start != first.head_start + slot as u32
        })
    {
        return Err(ZKVMError::InvalidWitness(
            "production attention boundary group is not canonical and adjacent".into(),
        ));
    }
    Ok(())
}

impl TensorProductionBoundaryReplayDescriptor {
    fn validate(self) -> Result<Self, ZKVMError> {
        if self.rows != 1 << self.log_rows {
            return Err(ZKVMError::InvalidWitness(
                "production boundary replay row count changed".into(),
            ));
        }
        if self
            .values
            .get(self.tensor_index_start..self.tensor_index_start + self.rows)
            .is_none()
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary value range is incomplete".into(),
            ));
        }
        Ok(self)
    }
}

pub fn collect_production_boundary_replay_descriptors(
    shard_ctx: &ShardContext,
    steps: &[StepRecord],
    indices: &[StepIndex],
) -> Result<Vec<TensorProductionBoundaryReplayDescriptor>, ZKVMError> {
    let mut descriptors = Vec::new();
    for &index in indices {
        let step = &steps[index];
        let syscall = step.syscall(&shard_ctx.syscall_witnesses).ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary syscall missing".into())
        })?;
        let boundary = syscall.tensor_production_boundary.as_ref().ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary descriptor missing".into())
        })?;
        let direction =
            usize::from(boundary.kind == ceno_emul::tensor::TensorProductionBoundaryKind::Export);
        let stage = boundary.stage as usize;
        let group = if stage == 1 {
            boundary.head_start as usize
                / ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        } else {
            0
        };
        let expected_parts = match (stage, direction) {
            (0, 0) => 1,
            (1, 1) => 1,
            (2, 0) => 2,
            (2, 1) => 1,
            _ => {
                return Err(ZKVMError::InvalidWitness(
                    "unknown production boundary stage/direction".into(),
                ));
            }
        };
        if boundary.parts.len() != expected_parts
            || boundary
                .parts
                .iter()
                .enumerate()
                .any(|(part, witness)| witness.part as usize != part)
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary parts are missing, duplicated, or out of order".into(),
            ));
        }
        for part_witness in &boundary.parts {
            let part = part_witness.part as usize;
            descriptors.push(
                TensorProductionBoundaryReplayDescriptor {
                    layer: boundary.layer,
                    stage,
                    direction,
                    part,
                    group,
                    head_start: boundary.head_start,
                    head_count: boundary.head_count,
                    step_index: index,
                    import_cycle: boundary.import_cycle,
                    tensor_id: boundary.tensor_id,
                    tensor_version: boundary.version,
                    base_byte_address: part_witness.base_byte_address,
                    tensor_index_start: part_witness.tensor_index_start,
                    values: boundary.values.clone(),
                    rows: part_witness.word_count,
                    log_rows: part_witness.word_count.trailing_zeros() as usize,
                }
                .validate()?,
            );
        }
    }
    descriptors.sort_unstable_by_key(|descriptor| (descriptor.step_index, descriptor.part));
    for descriptor in &descriptors {
        if descriptor.rows
            != production_boundary_replay_rows(
                descriptor.stage,
                descriptor.direction,
                descriptor.part,
            )
            || descriptor.log_rows
                != production_boundary_replay_rows(
                    descriptor.stage,
                    descriptor.direction,
                    descriptor.part,
                )
                .trailing_zeros() as usize
            || descriptor.tensor_index_start
                != production_boundary_tensor_offset(
                    descriptor.stage,
                    descriptor.direction,
                    descriptor.part,
                )
            || descriptor.group >= ceno_emul::tensor::production_attention::CIRCUITS
        {
            return Err(ZKVMError::InvalidWitness(
                "production boundary stage shape changed".into(),
            ));
        }
    }
    tracing::info!(
        target: "ceno_pipeline",
        hidden_memory_rows = 0,
        context_memory_rows = 0,
        boundary_parts = descriptors.len(),
        "Production boundary ownership classified"
    );
    Ok(descriptors)
}

fn tensor_space_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    layer: Expression<E>,
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
        layer,
        tensor_id_lo,
        tensor_id_hi,
        version,
        index,
        value,
    ]
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
        let stage = cb.create_witin(|| "production_anchor_stage");
        let head_start = cb.create_witin(|| "production_anchor_head_start");
        let head_count = cb.create_witin(|| "production_anchor_head_count");
        let is_projection = cb.create_witin(|| "production_anchor_is_projection");
        let is_attention = cb.create_witin(|| "production_anchor_is_attention");
        let is_post = cb.create_witin(|| "production_anchor_is_post");
        for (name, selector) in [
            ("projection", is_projection),
            ("attention", is_attention),
            ("post", is_post),
        ] {
            cb.assert_bit(|| format!("production_anchor_{name}_bit"), selector.expr())?;
        }
        cb.require_equal(
            || "production_anchor_one_stage",
            is_projection.expr() + is_attention.expr() + is_post.expr(),
            E::BaseField::ONE.expr(),
        )?;
        cb.require_equal(
            || "production_anchor_stage_value",
            stage.expr(),
            is_attention.expr() + is_post.expr() * E::BaseField::from_u32(2).expr(),
        )?;
        let descriptor_stage = desc_before(match KIND {
            0 => 6,
            1 => 4,
            2 => 5,
            _ => unreachable!(),
        });
        cb.require_equal(|| "production_anchor_stage", stage.expr(), descriptor_stage)?;
        if KIND == 1 {
            cb.require_equal(
                || "production_anchor_head_start",
                head_start.expr(),
                desc_before(5),
            )?;
            cb.require_equal(
                || "production_anchor_head_count",
                head_count.expr(),
                desc_before(6),
            )?;
            cb.require_equal(
                || "production_anchor_reserved",
                desc_before(7),
                E::BaseField::ZERO.expr(),
            )?;
        } else {
            let packed = desc_before(if KIND == 0 { 7 } else { 6 });
            cb.require_equal(
                || "production_anchor_packed_head_range",
                packed,
                head_start.expr() + head_count.expr() * E::BaseField::from_u32(1 << 16).expr(),
            )?;
            if KIND == 2 {
                cb.require_equal(
                    || "production_anchor_reserved",
                    desc_before(7),
                    E::BaseField::ZERO.expr(),
                )?;
            }
        }
        cb.require_equal(
            || "production_anchor_whole_stage_start",
            is_post.expr() * head_start.expr(),
            E::BaseField::ZERO.expr(),
        )?;
        cb.require_equal(
            || "production_anchor_whole_stage_count",
            is_post.expr() * (head_count.expr() - E::BaseField::from_u32(32).expr()),
            E::BaseField::ZERO.expr(),
        )?;
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
                let pointer = desc_before(if KIND == 0 { 5 } else { 3 });
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
        if KIND == 1 {
            let input_values = input_values.as_ref().expect("full-layer input handle");
            let output_values = output_values.as_ref().expect("full-layer output handle");
            let call = production_full_layer_call_record(
                import_cycle.expr(),
                input_values,
                output_values,
                E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER)
                    .expr(),
                desc_before(1),
                stage.expr(),
                head_start.expr(),
                head_count.expr(),
            );
            cb.write_rlc_record(
                || "production_full_layer_call",
                conditional_type(is_attention.expr()),
                call.clone(),
                conditional_rlc(cb, is_attention.expr(), &call),
            )?;
        }

        if KIND != 1 {
            let mut event = vec![
                CustomRWTag::TensorBusEvent.expr::<E>(),
                E::BaseField::from_u32(code).expr(),
            ];
            event.extend(desc.iter().map(|word| anchor_word(word, false)));
            let words = if KIND == 0 {
                is_projection.expr()
                    * E::BaseField::from_usize(
                        ceno_emul::tensor::production_attention::HIDDEN_WORDS,
                    )
                    .expr()
                    + is_attention.expr()
                        * head_count.expr()
                        * E::BaseField::from_usize(
                            3 * ceno_emul::tensor::production_attention::SEQUENCE
                                * ceno_emul::tensor::production_attention::HEAD_DIM,
                        )
                        .expr()
                    + is_post.expr()
                        * E::BaseField::from_usize(
                            2 * ceno_emul::tensor::production_attention::HIDDEN_WORDS,
                        )
                        .expr()
            } else {
                is_projection.expr()
                    * E::BaseField::from_usize(ceno_emul::tensor::production_attention::QKV_WORDS)
                        .expr()
                    + is_attention.expr()
                        * head_count.expr()
                        * E::BaseField::from_usize(
                            ceno_emul::tensor::production_attention::SEQUENCE
                                * ceno_emul::tensor::production_attention::HEAD_DIM,
                        )
                        .expr()
                    + is_post.expr()
                        * E::BaseField::from_usize(
                            ceno_emul::tensor::production_attention::HIDDEN_WORDS,
                        )
                        .expr()
            };
            event.extend([
                words.clone() * E::BaseField::from_u32(4).expr(),
                words,
                E::BaseField::ONE.expr(),
                E::BaseField::ZERO.expr(),
            ]);
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
            input_handle,
            output_handle,
            stage,
            head_start,
            head_count,
            is_projection,
            is_attention,
            is_post,
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
            if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
                let op = step.rs1().expect("production anchor ECALL register");
                tracing::info!(
                    target: "ceno_gpu::tensor_anchor_ram_owner",
                    kind = KIND,
                    owner = production_spec::<KIND>().1,
                    role = "ecall_id",
                    ram_type = "Register",
                    addr = Platform::reg_ecall() as u64,
                    before_value = op.value,
                    after_value = op.value,
                    previous_cycle = op.previous_cycle,
                    local_previous_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle),
                    current_cycle = step.cycle() + FullTracer::SUBCYCLE_RS1,
                    local_clk = shard_ctx
                        .aligned_current_ts(step.cycle() + FullTracer::SUBCYCLE_RS1),
                    future = step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
                    expected_read_namespace = "read_rs/read_record",
                    expected_write_namespace = "read_rs/write_record",
                    assignment_emitted = true,
                    assignment_prev_value = ?Option::<u32>::None,
                    "Production anchor emulator RAM-event owner"
                );
            }
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
            if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
                let op = &syscall.reg_ops[0];
                tracing::info!(
                    target: "ceno_gpu::tensor_anchor_ram_owner",
                    kind = KIND,
                    owner = production_spec::<KIND>().1,
                    role = "desc_ptr",
                    ram_type = "Register",
                    addr = Platform::reg_arg0() as u64,
                    before_value = op.value.before,
                    after_value = op.value.after,
                    previous_cycle = op.previous_cycle,
                    local_previous_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle),
                    current_cycle = step.cycle() + FullTracer::SUBCYCLE_RD,
                    local_clk = shard_ctx
                        .aligned_current_ts(step.cycle() + FullTracer::SUBCYCLE_RD),
                    future = syscall.reg_future_access[0] != 0,
                    expected_read_namespace = "write_rd/read_record",
                    expected_write_namespace = "write_rd/write_record",
                    assignment_emitted = true,
                    assignment_prev_value = ?Some(op.value.before),
                    "Production anchor emulator RAM-event owner"
                );
            }
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
            if KIND != 2 {
                memories.extend(
                    config
                        .output_handle
                        .as_ref()
                        .expect("production output handle")
                        .iter(),
                );
            }
            let selected = match KIND {
                0 => (0..DESC_WORDS)
                    .chain(syscall.mem_ops.len() - HANDLE_WORDS..syscall.mem_ops.len())
                    .collect_vec(),
                1 => (0..DESC_WORDS + 2 * HANDLE_WORDS).collect_vec(),
                2 => (0..DESC_WORDS + HANDLE_WORDS).collect_vec(),
                _ => unreachable!(),
            };
            for (memory, &mem_index) in memories.iter().zip(&selected) {
                let op = &syscall.mem_ops[mem_index];
                let traced_addr = op.addr.baddr().0;
                if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some()
                    && (matches!(traced_addr, 0x3fff_ff30 | 0x3fff_ff40)
                        || ((8..12).contains(&mem_index)
                            && (0x3fff_ff10..=0x3fff_ff2c).contains(&traced_addr)))
                {
                    let role = match (KIND, mem_index) {
                        (_, 0..8) => format!("desc[{}]", mem_index),
                        (0, 8..) => format!("output_handle[{}]", mem_index - 8),
                        (1, 8..12) => format!("input_handle[{}]", mem_index - 8),
                        (1, 12..) => format!("output_handle[{}]", mem_index - 12),
                        (2, 8..) => format!("input_handle[{}]", mem_index - 8),
                        _ => unreachable!("production anchor memory layout"),
                    };
                    tracing::info!(
                        target: "ceno_gpu::tensor_anchor_ram_owner",
                        kind = KIND,
                        owner = production_spec::<KIND>().1,
                        role,
                        mem_index,
                        ram_type = "Memory",
                        addr = op.addr.baddr().0 as u64,
                        before_value = op.value.before,
                        after_value = op.value.after,
                        previous_cycle = op.previous_cycle,
                        local_previous_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle),
                        current_cycle = step.cycle() + FullTracer::SUBCYCLE_MEM,
                        local_clk = shard_ctx
                            .aligned_current_ts(step.cycle() + FullTracer::SUBCYCLE_MEM),
                        future = syscall.mem_future_access[mem_index] != 0,
                        expected_read_namespace = "write_memory/read_record",
                        expected_write_namespace = "write_memory/write_record",
                        assignment_emitted = true,
                        assignment_prev_value = ?Some(op.value.before),
                        "Production anchor emulator RAM-event owner"
                    );
                }
                memory
                    .before
                    .assign_value(instance, UIntValue::new_unchecked(op.value.before));
                let after = if memory.write {
                    UIntValue::new(op.value.after, &mut lkm)
                } else {
                    UIntValue::new_unchecked(op.value.after)
                };
                memory.after.assign_value(instance, after);
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
                syscall
                    .tensor_production_boundary
                    .as_ref()
                    .unwrap()
                    .import_cycle
            };
            set_val!(
                instance,
                config.import_cycle,
                if KIND == 1 {
                    import_cycle
                } else {
                    shard_ctx.aligned_current_ts(import_cycle)
                }
            );
            set_val!(instance, config.key_shard_id, shard_ctx.shard_id as u64);
            set_val!(
                instance,
                config.key_local_shard_cycle,
                shard_ctx.aligned_current_ts(step.cycle())
            );
            set_val!(instance, config.key_ordinal, 0_u64);
            let payload = if KIND == 1 {
                syscall.tensor_production_full_layer.as_ref().unwrap()
            } else {
                // Import/export carry the same stage tuple in their boundary payload.
                let boundary = syscall.tensor_production_boundary.as_ref().unwrap();
                set_val!(instance, config.stage, boundary.stage as u64);
                set_val!(instance, config.head_start, boundary.head_start as u64);
                set_val!(instance, config.head_count, boundary.head_count as u64);
                set_val!(
                    instance,
                    config.is_projection,
                    u64::from(boundary.stage == 0)
                );
                set_val!(
                    instance,
                    config.is_attention,
                    u64::from(boundary.stage == 1)
                );
                set_val!(instance, config.is_post, u64::from(boundary.stage == 2));
                lkm.fetch(step.pc().before.0);
                continue;
            };
            set_val!(instance, config.stage, payload.stage as u64);
            set_val!(instance, config.head_start, payload.head_start as u64);
            set_val!(instance, config.head_count, payload.head_count as u64);
            set_val!(
                instance,
                config.is_projection,
                u64::from(payload.stage == 0)
            );
            set_val!(instance, config.is_attention, u64::from(payload.stage == 1));
            set_val!(instance, config.is_post, u64::from(payload.stage == 2));
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
        Ok(())
    }
}

impl<
    E: ExtensionField,
    const STAGE: usize,
    const DIRECTION: usize,
    const PART: usize,
    const GROUP: usize,
> Instruction<E> for TensorProductionBoundaryInstruction<E, STAGE, DIRECTION, PART, GROUP>
{
    type InstructionConfig = TensorProductionBoundaryConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        let stage = ["Projection", "Attention", "PostFfn"][STAGE];
        let direction = ["Input", "Output"][DIRECTION];
        if STAGE == 1 {
            let start = GROUP * ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
            let end = start + ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT - 1;
            format!("TensorProductionBoundary{stage}{direction}Part{PART}Heads{start:02}_{end:02}")
        } else {
            format!("TensorProductionBoundary{stage}{direction}Part{PART}")
        }
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let log_rows = production_boundary_log_rows(STAGE, DIRECTION, PART);
        assert!(GROUP < ceno_emul::tensor::production_attention::CIRCUITS);
        let layer = cb.create_witin(|| "production_boundary_layer");
        let metadata_slots = if (STAGE, DIRECTION, PART) == (0, 0, 0) {
            ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        } else {
            1
        };
        let metadata = (0..metadata_slots)
            .map(|slot| TensorProductionBoundaryMetadataConfig {
                import_cycle: cb
                    .create_witin(|| format!("production_boundary_import_cycle_{slot}")),
                tensor_id_lo: cb
                    .create_witin(|| format!("production_boundary_tensor_id_lo_{slot}")),
                tensor_id_hi: cb
                    .create_witin(|| format!("production_boundary_tensor_id_hi_{slot}")),
                tensor_version: cb
                    .create_witin(|| format!("production_boundary_tensor_version_{slot}")),
                base_byte_address: cb
                    .create_witin(|| format!("production_boundary_base_byte_address_{slot}")),
            })
            .collect_vec();
        let value = UInt::new(|| "production_boundary_value", cb)?;
        let sign = cb.create_witin(|| "production_boundary_sign");
        cb.assert_bit(|| "production_boundary_sign_bit", sign.expr())?;
        let value_limbs = value.expr();
        cb.assert_const_range(
            || "production_boundary_high_magnitude_range",
            value_limbs[1].clone() - sign.expr() * E::BaseField::from_u32(1 << 15).expr(),
            15,
        )?;
        let signed_value = value.value() - sign.expr() * E::BaseField::from_u64(1_u64 << 32).expr();
        let physical_local_index = cb.create_structural_witin(
            || "production_boundary_physical_local_index",
            StructuralWitInType::OuterRepeatingIncrementalSequence {
                k: if STAGE == 1 { 18 } else { log_rows },
                n: log_rows,
            },
        );
        // Keep this structural order stable. Device replay derives column IDs
        // from the constructed VK/config and refuses any other layout.
        let eq_rotation_left =
            cb.create_placeholder_structural_witin(|| "production_boundary_rotation_left");
        let eq_rotation_right =
            cb.create_placeholder_structural_witin(|| "production_boundary_rotation_right");
        let eq_rotation = cb.create_placeholder_structural_witin(|| "production_boundary_rotation");
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let global_index = physical_local_index.expr()
            + E::BaseField::from_usize(production_boundary_tensor_offset(STAGE, DIRECTION, PART))
                .expr();
        let is_provider_hidden = matches!(
            (STAGE, DIRECTION, PART),
            (0, 0, 0) | (2, 0, 0) | (2, 0, 1) | (2, 1, 0)
        );
        for (slot, metadata) in metadata.iter().enumerate() {
            let tensor_record = tensor_space_record(
                metadata.import_cycle.expr(),
                layer.expr(),
                metadata.tensor_id_lo.expr(),
                metadata.tensor_id_hi.expr(),
                metadata.tensor_version.expr(),
                global_index.clone(),
                signed_value.clone(),
            );
            if is_provider_hidden {
                cb.write_record(
                    || format!("production_hidden_witness_local_write_{slot}"),
                    RAMType::Custom,
                    tensor_record.clone(),
                )?;
                cb.read_record(
                    || format!("production_hidden_witness_local_read_{slot}"),
                    RAMType::Custom,
                    tensor_record,
                )?;
            } else if DIRECTION == 0 {
                cb.write_record(
                    || format!("production_boundary_tensor_write_{slot}"),
                    RAMType::Custom,
                    tensor_record,
                )?;
            } else {
                cb.read_record(
                    || format!("production_boundary_tensor_read_{slot}"),
                    RAMType::Custom,
                    tensor_record,
                )?;
            }
        }
        let structural = TensorProductionBoundaryStructuralConfig {
            physical_local_index,
            eq_rotation_left,
            eq_rotation_right,
            eq_rotation,
            selector,
        };
        Ok(TensorProductionBoundaryConfig::Output(
            TensorProductionBoundaryOutputConfig {
                layer,
                metadata,
                value,
                sign,
                structural,
            },
        ))
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
        let structural = config.structural();
        cb.set_rotation_params(
            structural.eq_rotation_left.expr(),
            structural.eq_rotation_right.expr(),
            structural.eq_rotation.expr(),
            production_boundary_log_rows(STAGE, DIRECTION, PART),
            production_boundary_rows(STAGE, DIRECTION, PART) - 1,
        );
        let physical_rows = production_boundary_rows(STAGE, DIRECTION, PART);
        assert!(physical_rows.is_power_of_two() && physical_rows > 0);
        cb.set_prefix_selector_num_instances(physical_rows);
        let selector_type = SelectorType::Prefix(structural.selector.expr());
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

#[cfg(test)]
mod boundary_group_tests {
    use super::*;

    fn descriptor(slot: usize) -> TensorProductionBoundaryReplayDescriptor {
        let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
        TensorProductionBoundaryReplayDescriptor {
            layer: 3,
            stage: 1,
            direction: 0,
            part: 0,
            group: 2,
            head_start: (2 * heads + slot) as u32,
            head_count: 1,
            step_index: slot,
            import_cycle: 100 + slot as u64,
            tensor_id: 200 + slot as u64,
            tensor_version: 7,
            base_byte_address: 0,
            tensor_index_start: 0,
            values: Arc::from([]),
            rows: 1 << 18,
            log_rows: 18,
        }
    }

    #[test]
    fn attention_boundary_group_requires_every_canonical_slot() {
        let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
        let canonical = (0..heads).map(descriptor).collect::<Vec<_>>();
        validate_production_boundary_group(&canonical).unwrap();

        let mut missing = canonical.clone();
        missing.pop();
        assert!(validate_production_boundary_group(&missing).is_err());

        if heads > 1 {
            let mut duplicate = canonical.clone();
            duplicate[1] = duplicate[0].clone();
            assert!(validate_production_boundary_group(&duplicate).is_err());

            let mut reversed = canonical.clone();
            reversed.swap(0, 1);
            assert!(validate_production_boundary_group(&reversed).is_err());

            let mut non_adjacent = canonical.clone();
            non_adjacent[1].head_start += 1;
            assert!(validate_production_boundary_group(&non_adjacent).is_err());
        }

        let mut extra = canonical.clone();
        extra.push(descriptor(heads));
        assert!(validate_production_boundary_group(&extra).is_err());
    }

    #[test]
    fn attention_boundary_replay_shape_is_one_ordinary_head() {
        assert_eq!(production_boundary_rows(1, 0, 0), 1 << 19);
        assert_eq!(production_boundary_log_rows(1, 0, 0), 19);
        assert_eq!(production_boundary_replay_rows(1, 0, 0), 1 << 18);
        assert_eq!(
            production_boundary_replay_rows(1, 0, 0).trailing_zeros(),
            18
        );
    }

    #[test]
    fn attention_boundary_group_rejects_descriptor_and_head_drift() {
        let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
        let canonical = (0..heads).map(descriptor).collect::<Vec<_>>();
        for mutate in [
            |item: &mut TensorProductionBoundaryReplayDescriptor| item.layer += 1,
            |item: &mut TensorProductionBoundaryReplayDescriptor| item.part += 1,
            |item: &mut TensorProductionBoundaryReplayDescriptor| item.group += 1,
            |item: &mut TensorProductionBoundaryReplayDescriptor| item.head_count += 1,
            |item: &mut TensorProductionBoundaryReplayDescriptor| item.rows *= 2,
        ] {
            let mut invalid = canonical.clone();
            mutate(&mut invalid[heads - 1]);
            assert!(validate_production_boundary_group(&invalid).is_err());
        }

        let mut misaligned = canonical;
        misaligned[0].head_start += 1;
        assert!(validate_production_boundary_group(&misaligned).is_err());
    }
}
