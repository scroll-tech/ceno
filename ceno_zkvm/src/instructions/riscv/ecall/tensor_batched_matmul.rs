use std::{collections::BTreeMap, marker::PhantomData};

use ceno_emul::{InsnKind, StepIndex, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{
    chip::Chip,
    default_out_eval_groups,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    utils::lk_multiplicity::Multiplicity,
};
use multilinear_extensions::{Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitIn};
use p3::field::PrimeCharacteristicRing;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::Instruction,
    structs::{CustomRWTag, ProgramParams, RAMType},
    tables::RMMCollections,
    witness::{LkMultiplicity, set_val},
};

pub const TENSOR_BATCHED_MATMUL_CORE_NAME: &str = "TensorBatchedMatMulCore";
pub const TENSOR_BATCHED_MATMUL_A_COL: usize = 0;
pub const TENSOR_BATCHED_MATMUL_W_COL: usize = 3;
pub const TENSOR_BATCHED_MATMUL_Q_COL: usize = 6;
pub const TENSOR_BATCHED_MATMUL_R_COL: usize = 9;
pub const TENSOR_BATCHED_MATMUL_SCALE: i64 = 1 << 16;
pub const TENSOR_BATCHED_MATMUL_STATE_VERSION: u32 = 5;
pub const TENSOR_RESIDENT_STATE_VERSION: u32 = 6;
pub const TENSOR_SPACE_VERSION: u32 = 1;
pub const TENSOR_HINT_REF_VERSION: u32 = 2;

#[derive(Clone, Debug)]
pub struct TensorBatchedMatMulSection {
    pub cycle: u64,
    pub call_id: u64,
    pub a: [[i32; 2]; 2],
    pub w: [[i32; 2]; 2],
    pub resident: Option<ceno_emul::tensor::TensorResidentMatMulWitness>,
}

pub(crate) fn tensor_space_record<E: ExtensionField>(
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

pub(crate) fn tensor_hint_ref_record<E: ExtensionField>(
    profile: Expression<E>,
    layer: Expression<E>,
    role: Expression<E>,
    tile: Expression<E>,
    index: Expression<E>,
    value: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(TENSOR_HINT_REF_VERSION).expr(),
        profile,
        layer,
        role,
        tile,
        index,
        value,
    ]
}

pub(crate) fn tensor_resident_claim_record<E: ExtensionField>(
    cycle: Expression<E>,
    import_cycle: Expression<E>,
    input_id_lo: Expression<E>,
    input_id_hi: Expression<E>,
    input_version: Expression<E>,
    output_id_lo: Expression<E>,
    output_id_hi: Expression<E>,
    output_version: Expression<E>,
    profile: Expression<E>,
    layer: Expression<E>,
    role: Expression<E>,
    row: Expression<E>,
    output_value: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(TENSOR_RESIDENT_STATE_VERSION).expr(),
        cycle,
        import_cycle,
        input_id_lo,
        input_id_hi,
        input_version,
        output_id_lo,
        output_id_hi,
        output_version,
        profile,
        layer,
        role,
        row,
        output_value,
    ]
}

pub(crate) fn tensor_batched_matmul_state_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    row: Expression<E>,
    a: Expression<E>,
    w: Expression<E>,
    q: Expression<E>,
    remainder: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(TENSOR_BATCHED_MATMUL_STATE_VERSION).expr(),
        cycle,
        call_id,
        row,
        a,
        w,
        q,
        remainder,
    ]
}

#[derive(Debug)]
pub struct TensorBatchedMatMulCoreConfig {
    a: WitIn,
    a_sign: WitIn,
    a_high7: WitIn,
    a_low_bytes: [WitIn; 3],
    a_magnitude: WitIn,
    a_magnitude_bits: [WitIn; 21],
    w: WitIn,
    w_sign: WitIn,
    w_high7: WitIn,
    w_low_bytes: [WitIn; 3],
    w_magnitude: WitIn,
    w_magnitude_bits: [WitIn; 21],
    q: WitIn,
    q_magnitude: WitIn,
    q_sign: WitIn,
    remainder: WitIn,
    remainder_bits: [WitIn; 16],
    cycle: WitIn,
    call_id: WitIn,
    logical_row: WitIn,
    physical_logical_row: StructuralWitIn,
    is_resident: WitIn,
    import_cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    profile: WitIn,
    layer: WitIn,
    role: WitIn,
    role_selectors: [WitIn; 11],
    tile: WitIn,
    rhs_tensor_id_lo: WitIn,
    rhs_tensor_id_hi: WitIn,
    rhs_tensor_version: WitIn,
    logical_row_bits: [WitIn; 2],
}

pub struct TensorBatchedMatMulCoreInstruction<E>(PhantomData<E>);

#[derive(Debug)]
pub struct TensorHintRefCoreConfig {
    profile: WitIn,
    layer: WitIn,
    role: WitIn,
    tile: WitIn,
    index: WitIn,
    value: WitIn,
    sign: WitIn,
    high7: WitIn,
    low_bytes: [WitIn; 3],
    magnitude: WitIn,
    magnitude_bits: [WitIn; 21],
    role_selectors: [WitIn; 9],
}

pub struct TensorHintRefCoreInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for TensorHintRefCoreInstruction<E> {
    type InstructionConfig = TensorHintRefCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }
    fn name() -> String {
        "TensorHintRefCore".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let profile = cb.create_witin(|| "tensor_hint_profile");
        let layer = cb.create_witin(|| "tensor_hint_layer");
        let role = cb.create_witin(|| "tensor_hint_role");
        let tile = cb.create_witin(|| "tensor_hint_tile");
        let index = cb.create_witin(|| "tensor_hint_index");
        let value = cb.create_witin(|| "tensor_hint_value");
        let sign = cb.create_witin(|| "tensor_hint_sign");
        let high7 = cb.create_witin(|| "tensor_hint_high7");
        let low_bytes =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_hint_byte_{i}")));
        let magnitude = cb.create_witin(|| "tensor_hint_magnitude");
        let magnitude_bits =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_hint_magnitude_bit_{i}")));
        constrain_signed_i32(
            cb,
            "tensor_hint",
            value,
            sign,
            high7,
            &low_bytes,
            magnitude,
            &magnitude_bits,
        )?;
        let role_selectors =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_hint_role_{i}_selector")));
        let mut selected_role = E::BaseField::ZERO.expr();
        let mut selected_count = E::BaseField::ZERO.expr();
        for (selector, (role_value, bound)) in role_selectors.iter().zip(HINT_ROLE_BOUNDS) {
            cb.assert_bit(
                || format!("tensor_hint_role_{role_value}_selector_bit"),
                selector.expr(),
            )?;
            selected_role = selected_role + selector.expr() * u64::from(role_value);
            selected_count = selected_count + selector.expr();
            for bit in &magnitude_bits[bound..] {
                cb.require_zero(
                    || format!("tensor_hint_role_{role_value}_value_bound"),
                    selector.expr() * bit.expr(),
                )?;
            }
        }
        cb.require_equal(|| "tensor_hint_role_value", role.expr(), selected_role)?;
        cb.require_equal(
            || "tensor_hint_exactly_one_role",
            selected_count,
            E::BaseField::ONE.expr(),
        )?;
        cb.require_equal(
            || "tensor_hint_tiny_profile",
            profile.expr(),
            E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA_TINY).expr(),
        )?;
        cb.require_zero(|| "tensor_hint_tile_zero", tile.expr())?;
        cb.write_record(
            || "tensor_hint_ref_write",
            RAMType::Custom,
            tensor_hint_ref_record(
                profile.expr(),
                layer.expr(),
                role.expr(),
                tile.expr(),
                index.expr(),
                value.expr(),
            ),
        )?;
        Ok(TensorHintRefCoreConfig {
            profile,
            layer,
            role,
            tile,
            index,
            value,
            sign,
            high7,
            low_bytes,
            magnitude,
            magnitude_bits,
            role_selectors,
        })
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            "HintRef Core is assigned by unique logical tiles".into(),
        ))
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let mut hints = BTreeMap::new();
        for index in indices {
            let syscall = steps[*index]
                .syscall(&shard_ctx.syscall_witnesses)
                .ok_or_else(|| {
                    ZKVMError::InvalidWitness("resident operator syscall missing".into())
                })?;
            if let Some(payload) = syscall.tensor_resident_matmul {
                if !HINT_ROLE_BOUNDS
                    .iter()
                    .any(|(role, _)| *role == payload.hint.role)
                {
                    continue;
                }
                if let Some(previous) = hints.insert(payload.hint, payload.matrix.w) {
                    if previous != payload.matrix.w {
                        return Err(ZKVMError::InvalidWitness(
                            "HintRef value changed between reads".into(),
                        ));
                    }
                }
            }
        }
        if hints.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "HintRef Core needs a resident tile".into(),
            ));
        }
        let rows = hints.len() * 4;
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural =
            RowMajorMatrix::new(rows, num_structural_witin, InstancePaddingStrategy::Default);
        let mut lkm = LkMultiplicity::default();
        for ((row, structural_row), (hint, values)) in witness
            .iter_mut()
            .zip(structural.iter_mut())
            .zip(hints.iter().flat_map(|(hint, matrix)| {
                matrix
                    .iter()
                    .flatten()
                    .enumerate()
                    .map(move |(i, v)| (hint, (i, *v)))
            }))
        {
            if num_structural_witin > 0 {
                *structural_row.last_mut().unwrap() = E::BaseField::ONE;
            }
            set_val!(row, config.profile, u64::from(hint.profile));
            set_val!(row, config.layer, u64::from(hint.layer));
            set_val!(row, config.role, u64::from(hint.role));
            set_val!(row, config.tile, u64::from(hint.tile_index));
            set_val!(row, config.index, values.0 as u64);
            for (selector, (role, _)) in config.role_selectors.iter().zip(HINT_ROLE_BOUNDS) {
                set_val!(row, *selector, u64::from(hint.role == role));
            }
            assign_signed_i32(
                config.value,
                config.sign,
                config.high7,
                &config.low_bytes,
                config.magnitude,
                &config.magnitude_bits,
                row,
                &mut lkm,
                i64::from(values.1),
            );
        }
        witness.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([witness, structural], lkm.into_finalize_result()))
    }
}

impl<E: ExtensionField> TensorHintRefCoreInstruction<E> {
    pub fn assign_hints(
        config: &TensorHintRefCoreConfig,
        num_witin: usize,
        num_structural_witin: usize,
        hints: &[(ceno_emul::tensor::TensorHintRef, [[i32; 2]; 2])],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        if hints.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "HintRef Core needs a resident tile".into(),
            ));
        }
        let unique = hints.iter().copied().collect::<BTreeMap<_, _>>();
        if unique.len() != hints.len() {
            return Err(ZKVMError::InvalidWitness(
                "HintRef tile identity is duplicated".into(),
            ));
        }
        let rows = unique.len() * 4;
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural =
            RowMajorMatrix::new(rows, num_structural_witin, InstancePaddingStrategy::Default);
        let mut lkm = LkMultiplicity::default();
        for ((row, structural_row), (hint, (index, value))) in witness
            .iter_mut()
            .zip(structural.iter_mut())
            .zip(unique.iter().flat_map(|(hint, matrix)| {
                matrix
                    .iter()
                    .flatten()
                    .enumerate()
                    .map(move |(index, value)| (hint, (index, *value)))
            }))
        {
            if num_structural_witin > 0 {
                *structural_row.last_mut().unwrap() = E::BaseField::ONE;
            }
            set_val!(row, config.profile, u64::from(hint.profile));
            set_val!(row, config.layer, u64::from(hint.layer));
            set_val!(row, config.role, u64::from(hint.role));
            set_val!(row, config.tile, u64::from(hint.tile_index));
            set_val!(row, config.index, index as u64);
            for (selector, (role, _)) in config.role_selectors.iter().zip(HINT_ROLE_BOUNDS) {
                set_val!(row, *selector, u64::from(hint.role == role));
            }
            assign_signed_i32(
                config.value,
                config.sign,
                config.high7,
                &config.low_bytes,
                config.magnitude,
                &config.magnitude_bits,
                row,
                &mut lkm,
                i64::from(value),
            );
        }
        witness.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([witness, structural], lkm.into_finalize_result()))
    }
}

fn constrain_signed<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    value: WitIn,
    magnitude: WitIn,
    sign: WitIn,
    bits: usize,
) -> Result<(), ZKVMError> {
    cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
    cb.assert_const_range(|| format!("{name}_magnitude_range"), magnitude.expr(), bits)?;
    cb.require_equal(
        || format!("{name}_signed_value"),
        value.expr(),
        magnitude.expr() * (E::BaseField::ONE.expr() - sign.expr() * 2),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn constrain_signed_i32<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    value: WitIn,
    sign: WitIn,
    high7: WitIn,
    low_bytes: &[WitIn; 3],
    magnitude: WitIn,
    magnitude_bits: &[WitIn; 21],
) -> Result<(), ZKVMError> {
    cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
    cb.assert_const_range(|| format!("{name}_high7_range"), high7.expr(), 7)?;
    for (index, byte) in low_bytes.iter().enumerate() {
        cb.assert_const_range(|| format!("{name}_byte_{index}_range"), byte.expr(), 8)?;
    }
    for (index, bit) in magnitude_bits.iter().enumerate() {
        cb.assert_bit(|| format!("{name}_magnitude_bit_{index}"), bit.expr())?;
    }
    let unsigned = low_bytes[0].expr()
        + low_bytes[1].expr() * (1u64 << 8)
        + low_bytes[2].expr() * (1u64 << 16)
        + (high7.expr() + sign.expr() * 128) * (1u64 << 24);
    cb.require_equal(
        || format!("{name}_canonical_twos_complement"),
        value.expr(),
        unsigned - sign.expr() * (1u64 << 32),
    )?;
    let magnitude_reconstructed = magnitude_bits
        .iter()
        .enumerate()
        .fold(E::BaseField::ZERO.expr(), |sum, (index, bit)| {
            sum + bit.expr() * (1u64 << index)
        });
    cb.require_equal(
        || format!("{name}_magnitude_reconstruction"),
        magnitude.expr(),
        magnitude_reconstructed,
    )?;
    cb.require_equal(
        || format!("{name}_signed_magnitude"),
        value.expr(),
        magnitude.expr() * (E::BaseField::ONE.expr() - sign.expr() * 2),
    )?;
    Ok(())
}

const RESIDENT_ROLE_BOUNDS: [(u32, usize, usize); 11] = [
    (ceno_emul::tensor::TENSOR_HINT_ROLE_ATTENTION, 8, 8),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_FFN, 8, 8),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_Q, 14, 2),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_K, 14, 2),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_V, 14, 11),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_QK, 14, 14),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_PV, 21, 8),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_O, 8, 17),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_GATE, 14, 12),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_UP, 14, 15),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_DOWN, 8, 15),
];

const HINT_ROLE_BOUNDS: [(u32, usize); 9] = [
    (ceno_emul::tensor::TENSOR_HINT_ROLE_ATTENTION, 8),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_FFN, 8),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_Q, 2),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_K, 2),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_V, 11),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_O, 17),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_GATE, 12),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_UP, 15),
    (ceno_emul::tensor::TENSOR_HINT_ROLE_DOWN, 15),
];

impl<E: ExtensionField> Instruction<E> for TensorBatchedMatMulCoreInstruction<E> {
    type InstructionConfig = TensorBatchedMatMulCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        TENSOR_BATCHED_MATMUL_CORE_NAME.into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // These stable offsets are opened directly by the matrix reduction.
        let a = cb.create_witin(|| "tensor_batched_a");
        let a_sign = cb.create_witin(|| "tensor_batched_a_sign");
        let a_high7 = cb.create_witin(|| "tensor_batched_a_high7");
        let w = cb.create_witin(|| "tensor_batched_w");
        let w_sign = cb.create_witin(|| "tensor_batched_w_sign");
        let w_high7 = cb.create_witin(|| "tensor_batched_w_high7");
        let q = cb.create_witin(|| "tensor_batched_q");
        let q_magnitude = cb.create_witin(|| "tensor_batched_q_magnitude");
        let q_sign = cb.create_witin(|| "tensor_batched_q_sign");
        let remainder = cb.create_witin(|| "tensor_batched_remainder");
        let remainder_bits =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_batched_r_bit_{i}")));
        let a_low_bytes =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_batched_a_byte_{i}")));
        let a_magnitude = cb.create_witin(|| "tensor_batched_a_magnitude");
        let a_magnitude_bits = std::array::from_fn(|i| {
            cb.create_witin(|| format!("tensor_batched_a_magnitude_bit_{i}"))
        });
        let w_low_bytes =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_batched_w_byte_{i}")));
        let w_magnitude = cb.create_witin(|| "tensor_batched_w_magnitude");
        let w_magnitude_bits = std::array::from_fn(|i| {
            cb.create_witin(|| format!("tensor_batched_w_magnitude_bit_{i}"))
        });
        let cycle = cb.create_witin(|| "tensor_batched_cycle");
        let call_id = cb.create_witin(|| "tensor_batched_call_id");
        let logical_row = cb.create_witin(|| "tensor_batched_logical_row");
        let physical_logical_row = cb.create_structural_witin(
            || "tensor_batched_physical_logical_row",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 2, n: 32 },
        );
        let is_resident = cb.create_witin(|| "tensor_batched_is_resident");
        let import_cycle = cb.create_witin(|| "tensor_batched_import_cycle");
        let input_id_lo = cb.create_witin(|| "tensor_batched_input_id_lo");
        let input_id_hi = cb.create_witin(|| "tensor_batched_input_id_hi");
        let input_version = cb.create_witin(|| "tensor_batched_input_version");
        let output_id_lo = cb.create_witin(|| "tensor_batched_output_id_lo");
        let output_id_hi = cb.create_witin(|| "tensor_batched_output_id_hi");
        let output_version = cb.create_witin(|| "tensor_batched_output_version");
        let profile = cb.create_witin(|| "tensor_batched_profile");
        let layer = cb.create_witin(|| "tensor_batched_layer");
        let role = cb.create_witin(|| "tensor_batched_role");
        let role_selectors = std::array::from_fn(|i| {
            cb.create_witin(|| format!("tensor_batched_role_{i}_selector"))
        });
        let tile = cb.create_witin(|| "tensor_batched_tile");
        let rhs_tensor_id_lo = cb.create_witin(|| "tensor_batched_rhs_tensor_id_lo");
        let rhs_tensor_id_hi = cb.create_witin(|| "tensor_batched_rhs_tensor_id_hi");
        let rhs_tensor_version = cb.create_witin(|| "tensor_batched_rhs_tensor_version");
        let logical_row_bits =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_batched_row_bit_{i}")));
        cb.assert_bit(|| "tensor_batched_is_resident_bit", is_resident.expr())?;

        cb.require_equal(
            || "tensor_batched_logical_row_matches_physical_row",
            logical_row.expr(),
            physical_logical_row.expr(),
        )?;
        for (index, bit) in logical_row_bits.iter().enumerate() {
            cb.assert_bit(
                || format!("tensor_batched_logical_row_bit_{index}"),
                bit.expr(),
            )?;
        }
        cb.require_equal(
            || "tensor_batched_logical_row_bits",
            logical_row.expr(),
            logical_row_bits[0].expr() + logical_row_bits[1].expr() * 2,
        )?;

        constrain_signed_i32(
            cb,
            "tensor_batched_a",
            a,
            a_sign,
            a_high7,
            &a_low_bytes,
            a_magnitude,
            &a_magnitude_bits,
        )?;
        constrain_signed_i32(
            cb,
            "tensor_batched_w",
            w,
            w_sign,
            w_high7,
            &w_low_bytes,
            w_magnitude,
            &w_magnitude_bits,
        )?;
        constrain_signed(cb, "tensor_batched_q", q, q_magnitude, q_sign, 16)?;
        let mut selected_role = E::BaseField::ZERO.expr();
        let mut selected_count = E::BaseField::ZERO.expr();
        for (selector, (role_value, a_bits, w_bits)) in
            role_selectors.iter().zip(RESIDENT_ROLE_BOUNDS)
        {
            cb.assert_bit(
                || format!("tensor_batched_role_{role_value}_selector_bit"),
                selector.expr(),
            )?;
            selected_role = selected_role + selector.expr() * u64::from(role_value);
            selected_count = selected_count + selector.expr();
            for bit in &a_magnitude_bits[a_bits..] {
                cb.require_zero(
                    || format!("tensor_batched_role_{role_value}_a_bound"),
                    selector.expr() * bit.expr(),
                )?;
            }
            for bit in &w_magnitude_bits[w_bits..] {
                cb.require_zero(
                    || format!("tensor_batched_role_{role_value}_w_bound"),
                    selector.expr() * bit.expr(),
                )?;
            }
        }
        cb.require_equal(|| "tensor_batched_role_value", role.expr(), selected_role)?;
        cb.require_equal(
            || "tensor_batched_one_role_for_resident_section",
            selected_count,
            is_resident.expr(),
        )?;
        cb.require_equal(
            || "tensor_batched_tiny_profile",
            profile.expr(),
            is_resident.expr()
                * E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA_TINY).expr(),
        )?;
        cb.require_zero(|| "tensor_batched_tile_zero", tile.expr())?;
        for (i, bit) in remainder_bits.iter().enumerate() {
            cb.assert_bit(|| format!("tensor_batched_r_bit_{i}_boolean"), bit.expr())?;
        }
        let reconstructed = remainder_bits
            .iter()
            .enumerate()
            .fold(E::BaseField::ZERO.expr(), |acc, (i, bit)| {
                acc + bit.expr() * (1u64 << i)
            });
        cb.require_equal(
            || "tensor_batched_canonical_remainder",
            remainder.expr(),
            reconstructed,
        )?;
        let standalone_record = tensor_batched_matmul_state_record(
            cycle.expr(),
            call_id.expr(),
            logical_row.expr(),
            a.expr(),
            w.expr(),
            q.expr(),
            remainder.expr(),
        );
        let standalone_selector = E::BaseField::ONE.expr() - is_resident.expr();
        let standalone_rlc = cb.rlc_chip_record(standalone_record.clone())
            * standalone_selector.clone()
            + is_resident.expr();
        let conditional_custom_type = |selector: Expression<E>| {
            E::BaseField::from_u64(RAMType::Custom as u64).expr() * selector.clone()
                + E::BaseField::from_u64(RAMType::Undefined as u64).expr()
                    * (E::BaseField::ONE.expr() - selector)
        };
        cb.read_rlc_record(
            || "tensor_batched_matmul_state",
            conditional_custom_type(standalone_selector),
            standalone_record,
            standalone_rlc,
        )?;
        let resident_claim = tensor_resident_claim_record(
            cycle.expr(),
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            profile.expr(),
            layer.expr(),
            role.expr(),
            logical_row.expr(),
            q.expr() * TENSOR_BATCHED_MATMUL_SCALE as u64 + remainder.expr(),
        );
        let resident_selector = is_resident.expr();
        let resident_padding = E::BaseField::ONE.expr() - resident_selector.clone();
        cb.read_rlc_record(
            || "tensor_resident_claim",
            conditional_custom_type(resident_selector.clone()),
            resident_claim.clone(),
            cb.rlc_chip_record(resident_claim) * resident_selector.clone()
                + resident_padding.clone(),
        )?;
        let input_record = tensor_space_record(
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            logical_row.expr(),
            a.expr(),
        );
        cb.read_rlc_record(
            || "tensor_space_input",
            conditional_custom_type(resident_selector.clone()),
            input_record.clone(),
            cb.rlc_chip_record(input_record) * resident_selector.clone() + resident_padding.clone(),
        )?;
        let output_record = tensor_space_record(
            import_cycle.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            logical_row.expr(),
            q.expr() * TENSOR_BATCHED_MATMUL_SCALE as u64 + remainder.expr(),
        );
        cb.write_rlc_record(
            || "tensor_space_output",
            conditional_custom_type(resident_selector.clone()),
            output_record.clone(),
            cb.rlc_chip_record(output_record) * resident_selector.clone()
                + resident_padding.clone(),
        )?;
        let tensor_rhs_selector = role_selectors[5].expr() + role_selectors[6].expr();
        let hint_selector = resident_selector.clone() - tensor_rhs_selector.clone();
        let hint_record = tensor_hint_ref_record(
            profile.expr(),
            layer.expr(),
            role.expr(),
            tile.expr(),
            logical_row.expr(),
            w.expr(),
        );
        cb.read_rlc_record(
            || "tensor_hint_ref_read",
            conditional_custom_type(hint_selector.clone()),
            hint_record.clone(),
            cb.rlc_chip_record(hint_record) * hint_selector.clone()
                + (E::BaseField::ONE.expr() - hint_selector),
        )?;
        let rhs_tensor_record = tensor_space_record(
            import_cycle.expr(),
            rhs_tensor_id_lo.expr(),
            rhs_tensor_id_hi.expr(),
            rhs_tensor_version.expr(),
            logical_row.expr(),
            w.expr(),
        );
        cb.read_rlc_record(
            || "tensor_space_rhs",
            conditional_custom_type(tensor_rhs_selector.clone()),
            rhs_tensor_record.clone(),
            cb.rlc_chip_record(rhs_tensor_record) * tensor_rhs_selector.clone()
                + (E::BaseField::ONE.expr() - tensor_rhs_selector),
        )?;

        Ok(TensorBatchedMatMulCoreConfig {
            a,
            a_sign,
            a_high7,
            a_low_bytes,
            a_magnitude,
            a_magnitude_bits,
            w,
            w_sign,
            w_high7,
            w_low_bytes,
            w_magnitude,
            w_magnitude_bits,
            q,
            q_magnitude,
            q_sign,
            remainder,
            remainder_bits,
            cycle,
            call_id,
            logical_row,
            physical_logical_row,
            is_resident,
            import_cycle,
            input_id_lo,
            input_id_hi,
            input_version,
            output_id_lo,
            output_id_hi,
            output_version,
            profile,
            layer,
            role,
            role_selectors,
            tile,
            rhs_tensor_id_lo,
            rhs_tensor_id_hi,
            rhs_tensor_version,
            logical_row_bits,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;

        // These three structural slots are replaced by eq(point, x) MLEs during
        // batched-main proving. They bind the matrix reduction's three terminal
        // points without introducing another PCS opening.
        let matrix_a_selector = cb.create_placeholder_structural_witin(|| "matrix_a_selector");
        let matrix_w_selector = cb.create_placeholder_structural_witin(|| "matrix_w_selector");
        let matrix_output_selector =
            cb.create_placeholder_structural_witin(|| "matrix_output_selector");

        // Keep the ordinary row-prefix selector last: assignment materializes
        // that selector in the final structural column, while the three dynamic
        // matrix selectors are materialized by batched-main itself.
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let selector_type = SelectorType::Prefix(selector.expr());
        cb.cs.r_selector = Some(selector_type.clone());
        cb.cs.w_selector = Some(selector_type.clone());
        cb.cs.lk_selector = Some(selector_type.clone());
        cb.cs.zero_selector = Some(selector_type);

        let mut chip = Chip::new_from_cb(cb);
        let ordinary_output_count = chip.final_out_evals.len();
        let mut layer = Layer::from_circuit_builder(
            cb,
            format!("{}_main", Self::name()),
            default_out_eval_groups(cb),
        );
        layer.add_matrix_identity_groups(
            [
                matrix_a_selector.expr(),
                matrix_w_selector.expr(),
                matrix_output_selector.expr(),
            ],
            [
                config.a.expr(),
                config.w.expr(),
                config.q.expr(),
                config.remainder.expr(),
            ],
        );
        chip.n_evaluations += 4;
        chip.final_out_evals = (0..ordinary_output_count + 4).collect();
        chip.add_layer(layer);
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
            "batched matmul Core is assigned by complete matrix sections".into(),
        ))
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let sections = indices
            .iter()
            .map(|index| {
                let step = &steps[*index];
                let syscall = step.syscall(&shard_ctx.syscall_witnesses).ok_or_else(|| {
                    ZKVMError::InvalidWitness("tiny batched MatMul syscall missing".into())
                })?;
                if let Some(payload) = syscall.tensor_batched_matmul_2x2 {
                    Ok(TensorBatchedMatMulSection {
                        cycle: step.cycle() - shard_ctx.current_shard_offset_cycle(),
                        call_id: syscall.reg_ops[0].value.after as u64,
                        a: payload.a,
                        w: payload.w,
                        resident: None,
                    })
                } else if let Some(mut resident) = syscall.tensor_resident_matmul {
                    resident.import_cycle = shard_ctx.aligned_current_ts(resident.import_cycle);
                    Ok(TensorBatchedMatMulSection {
                        cycle: step.cycle() - shard_ctx.current_shard_offset_cycle(),
                        call_id: step.cycle(),
                        a: resident.matrix.a,
                        w: resident.matrix.w,
                        resident: Some(resident),
                    })
                } else {
                    Err(ZKVMError::InvalidWitness(
                        "tiny batched MatMul payload missing".into(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        Self::assign_sections(config, num_witin, num_structural_witin, &sections)
    }
}

impl<E: ExtensionField> TensorBatchedMatMulCoreInstruction<E> {
    pub fn assign_sections(
        config: &TensorBatchedMatMulCoreConfig,
        num_witin: usize,
        num_structural_witin: usize,
        sections: &[TensorBatchedMatMulSection],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        if sections.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "batched matmul needs at least one complete section".into(),
            ));
        }
        let rows = sections.len() * 4;
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural =
            RowMajorMatrix::new(rows, num_structural_witin, InstancePaddingStrategy::Default);
        let mut lkm = LkMultiplicity::default();

        for (physical_row, (row, structural_row)) in
            witness.iter_mut().zip(structural.iter_mut()).enumerate()
        {
            let section = &sections[physical_row / 4];
            let logical_row = physical_row % 4;
            if num_structural_witin > 0 {
                *structural_row.last_mut().unwrap() = E::BaseField::ONE;
            }
            let k = logical_row & 1;
            let m = logical_row >> 1;
            let n = logical_row & 1;
            let wk = logical_row >> 1;
            let acc = (0..2)
                .map(|inner| i64::from(section.a[m][inner]) * i64::from(section.w[inner][n]))
                .sum::<i64>();
            let q = acc.div_euclid(TENSOR_BATCHED_MATMUL_SCALE);
            let remainder = acc.rem_euclid(TENSOR_BATCHED_MATMUL_SCALE) as u64;

            set_val!(row, config.cycle, section.cycle);
            set_val!(row, config.call_id, section.call_id);
            set_val!(row, config.logical_row, logical_row as u64);
            set_val!(
                structural_row,
                config.physical_logical_row,
                logical_row as u64
            );
            for (index, bit) in config.logical_row_bits.iter().enumerate() {
                set_val!(row, *bit, ((logical_row >> index) & 1) as u64);
            }
            if let Some(resident) = section.resident {
                let tensor_rhs = matches!(
                    resident.hint.role,
                    ceno_emul::tensor::TENSOR_HINT_ROLE_QK | ceno_emul::tensor::TENSOR_HINT_ROLE_PV
                );
                if tensor_rhs != resident.rhs_tensor_id.is_some()
                    || tensor_rhs != resident.rhs_tensor_version.is_some()
                {
                    return Err(ZKVMError::InvalidWitness(
                        "resident MatMul RHS ownership does not match its role".into(),
                    ));
                }
                set_val!(row, config.is_resident, 1);
                set_val!(row, config.import_cycle, resident.import_cycle);
                set_val!(
                    row,
                    config.input_id_lo,
                    u64::from(resident.input_tensor_id as u32)
                );
                set_val!(row, config.input_id_hi, resident.input_tensor_id >> 32);
                set_val!(row, config.input_version, u64::from(resident.input_version));
                set_val!(
                    row,
                    config.output_id_lo,
                    u64::from(resident.output_tensor_id as u32)
                );
                set_val!(row, config.output_id_hi, resident.output_tensor_id >> 32);
                set_val!(
                    row,
                    config.output_version,
                    u64::from(resident.output_version)
                );
                set_val!(row, config.profile, u64::from(resident.hint.profile));
                set_val!(row, config.layer, u64::from(resident.hint.layer));
                set_val!(row, config.role, u64::from(resident.hint.role));
                set_val!(row, config.tile, u64::from(resident.hint.tile_index));
                match (resident.rhs_tensor_id, resident.rhs_tensor_version) {
                    (Some(rhs_tensor_id), Some(rhs_tensor_version)) => {
                        set_val!(
                            row,
                            config.rhs_tensor_id_lo,
                            u64::from(rhs_tensor_id as u32)
                        );
                        set_val!(row, config.rhs_tensor_id_hi, rhs_tensor_id >> 32);
                        set_val!(
                            row,
                            config.rhs_tensor_version,
                            u64::from(rhs_tensor_version)
                        );
                    }
                    (None, None) => {}
                    _ => {
                        return Err(ZKVMError::InvalidWitness(
                            "resident MatMul RHS tensor identity is incomplete".into(),
                        ));
                    }
                }
                for (selector, (role, _, _)) in
                    config.role_selectors.iter().zip(RESIDENT_ROLE_BOUNDS)
                {
                    set_val!(row, *selector, u64::from(resident.hint.role == role));
                }
            }

            assign_signed_i32(
                config.a,
                config.a_sign,
                config.a_high7,
                &config.a_low_bytes,
                config.a_magnitude,
                &config.a_magnitude_bits,
                row,
                &mut lkm,
                i64::from(section.a[m][k]),
            );
            assign_signed_i32(
                config.w,
                config.w_sign,
                config.w_high7,
                &config.w_low_bytes,
                config.w_magnitude,
                &config.w_magnitude_bits,
                row,
                &mut lkm,
                i64::from(section.w[wk][n]),
            );
            assign_signed(
                config.q,
                config.q_magnitude,
                config.q_sign,
                row,
                &mut lkm,
                q,
                16,
            );
            set_val!(row, config.remainder, remainder);
            for (i, bit) in config.remainder_bits.iter().enumerate() {
                set_val!(row, *bit, (remainder >> i) & 1);
            }
        }
        for physical_row in rows..structural.height() {
            let structural_row = structural.row_mut(physical_row);
            set_val!(
                structural_row,
                config.physical_logical_row,
                (physical_row % 4) as u64
            );
        }
        witness.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([witness, structural], lkm.into_finalize_result()))
    }
}

fn assign_signed<F: PrimeCharacteristicRing>(
    value_col: WitIn,
    magnitude_col: WitIn,
    sign_col: WitIn,
    row: &mut [F],
    lkm: &mut LkMultiplicity,
    value: i64,
    bits: usize,
) {
    let magnitude = value.unsigned_abs();
    row[value_col.id as usize] = if value < 0 {
        -F::from_u64(magnitude)
    } else {
        F::from_u64(magnitude)
    };
    row[magnitude_col.id as usize] = F::from_u64(magnitude);
    row[sign_col.id as usize] = F::from_u64(u64::from(value < 0));
    lkm.assert_const_range(magnitude, bits);
}

#[allow(clippy::too_many_arguments)]
fn assign_signed_i32<F: PrimeCharacteristicRing>(
    value_col: WitIn,
    sign_col: WitIn,
    high7_col: WitIn,
    low_byte_cols: &[WitIn; 3],
    magnitude_col: WitIn,
    magnitude_bit_cols: &[WitIn; 21],
    row: &mut [F],
    lkm: &mut LkMultiplicity,
    value: i64,
) {
    let signed = i32::try_from(value).expect("MatMul operand must fit signed i32");
    let bytes = signed.to_le_bytes();
    let sign = u64::from(signed < 0);
    let magnitude = value.unsigned_abs();
    assert!(
        magnitude < (1 << magnitude_bit_cols.len()),
        "MatMul operand exceeds its canonical tiny-layer envelope"
    );
    row[value_col.id as usize] = if signed < 0 {
        -F::from_u64(magnitude)
    } else {
        F::from_u64(magnitude)
    };
    row[sign_col.id as usize] = F::from_u64(sign);
    row[high7_col.id as usize] = F::from_u64(u64::from(bytes[3] & 0x7f));
    lkm.assert_const_range(u64::from(bytes[3] & 0x7f), 7);
    for (column, byte) in low_byte_cols.iter().zip(bytes[..3].iter()) {
        row[column.id as usize] = F::from_u64(u64::from(*byte));
        lkm.assert_const_range(u64::from(*byte), 8);
    }
    row[magnitude_col.id as usize] = F::from_u64(magnitude);
    for (index, column) in magnitude_bit_cols.iter().enumerate() {
        row[column.id as usize] = F::from_u64((magnitude >> index) & 1);
    }
}
