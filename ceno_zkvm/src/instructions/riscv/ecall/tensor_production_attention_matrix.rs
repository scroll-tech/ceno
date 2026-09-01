//! Exact four-head QK and K128-tiled PV matrix Cores.
//!
//! PV tiles the reduction axis because BabyBear satisfies
//! `p = 1920 * 2^20 + 1`: a full-K centered-Q20 relation would admit distinct
//! canonical integer quotient/remainder pairs with the same field value.
//! K128 bounds a sign-fixed partial quotient by 1024.  Sixteen partials are
//! folded by a Tensor-space accumulator chain without changing the matrix
//! row count, auxiliary-sumcheck round count, or PCS opening count.

use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{
    chip::Chip,
    default_out_eval_groups,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    tables::LookupTable,
};
use multilinear_extensions::{Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitIn};
use p3::field::{Field, PrimeCharacteristicRing};

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::Instruction,
    structs::{CustomRWTag, ProgramParams, RAMType},
    witness::LkMultiplicity,
};

const HEAD_GROUP_BITS: usize = ceno_emul::tensor::production_attention::MATRIX_GROUP_BITS;
const ROW_BITS: usize = 22 + HEAD_GROUP_BITS;
const ROWS: usize = 1 << ROW_BITS;
const SEQUENCE: u64 = 2048;
const HEAD_DIM: u64 = 128;
const HEADS_PER_CORE: u64 = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT as u64;
const CONTEXT_WORDS: u64 = 1 << 23;
const SCORE_VERSION_OFFSET: u64 = 1;
const PROBABILITY_VERSION_OFFSET: u64 = 2;
const ATTENTION_CALL_VERSION: u64 = 9;
const Q16_SCALE: u64 = 1 << 16;
const Q20_SCALE: u64 = 1 << 20;
const Q20_HALF: u64 = 1 << 19;
const PV_STATE_VERSION: u64 = 10;
const PV_W_STATE_VERSION: u64 = 11;

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
        E::BaseField::ONE.expr(),
        import_cycle,
        tensor_id_lo,
        tensor_id_hi,
        version,
        index,
        value,
    ]
}

pub struct TensorProductionQkCoreInstruction<E, const GROUP: usize>(PhantomData<E>);
pub struct TensorProductionPvCoreInstruction<E, const GROUP: usize>(PhantomData<E>);

#[derive(Debug)]
pub struct TensorProductionQkCoreConfig {
    // Stable A/W/Q/R offsets consumed by the matrix reduction.
    pub(crate) a: WitIn,
    pub(crate) w: WitIn,
    pub(crate) q: WitIn,
    pub(crate) remainder: WitIn,
    a_low7: WitIn,
    a_sign: WitIn,
    w_low7: WitIn,
    w_sign: WitIn,
    axis_low7: WitIn,
    axis_high4: WitIn,
    row_low7: WitIn,
    row_high4: WitIn,
    head: WitIn,
    axis_active: WitIn,
    axis_high_inverse: WitIn,
    row_active: WitIn,
    row_high_inverse: WitIn,
    import_cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    call_row: WitIn,
    call_row_inverse: WitIn,
    physical_index: StructuralWitIn,
    matrix_a_selector: StructuralWitIn,
    matrix_w_selector: StructuralWitIn,
    matrix_output_selector: StructuralWitIn,
    selector: StructuralWitIn,
}

impl TensorProductionQkCoreConfig {
    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionQkColumnMap, ZKVMError> {
        use ceno_gpu::common::witgen::ProductionAttentionQkColumnMap;

        let id = |cell: WitIn| cell.id as u32;
        let structural_id = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionQkColumnMap {
            witness: [
                id(self.a),
                id(self.w),
                id(self.q),
                id(self.remainder),
                id(self.a_low7),
                id(self.a_sign),
                id(self.w_low7),
                id(self.w_sign),
                id(self.axis_low7),
                id(self.axis_high4),
                id(self.row_low7),
                id(self.row_high4),
                id(self.head),
                id(self.axis_active),
                id(self.axis_high_inverse),
                id(self.row_active),
                id(self.row_high_inverse),
                id(self.import_cycle),
                id(self.input_id_lo),
                id(self.input_id_hi),
                id(self.input_version),
                id(self.output_id_lo),
                id(self.output_id_hi),
                id(self.output_version),
                id(self.call_row),
                id(self.call_row_inverse),
            ],
            structural: [
                structural_id(self.physical_index),
                structural_id(self.matrix_a_selector),
                structural_id(self.matrix_w_selector),
                structural_id(self.matrix_output_selector),
                structural_id(self.selector),
            ],
            num_witin: u32::try_from(num_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production QK witness width overflow".into())
            })?,
            num_structural_witin: u32::try_from(num_structural_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production QK structural width overflow".into())
            })?,
        };
        if num_witin != 26
            || num_structural_witin != 5
            || map.witness != core::array::from_fn(|index| index as u32)
            || map.structural != core::array::from_fn(|index| index as u32)
        {
            return Err(ZKVMError::InvalidWitness(
                "production QK device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

#[derive(Debug)]
pub struct TensorProductionPvCoreConfig {
    // Stable A/W/Q/R offsets consumed by the matrix reduction.
    pub(crate) a: WitIn,
    pub(crate) w: WitIn,
    pub(crate) q: WitIn,
    pub(crate) remainder: WitIn,
    probability_low16: WitIn,
    probability_mid16: WitIn,
    probability_high9: WitIn,
    w_sign: WitIn,
    w_low16: WitIn,
    w_high15: WitIn,
    q_sign: WitIn,
    q_limbs: [WitIn; 4],
    remainder_low16: WitIn,
    remainder_high4: WitIn,
    row_high_is_zero: WitIn,
    row_high_inverse: WitIn,
    row_high_is_last: WitIn,
    row_high_last_inverse: WitIn,
    tile_is_zero: WitIn,
    tile_inverse: WitIn,
    tile_is_last: WitIn,
    tile_last_inverse: WitIn,
    accumulator_q_before: WitIn,
    accumulator_r_before: WitIn,
    accumulator_q_after: WitIn,
    accumulator_q_after_sign: WitIn,
    accumulator_q_after_limbs: [WitIn; 4],
    accumulator_r_after: WitIn,
    accumulator_r_after_low16: WitIn,
    accumulator_r_after_high4: WitIn,
    carry: WitIn,
    final_q: WitIn,
    final_remainder: WitIn,
    final_remainder_low16: WitIn,
    final_remainder_high4: WitIn,
    import_cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    physical_index: StructuralWitIn,
    axis: StructuralWitIn,
    row_low7: StructuralWitIn,
    row_high4: StructuralWitIn,
    head: StructuralWitIn,
    tile: StructuralWitIn,
    matrix_a_selector: StructuralWitIn,
    matrix_w_selector: StructuralWitIn,
    matrix_output_selector: StructuralWitIn,
    selector: StructuralWitIn,
}

impl TensorProductionPvCoreConfig {
    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionPvColumnMap, ZKVMError> {
        use ceno_gpu::common::witgen::ProductionAttentionPvColumnMap;

        let id = |cell: WitIn| cell.id as u32;
        let structural_id = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionPvColumnMap {
            witness: [
                id(self.a),
                id(self.w),
                id(self.q),
                id(self.remainder),
                id(self.probability_low16),
                id(self.probability_mid16),
                id(self.probability_high9),
                id(self.w_sign),
                id(self.w_low16),
                id(self.w_high15),
                id(self.q_sign),
                id(self.q_limbs[0]),
                id(self.q_limbs[1]),
                id(self.q_limbs[2]),
                id(self.q_limbs[3]),
                id(self.remainder_low16),
                id(self.remainder_high4),
                id(self.row_high_is_zero),
                id(self.row_high_inverse),
                id(self.row_high_is_last),
                id(self.row_high_last_inverse),
                id(self.tile_is_zero),
                id(self.tile_inverse),
                id(self.tile_is_last),
                id(self.tile_last_inverse),
                id(self.accumulator_q_before),
                id(self.accumulator_r_before),
                id(self.accumulator_q_after),
                id(self.accumulator_q_after_sign),
                id(self.accumulator_q_after_limbs[0]),
                id(self.accumulator_q_after_limbs[1]),
                id(self.accumulator_q_after_limbs[2]),
                id(self.accumulator_q_after_limbs[3]),
                id(self.accumulator_r_after),
                id(self.accumulator_r_after_low16),
                id(self.accumulator_r_after_high4),
                id(self.carry),
                id(self.final_q),
                id(self.final_remainder),
                id(self.final_remainder_low16),
                id(self.final_remainder_high4),
                id(self.import_cycle),
                id(self.input_id_lo),
                id(self.input_id_hi),
                id(self.input_version),
                id(self.output_id_lo),
                id(self.output_id_hi),
                id(self.output_version),
            ],
            structural: [
                structural_id(self.physical_index),
                structural_id(self.axis),
                structural_id(self.row_low7),
                structural_id(self.row_high4),
                structural_id(self.head),
                structural_id(self.tile),
                structural_id(self.matrix_a_selector),
                structural_id(self.matrix_w_selector),
                structural_id(self.matrix_output_selector),
                structural_id(self.selector),
            ],
            num_witin: u32::try_from(num_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production PV witness width overflow".into())
            })?,
            num_structural_witin: u32::try_from(num_structural_witin).map_err(|_| {
                ZKVMError::InvalidWitness("production PV structural width overflow".into())
            })?,
        };
        if num_witin != 48
            || num_structural_witin != 10
            || map.witness != core::array::from_fn(|index| index as u32)
            || map.structural != [5, 0, 1, 2, 3, 4, 6, 7, 8, 9]
        {
            return Err(ZKVMError::InvalidWitness(
                "production PV device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

fn dynamic_range<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: WitIn,
    bits: u32,
) -> Result<(), ZKVMError> {
    Ok(cb.lk_record(
        || name,
        LookupTable::Dynamic,
        vec![value.expr(), E::BaseField::from_u32(bits).expr()],
    )?)
}

fn bit<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: WitIn,
) -> Result<(), ZKVMError> {
    Ok(cb.assert_bit(|| name, value.expr())?)
}

fn zero_indicator<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: Expression<E>,
    indicator: WitIn,
    inverse: WitIn,
) -> Result<(), ZKVMError> {
    bit(cb, name, indicator)?;
    cb.require_zero(|| name, indicator.expr() * value.clone())?;
    Ok(cb.require_equal(
        || name,
        value * inverse.expr(),
        E::BaseField::ONE.expr() - indicator.expr(),
    )?)
}

fn signed_byte<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: WitIn,
    low7: WitIn,
    sign: WitIn,
) -> Result<(), ZKVMError> {
    bit(cb, name, sign)?;
    dynamic_range(cb, name, low7, 7)?;
    Ok(cb.require_equal(
        || name,
        value.expr(),
        low7.expr() - sign.expr() * E::BaseField::from_u32(128).expr(),
    )?)
}

fn signed_u64_limbs<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: WitIn,
    sign: WitIn,
    limbs: [WitIn; 4],
) -> Result<(), ZKVMError> {
    bit(cb, name, sign)?;
    for limb in limbs {
        dynamic_range(cb, name, limb, 16)?;
    }
    let magnitude: Expression<E> = limbs
        .iter()
        .enumerate()
        .map(|(index, limb)| limb.expr() * E::BaseField::from_u64(1u64 << (16 * index)).expr())
        .sum();
    Ok(cb.require_equal(
        || name,
        value.expr(),
        magnitude * (E::BaseField::ONE.expr() - sign.expr() * 2),
    )?)
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

fn attention_call_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    input_id_lo: Expression<E>,
    input_id_hi: Expression<E>,
    input_version: Expression<E>,
    output_id_lo: Expression<E>,
    output_id_hi: Expression<E>,
    output_version: Expression<E>,
    head_start: usize,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u64(ATTENTION_CALL_VERSION).expr(),
        import_cycle,
        input_id_lo,
        input_id_hi,
        input_version,
        output_id_lo,
        output_id_hi,
        output_version,
        E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER).expr(),
        E::BaseField::ZERO.expr(),
        E::BaseField::ONE.expr(),
        E::BaseField::from_usize(head_start).expr(),
        E::BaseField::from_u64(HEADS_PER_CORE).expr(),
    ]
}

fn add_matrix_layer<E: ExtensionField, C>(
    cb: &mut CircuitBuilder<E>,
    name: String,
    config: C,
    columns: [WitIn; 4],
    selectors: [StructuralWitIn; 4],
) -> Result<(C, GKRCircuit<E>), ZKVMError> {
    let [
        matrix_a_selector,
        matrix_w_selector,
        matrix_output_selector,
        selector,
    ] = selectors;
    let selector_type = SelectorType::Prefix(selector.expr());
    cb.cs.r_selector = Some(selector_type.clone());
    cb.cs.w_selector = Some(selector_type.clone());
    cb.cs.lk_selector = Some(selector_type.clone());
    cb.cs.zero_selector = Some(selector_type);

    let mut chip = Chip::new_from_cb(cb);
    let ordinary_output_count = chip.final_out_evals.len();
    let mut layer =
        Layer::from_circuit_builder(cb, format!("{name}_main"), default_out_eval_groups(cb));
    layer.add_matrix_identity_groups(
        [
            matrix_a_selector.expr(),
            matrix_w_selector.expr(),
            matrix_output_selector.expr(),
        ],
        columns.map(|column| column.expr()),
    );
    chip.n_evaluations += 4;
    chip.final_out_evals = (0..ordinary_output_count + 4).collect();
    chip.add_layer(layer);
    Ok((config, chip.gkr_circuit()))
}

fn qk_name(group: usize) -> String {
    let start = group * HEADS_PER_CORE as usize;
    format!(
        "TensorAttentionQKHeads{:02}_{:02}",
        start,
        start + HEADS_PER_CORE as usize - 1
    )
}

fn pv_name(group: usize) -> String {
    let start = group * HEADS_PER_CORE as usize;
    format!(
        "TensorAttentionPVHeads{:02}_{:02}",
        start,
        start + HEADS_PER_CORE as usize - 1
    )
}

impl<E: ExtensionField, const GROUP: usize> Instruction<E>
    for TensorProductionQkCoreInstruction<E, GROUP>
{
    type InstructionConfig = TensorProductionQkCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        assert!(
            GROUP < ceno_emul::tensor::production_attention::CIRCUITS,
            "invalid production QK group"
        );
        qk_name(GROUP)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let a = cb.create_witin(|| "production_qk_a");
        let w = cb.create_witin(|| "production_qk_w");
        let q = cb.create_witin(|| "production_qk_q");
        let remainder = cb.create_witin(|| "production_qk_remainder");
        let a_low7 = cb.create_witin(|| "production_qk_a_low7");
        let a_sign = cb.create_witin(|| "production_qk_a_sign");
        let w_low7 = cb.create_witin(|| "production_qk_w_low7");
        let w_sign = cb.create_witin(|| "production_qk_w_sign");
        signed_byte(cb, "production_qk_a_signed_byte", a, a_low7, a_sign)?;
        signed_byte(cb, "production_qk_w_signed_byte", w, w_low7, w_sign)?;
        cb.require_zero(
            || "production_qk_quotient",
            q.expr() * (q.expr() + E::BaseField::ONE.expr()),
        )?;
        dynamic_range(cb, "production_qk_remainder_u16", remainder, 16)?;

        let axis_low7 = cb.create_witin(|| "production_qk_axis_low7");
        let axis_high4 = cb.create_witin(|| "production_qk_axis_high4");
        let row_low7 = cb.create_witin(|| "production_qk_row_low7");
        let row_high4 = cb.create_witin(|| "production_qk_row_high4");
        let head = cb.create_witin(|| "production_qk_head");
        for (name, value, bits) in [
            ("production_qk_axis_low7_range", axis_low7, 7),
            ("production_qk_axis_high4_range", axis_high4, 4),
            ("production_qk_row_low7_range", row_low7, 7),
            ("production_qk_row_high4_range", row_high4, 4),
        ] {
            dynamic_range(cb, name, value, bits)?;
        }
        if HEAD_GROUP_BITS == 0 {
            cb.require_zero(|| "production_qk_single_head", head.expr())?;
        } else {
            dynamic_range(cb, "production_qk_head_range", head, HEAD_GROUP_BITS as u32)?;
        }
        let axis_active = cb.create_witin(|| "production_qk_axis_active");
        let axis_high_inverse = cb.create_witin(|| "production_qk_axis_high_inverse");
        let row_active = cb.create_witin(|| "production_qk_row_active");
        let row_high_inverse = cb.create_witin(|| "production_qk_row_high_inverse");
        zero_indicator(
            cb,
            "production_qk_axis_active_exact",
            axis_high4.expr(),
            axis_active,
            axis_high_inverse,
        )?;
        zero_indicator(
            cb,
            "production_qk_row_active_exact",
            row_high4.expr(),
            row_active,
            row_high_inverse,
        )?;
        cb.require_zero(
            || "production_qk_a_padding",
            (E::BaseField::ONE.expr() - axis_active.expr()) * a.expr(),
        )?;
        cb.require_zero(
            || "production_qk_w_padding",
            (E::BaseField::ONE.expr() - row_active.expr()) * w.expr(),
        )?;

        let physical_index = cb.create_structural_witin(
            || "production_qk_physical_index",
            StructuralWitInType::OuterRepeatingIncrementalSequence {
                k: ROW_BITS,
                n: ROW_BITS,
            },
        );
        let matrix_a_selector = cb.create_placeholder_structural_witin(|| "matrix_a_selector");
        let matrix_w_selector = cb.create_placeholder_structural_witin(|| "matrix_w_selector");
        let matrix_output_selector =
            cb.create_placeholder_structural_witin(|| "matrix_output_selector");
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let axis: Expression<E> = axis_low7.expr() + axis_high4.expr() * 128;
        let row: Expression<E> = row_low7.expr() + row_high4.expr() * 128;
        cb.require_equal(
            || "production_qk_physical_coordinate",
            physical_index.expr(),
            axis.clone() + row.clone() * SEQUENCE + head.expr() * (1u64 << 22),
        )?;

        let import_cycle = cb.create_witin(|| "production_qk_import_cycle");
        let input_id_lo = cb.create_witin(|| "production_qk_input_id_lo");
        let input_id_hi = cb.create_witin(|| "production_qk_input_id_hi");
        let input_version = cb.create_witin(|| "production_qk_input_version");
        let output_id_lo = cb.create_witin(|| "production_qk_output_id_lo");
        let output_id_hi = cb.create_witin(|| "production_qk_output_id_hi");
        let output_version = cb.create_witin(|| "production_qk_output_version");
        let call_row = cb.create_witin(|| "production_qk_call_row");
        let call_row_inverse = cb.create_witin(|| "production_qk_call_row_inverse");
        zero_indicator(
            cb,
            "production_qk_call_row_exact",
            physical_index.expr(),
            call_row,
            call_row_inverse,
        )?;
        {
            let call_record = attention_call_record(
                import_cycle.expr(),
                input_id_lo.expr(),
                input_id_hi.expr(),
                input_version.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr(),
                GROUP * HEADS_PER_CORE as usize,
            );
            cb.read_rlc_record(
                || "production_attention_call_once",
                conditional_type(call_row.expr()),
                call_record.clone(),
                conditional_rlc(cb, call_row.expr(), &call_record),
            )?;
        }
        let group_words = HEADS_PER_CORE * SEQUENCE * HEAD_DIM;
        let q_index = (head.expr() * SEQUENCE + row.clone()) * HEAD_DIM + axis_low7.expr();
        let k_index = E::BaseField::from_u64(group_words).expr()
            + (head.expr() * SEQUENCE + axis.clone()) * HEAD_DIM
            + row_low7.expr();
        let score_index = (head.expr() * SEQUENCE + row) * SEQUENCE + axis;
        let q_record = tensor_space_record(
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            q_index,
            a.expr(),
        );
        cb.read_rlc_record(
            || "production_qk_q_read",
            conditional_type(axis_active.expr()),
            q_record.clone(),
            conditional_rlc(cb, axis_active.expr(), &q_record),
        )?;
        let k_record = tensor_space_record(
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            k_index,
            w.expr(),
        );
        cb.read_rlc_record(
            || "production_qk_k_read",
            conditional_type(row_active.expr()),
            k_record.clone(),
            conditional_rlc(cb, row_active.expr(), &k_record),
        )?;
        cb.write_record(
            || "production_qk_score_write",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + SCORE_VERSION_OFFSET,
                score_index,
                q.expr() * Q16_SCALE + remainder.expr(),
            ),
        )?;
        Ok(TensorProductionQkCoreConfig {
            a,
            w,
            q,
            remainder,
            a_low7,
            a_sign,
            w_low7,
            w_sign,
            axis_low7,
            axis_high4,
            row_low7,
            row_high4,
            head,
            axis_active,
            axis_high_inverse,
            row_active,
            row_high_inverse,
            import_cycle,
            input_id_lo,
            input_id_hi,
            input_version,
            output_id_lo,
            output_id_hi,
            output_version,
            call_row,
            call_row_inverse,
            physical_index,
            matrix_a_selector,
            matrix_w_selector,
            matrix_output_selector,
            selector,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        let columns = [config.a, config.w, config.q, config.remainder];
        let selectors = [
            config.matrix_a_selector,
            config.matrix_w_selector,
            config.matrix_output_selector,
            config.selector,
        ];
        add_matrix_layer(cb, Self::name(), config, columns, selectors)
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            "production QK requires deterministic device replay".into(),
        ))
    }
}

fn pv_state_record<E: ExtensionField>(
    version: u64,
    import_cycle: Expression<E>,
    output_id_lo: Expression<E>,
    output_id_hi: Expression<E>,
    output_version: Expression<E>,
    group: usize,
    index: Expression<E>,
    step: Expression<E>,
    values: impl IntoIterator<Item = Expression<E>>,
) -> Vec<Expression<E>> {
    let mut record = vec![
        crate::structs::CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u64(version).expr(),
        import_cycle,
        output_id_lo,
        output_id_hi,
        output_version,
        E::BaseField::from_usize(group).expr(),
        index,
        step,
    ];
    record.extend(values);
    record
}

impl<E: ExtensionField, const GROUP: usize> Instruction<E>
    for TensorProductionPvCoreInstruction<E, GROUP>
{
    type InstructionConfig = TensorProductionPvCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        assert!(
            GROUP < ceno_emul::tensor::production_attention::CIRCUITS,
            "invalid production PV group"
        );
        pv_name(GROUP)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let a = cb.create_witin(|| "production_pv_a");
        let w = cb.create_witin(|| "production_pv_w");
        let q = cb.create_witin(|| "production_pv_q");
        let remainder = cb.create_witin(|| "production_pv_remainder");
        let probability_low16 = cb.create_witin(|| "production_pv_probability_low16");
        let probability_mid16 = cb.create_witin(|| "production_pv_probability_mid16");
        let probability_high9 = cb.create_witin(|| "production_pv_probability_high9");
        dynamic_range(
            cb,
            "production_pv_probability_low16_range",
            probability_low16,
            16,
        )?;
        dynamic_range(
            cb,
            "production_pv_probability_mid16_range",
            probability_mid16,
            16,
        )?;
        dynamic_range(
            cb,
            "production_pv_probability_high9_range",
            probability_high9,
            9,
        )?;
        cb.require_equal(
            || "production_pv_probability",
            a.expr(),
            probability_low16.expr()
                + probability_mid16.expr() * (1u64 << 16)
                + probability_high9.expr() * (1u64 << 32),
        )?;
        let w_sign = cb.create_witin(|| "production_pv_w_sign");
        let w_low16 = cb.create_witin(|| "production_pv_w_low16");
        let w_high15 = cb.create_witin(|| "production_pv_w_high15");
        bit(cb, "production_pv_w_sign_bit", w_sign)?;
        dynamic_range(cb, "production_pv_w_low16_range", w_low16, 16)?;
        dynamic_range(cb, "production_pv_w_high15_range", w_high15, 15)?;
        cb.require_equal(
            || "production_pv_w_signed_i32",
            w.expr(),
            (w_low16.expr() + w_high15.expr() * (1u64 << 16))
                * (E::BaseField::ONE.expr() - w_sign.expr() * 2),
        )?;
        let q_sign = cb.create_witin(|| "production_pv_q_sign");
        let q_limbs = core::array::from_fn(|index| {
            cb.create_witin(|| format!("production_pv_q_limb_{index}"))
        });
        signed_u64_limbs(cb, "production_pv_q_signed_u64", q, q_sign, q_limbs)?;
        let remainder_low16 = cb.create_witin(|| "production_pv_remainder_low16");
        let remainder_high4 = cb.create_witin(|| "production_pv_remainder_high4");
        dynamic_range(
            cb,
            "production_pv_remainder_low16_range",
            remainder_low16,
            16,
        )?;
        dynamic_range(
            cb,
            "production_pv_remainder_high4_range",
            remainder_high4,
            4,
        )?;
        cb.require_equal(
            || "production_pv_centered_remainder",
            remainder.expr() + Q20_HALF,
            remainder_low16.expr() + remainder_high4.expr() * (1u64 << 16),
        )?;

        let axis_formula = cb.create_structural_witin(
            || "production_pv_axis",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 7, n: ROW_BITS },
        );
        let row_low7_formula = cb.create_structural_witin(
            || "production_pv_row_low7_prefix",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 14, n: ROW_BITS },
        );
        let row_high4_formula = cb.create_structural_witin(
            || "production_pv_row_high4_prefix",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 18, n: ROW_BITS },
        );
        let head_formula = cb.create_structural_witin(
            || "production_pv_head_prefix",
            StructuralWitInType::OuterRepeatingIncrementalSequence {
                k: 18 + HEAD_GROUP_BITS,
                n: ROW_BITS,
            },
        );
        let tile_formula = cb.create_structural_witin(
            || "production_pv_tile",
            StructuralWitInType::InnerRepeatingIncrementalSequence {
                k: 18 + HEAD_GROUP_BITS,
                n: ROW_BITS,
            },
        );
        let inv_128 = E::BaseField::from_u64(1 << 7).inverse().expr();
        let inv_16384 = E::BaseField::from_u64(1 << 14).inverse().expr();
        let inv_262144 = E::BaseField::from_u64(1 << 18).inverse().expr();
        let axis = axis_formula.expr();
        let row_low7 = (row_low7_formula.expr() - axis.clone()) * inv_128;
        let row_high4 = (row_high4_formula.expr() - row_low7_formula.expr()) * inv_16384;
        let head = (head_formula.expr() - row_high4_formula.expr()) * inv_262144;
        let tile = tile_formula.expr();
        let row_high_is_zero = cb.create_witin(|| "production_pv_row_high_is_zero");
        let row_high_inverse = cb.create_witin(|| "production_pv_row_high_inverse");
        let row_high_is_last = cb.create_witin(|| "production_pv_row_high_is_last");
        let row_high_last_inverse = cb.create_witin(|| "production_pv_row_high_last_inverse");
        let tile_is_zero = cb.create_witin(|| "production_pv_tile_is_zero");
        let tile_inverse = cb.create_witin(|| "production_pv_tile_inverse");
        let tile_is_last = cb.create_witin(|| "production_pv_tile_is_last");
        let tile_last_inverse = cb.create_witin(|| "production_pv_tile_last_inverse");
        zero_indicator(
            cb,
            "production_pv_row_high_zero_exact",
            row_high4.expr(),
            row_high_is_zero,
            row_high_inverse,
        )?;
        zero_indicator(
            cb,
            "production_pv_row_high_last_exact",
            row_high4.expr() - 15,
            row_high_is_last,
            row_high_last_inverse,
        )?;
        zero_indicator(
            cb,
            "production_pv_tile_zero_exact",
            tile.expr(),
            tile_is_zero,
            tile_inverse,
        )?;
        zero_indicator(
            cb,
            "production_pv_tile_last_exact",
            tile.expr() - 15,
            tile_is_last,
            tile_last_inverse,
        )?;
        let physical_index = cb.create_structural_witin(
            || "production_pv_physical_index",
            StructuralWitInType::OuterRepeatingIncrementalSequence {
                k: ROW_BITS,
                n: ROW_BITS,
            },
        );
        let matrix_a_selector = cb.create_placeholder_structural_witin(|| "matrix_a_selector");
        let matrix_w_selector = cb.create_placeholder_structural_witin(|| "matrix_w_selector");
        let matrix_output_selector =
            cb.create_placeholder_structural_witin(|| "matrix_output_selector");
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let row: Expression<E> = row_low7.expr() + row_high4.expr() * 128;
        cb.require_equal(
            || "production_pv_physical_coordinate",
            physical_index.expr(),
            axis.expr()
                + row.clone() * 128
                + head.expr() * (1u64 << 18)
                + tile.expr() * (1u64 << (18 + HEAD_GROUP_BITS)),
        )?;

        let accumulator_q_before = cb.create_witin(|| "production_pv_accumulator_q_before");
        let accumulator_r_before = cb.create_witin(|| "production_pv_accumulator_r_before");
        let accumulator_q_after = cb.create_witin(|| "production_pv_accumulator_q_after");
        let accumulator_q_after_sign = cb.create_witin(|| "production_pv_accumulator_q_after_sign");
        let accumulator_q_after_limbs = core::array::from_fn(|index| {
            cb.create_witin(|| format!("production_pv_accumulator_q_after_limb_{index}"))
        });
        let accumulator_r_after = cb.create_witin(|| "production_pv_accumulator_r_after");
        let accumulator_r_after_low16 =
            cb.create_witin(|| "production_pv_accumulator_r_after_low16");
        let accumulator_r_after_high4 =
            cb.create_witin(|| "production_pv_accumulator_r_after_high4");
        signed_u64_limbs(
            cb,
            "production_pv_accumulator_q_after",
            accumulator_q_after,
            accumulator_q_after_sign,
            accumulator_q_after_limbs,
        )?;
        dynamic_range(
            cb,
            "production_pv_accumulator_r_after",
            accumulator_r_after_low16,
            16,
        )?;
        dynamic_range(
            cb,
            "production_pv_accumulator_r_after",
            accumulator_r_after_high4,
            4,
        )?;
        cb.require_equal(
            || "production_pv_accumulator_r_after",
            accumulator_r_after.expr() + Q20_HALF,
            accumulator_r_after_low16.expr() + accumulator_r_after_high4.expr() * (1u64 << 16),
        )?;
        let carry = cb.create_witin(|| "production_pv_carry");
        cb.require_zero(
            || "production_pv_carry_trit",
            carry.expr()
                * (carry.expr() - E::BaseField::ONE.expr())
                * (carry.expr() + E::BaseField::ONE.expr()),
        )?;
        cb.require_equal(
            || "production_pv_remainder_accumulate",
            accumulator_r_before.expr() + remainder.expr(),
            carry.expr() * Q20_SCALE + accumulator_r_after.expr(),
        )?;
        cb.require_equal(
            || "production_pv_quotient_accumulate",
            accumulator_q_after.expr(),
            accumulator_q_before.expr() + q.expr() + carry.expr(),
        )?;
        cb.require_zero(
            || "production_pv_accumulator_seed_q",
            tile_is_zero.expr() * accumulator_q_before.expr(),
        )?;
        cb.require_zero(
            || "production_pv_accumulator_seed_r",
            tile_is_zero.expr() * accumulator_r_before.expr(),
        )?;
        let final_q = cb.create_witin(|| "production_pv_final_q");
        let final_remainder = cb.create_witin(|| "production_pv_final_remainder");
        let final_remainder_low16 = cb.create_witin(|| "production_pv_final_remainder_low16");
        let final_remainder_high4 = cb.create_witin(|| "production_pv_final_remainder_high4");
        dynamic_range(
            cb,
            "production_pv_final_remainder_low16_range",
            final_remainder_low16,
            16,
        )?;
        dynamic_range(
            cb,
            "production_pv_final_remainder_high4_range",
            final_remainder_high4,
            4,
        )?;
        cb.require_equal(
            || "production_pv_final_centered_remainder",
            final_remainder.expr() + Q20_HALF,
            final_remainder_low16.expr() + final_remainder_high4.expr() * (1u64 << 16),
        )?;
        cb.require_equal(
            || "production_pv_second_q20_rescale",
            accumulator_q_after.expr(),
            final_q.expr() * Q20_SCALE + final_remainder.expr(),
        )?;

        let import_cycle = cb.create_witin(|| "production_pv_import_cycle");
        let input_id_lo = cb.create_witin(|| "production_pv_input_id_lo");
        let input_id_hi = cb.create_witin(|| "production_pv_input_id_hi");
        let input_version = cb.create_witin(|| "production_pv_input_version");
        let output_id_lo = cb.create_witin(|| "production_pv_output_id_lo");
        let output_id_hi = cb.create_witin(|| "production_pv_output_id_hi");
        let output_version = cb.create_witin(|| "production_pv_output_version");
        let key = tile.expr() * 128 + axis.expr();
        let probability_index = (head.expr() * SEQUENCE + row.clone()) * SEQUENCE + key;
        cb.read_record(
            || "production_pv_probability_read",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + PROBABILITY_VERSION_OFFSET,
                probability_index,
                a.expr(),
            ),
        )?;
        let v_key: Expression<E> = tile.expr() * 128 + row_low7.expr();
        let group_words = HEADS_PER_CORE * SEQUENCE * HEAD_DIM;
        let v_index = E::BaseField::from_u64(2 * group_words).expr()
            + (head.expr() * SEQUENCE + v_key.clone()) * HEAD_DIM
            + axis.expr();
        let v_record = tensor_space_record(
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            v_index.clone(),
            w.expr() * Q20_SCALE,
        );
        cb.read_rlc_record(
            || "production_pv_v_read_once",
            conditional_type(row_high_is_zero.expr()),
            v_record.clone(),
            conditional_rlc(cb, row_high_is_zero.expr(), &v_record),
        )?;
        let w_state_in = pv_state_record(
            PV_W_STATE_VERSION,
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            GROUP,
            v_index.clone(),
            row_high4.expr(),
            [w.expr()],
        );
        let w_state_selector = E::BaseField::ONE.expr() - row_high_is_zero.expr();
        cb.read_rlc_record(
            || "production_pv_w_state_read",
            conditional_type(w_state_selector.clone()),
            w_state_in.clone(),
            conditional_rlc(cb, w_state_selector, &w_state_in),
        )?;
        let w_state_out = pv_state_record(
            PV_W_STATE_VERSION,
            import_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            GROUP,
            v_index,
            row_high4.expr() + 1,
            [w.expr()],
        );
        let w_write_selector = E::BaseField::ONE.expr() - row_high_is_last.expr();
        cb.write_rlc_record(
            || "production_pv_w_state_write",
            conditional_type(w_write_selector.clone()),
            w_state_out.clone(),
            conditional_rlc(cb, w_write_selector, &w_state_out),
        )?;

        let global_head =
            E::BaseField::from_u64((GROUP * HEADS_PER_CORE as usize) as u64).expr() + head.expr();
        let context_index = (global_head * SEQUENCE + row) * HEAD_DIM + axis.expr();
        let accumulator_in = pv_state_record(
            PV_STATE_VERSION,
            import_cycle.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            GROUP,
            context_index.clone(),
            tile.expr(),
            [accumulator_q_before.expr(), accumulator_r_before.expr()],
        );
        let accumulator_read_selector = E::BaseField::ONE.expr() - tile_is_zero.expr();
        cb.read_rlc_record(
            || "production_pv_accumulator_read",
            conditional_type(accumulator_read_selector.clone()),
            accumulator_in.clone(),
            conditional_rlc(cb, accumulator_read_selector, &accumulator_in),
        )?;
        let accumulator_out = pv_state_record(
            PV_STATE_VERSION,
            import_cycle.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            GROUP,
            context_index.clone(),
            tile.expr() + 1,
            [accumulator_q_after.expr(), accumulator_r_after.expr()],
        );
        let accumulator_write_selector = E::BaseField::ONE.expr() - tile_is_last.expr();
        cb.write_rlc_record(
            || "production_pv_accumulator_write",
            conditional_type(accumulator_write_selector.clone()),
            accumulator_out.clone(),
            conditional_rlc(cb, accumulator_write_selector, &accumulator_out),
        )?;
        let context_record = tensor_space_record(
            import_cycle.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            context_index,
            final_q.expr(),
        );
        cb.write_rlc_record(
            || "production_pv_context_write",
            conditional_type(tile_is_last.expr()),
            context_record.clone(),
            conditional_rlc(cb, tile_is_last.expr(), &context_record),
        )?;

        Ok(TensorProductionPvCoreConfig {
            a,
            w,
            q,
            remainder,
            probability_low16,
            probability_mid16,
            probability_high9,
            w_sign,
            w_low16,
            w_high15,
            q_sign,
            q_limbs,
            remainder_low16,
            remainder_high4,
            row_high_is_zero,
            row_high_inverse,
            row_high_is_last,
            row_high_last_inverse,
            tile_is_zero,
            tile_inverse,
            tile_is_last,
            tile_last_inverse,
            accumulator_q_before,
            accumulator_r_before,
            accumulator_q_after,
            accumulator_q_after_sign,
            accumulator_q_after_limbs,
            accumulator_r_after,
            accumulator_r_after_low16,
            accumulator_r_after_high4,
            carry,
            final_q,
            final_remainder,
            final_remainder_low16,
            final_remainder_high4,
            import_cycle,
            input_id_lo,
            input_id_hi,
            input_version,
            output_id_lo,
            output_id_hi,
            output_version,
            physical_index,
            axis: axis_formula,
            row_low7: row_low7_formula,
            row_high4: row_high4_formula,
            head: head_formula,
            tile: tile_formula,
            matrix_a_selector,
            matrix_w_selector,
            matrix_output_selector,
            selector,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        assert_eq!(
            cb.cs.num_witin as usize, 48,
            "production PV witness width changed"
        );
        assert_eq!(
            cb.cs.num_structural_witin as usize, 10,
            "production PV structural width changed"
        );
        let reads = cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len();
        let writes = cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len();
        let lookups = cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len();
        assert_eq!(reads, 4, "production PV TensorBus/state read count changed");
        assert_eq!(
            writes, 3,
            "production PV TensorBus/state write count changed"
        );
        assert_eq!(
            lookups, 19,
            "production PV Dynamic-range record count changed"
        );
        for expected in [
            "production_pv_probability_read",
            "production_pv_v_read_once",
            "production_pv_w_state_read",
            "production_pv_accumulator_read",
        ] {
            assert!(
                cb.cs
                    .r_expressions_namespace_map
                    .iter()
                    .any(|name| name.ends_with(expected)),
                "production PV read record identity changed: {expected}"
            );
        }
        for expected in [
            "production_pv_w_state_write",
            "production_pv_accumulator_write",
            "production_pv_context_write",
        ] {
            assert!(
                cb.cs
                    .w_expressions_namespace_map
                    .iter()
                    .any(|name| name.ends_with(expected)),
                "production PV write record identity changed: {expected}"
            );
        }
        let lookup_virtual_rows = (ROWS / 2) * lookups.next_power_of_two();
        assert_eq!(
            lookup_virtual_rows,
            (HEADS_PER_CORE as usize) << 26,
            "production PV lookup virtual group changed"
        );
        let columns = [config.a, config.w, config.q, config.remainder];
        let selectors = [
            config.matrix_a_selector,
            config.matrix_w_selector,
            config.matrix_output_selector,
            config.selector,
        ];
        add_matrix_layer(cb, Self::name(), config, columns, selectors)
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            "production PV requires deterministic device replay".into(),
        ))
    }
}

const _: () = assert!(ROWS == ceno_emul::tensor::production_attention::GROUP_SCORE_ROWS);
