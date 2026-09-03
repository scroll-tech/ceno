//! One-domain production QK, shift, and causal-softmax relation.
//!
//! The QK matrix identity, shift witness, and softmax relation remain separate
//! logical sections. Their only internal seams are the constrained QK `q` and
//! `remainder` cells and the softmax shift cell.

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

const ROWS_PER_HEAD_BITS: usize = 22;
const ACTIVE_HEADS_PER_SHARD: usize = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
const ACTIVE_ROWS: usize = ACTIVE_HEADS_PER_SHARD << ROWS_PER_HEAD_BITS;
const SEQUENCE: u64 = 2048;
const HEAD_DIM: u64 = 128;
const ATTENTION_CALL_VERSION: u64 = 9;
const PROBABILITY_VERSION_OFFSET: u64 = 2;
const Q16_SCALE: u64 = 1 << 16;

pub struct TensorAttentionQkShiftSoftmax<E, const HEADS_PER_SHARD: usize>(PhantomData<E>);

pub type TensorProductionQkShiftSoftmaxCoreInstruction<E> =
    TensorAttentionQkShiftSoftmax<E, ACTIVE_HEADS_PER_SHARD>;

#[derive(Debug)]
pub struct TensorProductionQkShiftSoftmaxCoreConfig {
    // QK matrix-reduction columns.
    pub(crate) a: WitIn,
    pub(crate) w: WitIn,
    pub(crate) q: WitIn,
    pub(crate) remainder: WitIn,
    a_low7: WitIn,
    a_sign: WitIn,
    w_low7: WitIn,
    w_sign: WitIn,
    axis_active: WitIn,
    axis_high_inverse: WitIn,
    row_active: WitIn,
    row_high_inverse: WitIn,
    // Shared descriptor columns.
    import_cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    layer: WitIn,
    head_start: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    call_row_inverse: WitIn,
    // Shift and Softmax columns. There is deliberately no score column.
    shift: WitIn,
    limbs: [WitIn; 3],
    exp3: WitIn,
    exp4: WitIn,
    causal: WitIn,
    comparison_diff_bits: [WitIn; 11],
    probability: WitIn,
    // One shared coordinate/layout definition.
    axis_low7: StructuralWitIn,
    axis_high4: StructuralWitIn,
    row_low7: StructuralWitIn,
    row_high4: StructuralWitIn,
    physical_index: StructuralWitIn,
    matrix_a_selector: StructuralWitIn,
    matrix_w_selector: StructuralWitIn,
    matrix_output_selector: StructuralWitIn,
    selector: StructuralWitIn,
}

impl TensorProductionQkShiftSoftmaxCoreConfig {
    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionQkShiftSoftmaxColumnMap, ZKVMError>
    {
        use ceno_gpu::common::witgen::ProductionAttentionQkShiftSoftmaxColumnMap;
        let id = |cell: WitIn| cell.id as u32;
        let sid = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionQkShiftSoftmaxColumnMap {
            witness: [
                id(self.a),
                id(self.w),
                id(self.q),
                id(self.remainder),
                id(self.a_low7),
                id(self.a_sign),
                id(self.w_low7),
                id(self.w_sign),
                id(self.axis_active),
                id(self.axis_high_inverse),
                id(self.row_active),
                id(self.row_high_inverse),
                id(self.import_cycle),
                id(self.input_id_lo),
                id(self.input_id_hi),
                id(self.input_version),
                id(self.layer),
                id(self.head_start),
                id(self.output_id_lo),
                id(self.output_id_hi),
                id(self.output_version),
                id(self.call_row_inverse),
                id(self.shift),
                id(self.limbs[0]),
                id(self.limbs[1]),
                id(self.limbs[2]),
                id(self.exp3),
                id(self.exp4),
                id(self.causal),
                id(self.comparison_diff_bits[0]),
                id(self.comparison_diff_bits[1]),
                id(self.comparison_diff_bits[2]),
                id(self.comparison_diff_bits[3]),
                id(self.comparison_diff_bits[4]),
                id(self.comparison_diff_bits[5]),
                id(self.comparison_diff_bits[6]),
                id(self.comparison_diff_bits[7]),
                id(self.comparison_diff_bits[8]),
                id(self.comparison_diff_bits[9]),
                id(self.comparison_diff_bits[10]),
                id(self.probability),
            ],
            structural: [
                sid(self.physical_index),
                sid(self.axis_low7),
                sid(self.axis_high4),
                sid(self.row_low7),
                sid(self.row_high4),
                sid(self.matrix_a_selector),
                sid(self.matrix_w_selector),
                sid(self.matrix_output_selector),
                sid(self.selector),
            ],
            num_witin: num_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness(
                    "production fused attention witness width overflow".into(),
                )
            })?,
            num_structural_witin: num_structural_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness(
                    "production fused attention structural width overflow".into(),
                )
            })?,
        };
        if num_witin != 41
            || num_structural_witin != 9
            || map.witness != core::array::from_fn(|index| index as u32)
            || map.structural != [4, 0, 1, 2, 3, 5, 6, 7, 8]
        {
            return Err(ZKVMError::InvalidWitness(
                "production fused attention device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

fn tensor_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    layer: Expression<E>,
    id_lo: Expression<E>,
    id_hi: Expression<E>,
    version: Expression<E>,
    index: Expression<E>,
    value: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::ONE.expr(),
        import_cycle,
        layer,
        id_lo,
        id_hi,
        version,
        index,
        value,
    ]
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

fn signed_byte<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: WitIn,
    low7: WitIn,
    sign: WitIn,
) -> Result<(), ZKVMError> {
    cb.assert_bit(|| name, sign.expr())?;
    dynamic_range(cb, name, low7, 7)?;
    Ok(cb.require_equal(
        || name,
        value.expr(),
        low7.expr() - sign.expr() * E::BaseField::from_u32(128).expr(),
    )?)
}

fn zero_indicator<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &'static str,
    value: Expression<E>,
    indicator: WitIn,
    inverse: WitIn,
) -> Result<(), ZKVMError> {
    cb.assert_bit(|| name, indicator.expr())?;
    cb.require_zero(|| name, indicator.expr() * value.clone())?;
    Ok(cb.require_equal(
        || name,
        value * inverse.expr(),
        E::BaseField::ONE.expr() - indicator.expr(),
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

fn add_qk_relation<E: ExtensionField, const HEADS_PER_SHARD: usize>(
    cb: &mut CircuitBuilder<E>,
) -> Result<
    (
        TensorProductionQkShiftSoftmaxCoreConfig,
        Expression<E>,
        Expression<E>,
    ),
    ZKVMError,
> {
    let a = cb.create_witin(|| "production_fused_qk_a");
    let w = cb.create_witin(|| "production_fused_qk_w");
    let q = cb.create_witin(|| "production_fused_qk_q");
    let remainder = cb.create_witin(|| "production_fused_qk_remainder");
    let a_low7 = cb.create_witin(|| "production_fused_qk_a_low7");
    let a_sign = cb.create_witin(|| "production_fused_qk_a_sign");
    let w_low7 = cb.create_witin(|| "production_fused_qk_w_low7");
    let w_sign = cb.create_witin(|| "production_fused_qk_w_sign");
    signed_byte(cb, "production_fused_qk_a_signed_byte", a, a_low7, a_sign)?;
    signed_byte(cb, "production_fused_qk_w_signed_byte", w, w_low7, w_sign)?;
    cb.require_zero(|| "production_fused_qk_quotient", q.expr() * (q.expr() + 1))?;
    dynamic_range(cb, "production_fused_qk_remainder_u16", remainder, 16)?;

    let axis_low7_formula = cb.create_structural_witin(
        || "production_fused_axis_low7_prefix",
        StructuralWitInType::OuterRepeatingIncrementalSequence {
            k: 7,
            n: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
        },
    );
    let axis_high4_formula = cb.create_structural_witin(
        || "production_fused_axis_high4_prefix",
        StructuralWitInType::OuterRepeatingIncrementalSequence {
            k: 11,
            n: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
        },
    );
    let row_low7_formula = cb.create_structural_witin(
        || "production_fused_row_low7_prefix",
        StructuralWitInType::OuterRepeatingIncrementalSequence {
            k: 18,
            n: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
        },
    );
    let row_high4_formula = cb.create_structural_witin(
        || "production_fused_row_high4_prefix",
        StructuralWitInType::OuterRepeatingIncrementalSequence {
            k: ROWS_PER_HEAD_BITS,
            n: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
        },
    );
    let axis_low7 = axis_low7_formula.expr();
    let axis_high4 = (axis_high4_formula.expr() - axis_low7_formula.expr())
        * E::BaseField::from_u64(1 << 7).inverse().expr();
    let row_low7 = (row_low7_formula.expr() - axis_high4_formula.expr())
        * E::BaseField::from_u64(1 << 11).inverse().expr();
    let row_high4 = (row_high4_formula.expr() - row_low7_formula.expr())
        * E::BaseField::from_u64(1 << 18).inverse().expr();
    let axis_active = cb.create_witin(|| "production_fused_qk_axis_active");
    let axis_high_inverse = cb.create_witin(|| "production_fused_qk_axis_high_inverse");
    let row_active = cb.create_witin(|| "production_fused_qk_row_active");
    let row_high_inverse = cb.create_witin(|| "production_fused_qk_row_high_inverse");
    zero_indicator(
        cb,
        "production_fused_qk_axis_active_exact",
        axis_high4.clone(),
        axis_active,
        axis_high_inverse,
    )?;
    zero_indicator(
        cb,
        "production_fused_qk_row_active_exact",
        row_high4.clone(),
        row_active,
        row_high_inverse,
    )?;
    cb.require_zero(
        || "production_fused_qk_a_padding",
        (E::BaseField::ONE.expr() - axis_active.expr()) * a.expr(),
    )?;
    cb.require_zero(
        || "production_fused_qk_w_padding",
        (E::BaseField::ONE.expr() - row_active.expr()) * w.expr(),
    )?;

    let physical_index = cb.create_structural_witin(
        || "production_fused_physical_index",
        StructuralWitInType::OuterRepeatingIncrementalSequence {
            k: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
            n: ROWS_PER_HEAD_BITS + HEADS_PER_SHARD.trailing_zeros() as usize,
        },
    );
    let matrix_a_selector = cb.create_placeholder_structural_witin(|| "matrix_a_selector");
    let matrix_w_selector = cb.create_placeholder_structural_witin(|| "matrix_w_selector");
    let matrix_output_selector =
        cb.create_placeholder_structural_witin(|| "matrix_output_selector");
    let selector = cb.create_placeholder_structural_witin(|| "selector");
    let key: Expression<E> = axis_low7.clone() + axis_high4 * 128;
    let query: Expression<E> = row_low7.clone() + row_high4 * 128;
    let local_row = row_high4_formula.expr();
    let slot = (physical_index.expr() - local_row.clone())
        * E::BaseField::from_u64(1 << ROWS_PER_HEAD_BITS)
            .inverse()
            .expr();
    cb.require_equal(
        || "production_fused_physical_coordinate",
        physical_index.expr(),
        key.clone() + query.clone() * SEQUENCE + slot.clone() * (1 << ROWS_PER_HEAD_BITS),
    )?;

    let import_cycle = cb.create_witin(|| "production_fused_import_cycle");
    let input_id_lo = cb.create_witin(|| "production_fused_input_id_lo");
    let input_id_hi = cb.create_witin(|| "production_fused_input_id_hi");
    let input_version = cb.create_witin(|| "production_fused_input_version");
    let layer = cb.create_witin(|| "production_fused_layer");
    let head_start = cb.create_witin(|| "production_fused_head_start");
    let output_id_lo = cb.create_witin(|| "production_fused_output_id_lo");
    let output_id_hi = cb.create_witin(|| "production_fused_output_id_hi");
    let output_version = cb.create_witin(|| "production_fused_output_version");
    let call_row_inverse = cb.create_witin(|| "production_fused_call_row_inverse");
    let call_row = E::BaseField::ONE.expr() - local_row.clone() * call_row_inverse.expr();
    cb.require_zero(
        || "production_fused_call_row_exact",
        local_row * call_row.clone(),
    )?;
    let call_record = vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u64(ATTENTION_CALL_VERSION).expr(),
        import_cycle.expr(),
        input_id_lo.expr(),
        input_id_hi.expr(),
        input_version.expr(),
        output_id_lo.expr(),
        output_id_hi.expr(),
        output_version.expr(),
        E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER).expr(),
        layer.expr(),
        E::BaseField::ONE.expr(),
        head_start.expr() + slot.clone(),
        E::BaseField::ONE.expr(),
    ];
    cb.read_rlc_record(
        || "production_fused_attention_call_once",
        conditional_type(call_row.clone()),
        call_record.clone(),
        conditional_rlc(cb, call_row, &call_record),
    )?;
    let q_record = tensor_record(
        import_cycle.expr(),
        layer.expr(),
        input_id_lo.expr(),
        input_id_hi.expr(),
        input_version.expr(),
        query.clone() * HEAD_DIM + axis_low7.clone(),
        a.expr(),
    );
    cb.read_rlc_record(
        || "production_fused_q_read",
        conditional_type(axis_active.expr()),
        q_record.clone(),
        conditional_rlc(cb, axis_active.expr(), &q_record),
    )?;
    let k_record = tensor_record(
        import_cycle.expr(),
        layer.expr(),
        input_id_lo.expr(),
        input_id_hi.expr(),
        input_version.expr(),
        E::BaseField::from_u64(SEQUENCE * HEAD_DIM).expr() + key.clone() * HEAD_DIM + row_low7,
        w.expr(),
    );
    cb.read_rlc_record(
        || "production_fused_k_read",
        conditional_type(row_active.expr()),
        k_record.clone(),
        conditional_rlc(cb, row_active.expr(), &k_record),
    )?;

    // Allocate the direct Shift/Softmax cells after all QK/shared columns.
    let shift = cb.create_witin(|| "production_fused_shift");
    let limbs =
        core::array::from_fn(|i| cb.create_witin(|| format!("production_fused_softmax_limb_{i}")));
    let exp3 = cb.create_witin(|| "production_fused_softmax_exp3");
    let exp4 = cb.create_witin(|| "production_fused_softmax_exp4");
    let causal = cb.create_witin(|| "production_fused_softmax_causal");
    let comparison_diff_bits = core::array::from_fn(|i| {
        cb.create_witin(|| format!("production_fused_softmax_diff_bit_{i}"))
    });
    let probability = cb.create_witin(|| "production_fused_softmax_probability");
    Ok((
        TensorProductionQkShiftSoftmaxCoreConfig {
            a,
            w,
            q,
            remainder,
            a_low7,
            a_sign,
            w_low7,
            w_sign,
            axis_active,
            axis_high_inverse,
            row_active,
            row_high_inverse,
            import_cycle,
            input_id_lo,
            input_id_hi,
            input_version,
            layer,
            head_start,
            output_id_lo,
            output_id_hi,
            output_version,
            call_row_inverse,
            shift,
            limbs,
            exp3,
            exp4,
            causal,
            comparison_diff_bits,
            probability,
            axis_low7: axis_low7_formula,
            axis_high4: axis_high4_formula,
            row_low7: row_low7_formula,
            row_high4: row_high4_formula,
            physical_index,
            matrix_a_selector,
            matrix_w_selector,
            matrix_output_selector,
            selector,
        },
        key,
        query,
    ))
}

fn add_softmax_relation<E: ExtensionField, const HEADS_PER_SHARD: usize>(
    cb: &mut CircuitBuilder<E>,
    config: &TensorProductionQkShiftSoftmaxCoreConfig,
    key: Expression<E>,
    query: Expression<E>,
) -> Result<(), ZKVMError> {
    for (i, (limb, bits)) in config.limbs.iter().zip([8_u32, 20, 20]).enumerate() {
        cb.lk_record(
            || format!("production_fused_softmax_digit_{i}_range"),
            LookupTable::Dynamic,
            vec![limb.expr(), E::BaseField::from_u32(bits).expr()],
        )?;
    }
    let magnitude = config.limbs[0].expr()
        + config.limbs[1].expr() * (1 << 8)
        + config.limbs[2].expr() * E::BaseField::from_u64(1 << 28).expr();
    let score = config.q.expr() * Q16_SCALE + config.remainder.expr();
    cb.require_equal(
        || "production_fused_softmax_shifted_magnitude",
        config.shift.expr() - score,
        magnitude,
    )?;
    cb.lk_record(
        || "production_fused_softmax_exp3_lookup",
        LookupTable::LlamaProductionSoftmaxExpMiddle,
        vec![config.limbs[1].expr(), config.exp3.expr()],
    )?;
    cb.lk_record(
        || "production_fused_softmax_exp4_lookup",
        LookupTable::LlamaProductionSoftmaxExpHigh,
        vec![config.limbs[2].expr(), config.exp4.expr()],
    )?;
    cb.assert_bit(
        || "production_fused_softmax_causal_bit",
        config.causal.expr(),
    )?;
    for bit in config.comparison_diff_bits {
        cb.assert_bit(|| "production_fused_softmax_diff_bit", bit.expr())?;
    }
    let diff: Expression<E> = config
        .comparison_diff_bits
        .iter()
        .enumerate()
        .map(|(i, bit)| bit.expr() * E::BaseField::from_u64(1 << i).expr())
        .sum();
    cb.require_equal(
        || "production_fused_softmax_causal_comparison",
        query.clone() - key.clone(),
        config.causal.expr() * diff.clone()
            - (E::BaseField::ONE.expr() - config.causal.expr()) * (diff + 1),
    )?;
    cb.require_equal(
        || "production_fused_softmax_masked_probability",
        config.probability.expr(),
        config.causal.expr() * config.exp3.expr() * config.exp4.expr(),
    )?;
    let index = query * SEQUENCE + key;
    cb.write_record(
        || "production_fused_softmax_probability_write",
        RAMType::Custom,
        tensor_record(
            config.import_cycle.expr(),
            config.layer.expr(),
            config.output_id_lo.expr(),
            config.output_id_hi.expr(),
            config.output_version.expr() + PROBABILITY_VERSION_OFFSET,
            index,
            config.probability.expr(),
        ),
    )?;
    Ok(())
}

impl<E: ExtensionField, const HEADS_PER_SHARD: usize> Instruction<E>
    for TensorAttentionQkShiftSoftmax<E, HEADS_PER_SHARD>
{
    type InstructionConfig = TensorProductionQkShiftSoftmaxCoreConfig;
    type InsnType = InsnKind;
    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }
    fn name() -> String {
        if HEADS_PER_SHARD == ACTIVE_HEADS_PER_SHARD {
            "TensorAttentionQkShiftSoftmax".into()
        } else {
            format!("TensorAttentionQkShiftSoftmaxHeads{HEADS_PER_SHARD}")
        }
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        assert!(
            HEADS_PER_SHARD.is_power_of_two() && HEADS_PER_SHARD <= 32,
            "HEADS_PER_SHARD must be a nonzero power of two no larger than 32"
        );
        let (config, key, query) = add_qk_relation::<E, HEADS_PER_SHARD>(cb)?;
        add_softmax_relation::<E, HEADS_PER_SHARD>(cb, &config, key, query)?;
        Ok(config)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        assert_eq!(
            cb.cs.num_witin as usize, 41,
            "production fused attention witness width changed"
        );
        assert_eq!(
            cb.cs.num_structural_witin as usize, 9,
            "production fused attention structural width changed"
        );
        assert_eq!(
            cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len(),
            3,
            "production fused attention read record count changed"
        );
        assert_eq!(
            cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len(),
            1,
            "production fused attention write record count changed"
        );
        assert_eq!(
            cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len(),
            8,
            "production fused attention lookup count changed"
        );
        let selector = SelectorType::Prefix(config.selector.expr());
        cb.cs.r_selector = Some(selector.clone());
        cb.cs.w_selector = Some(selector.clone());
        cb.cs.lk_selector = Some(selector.clone());
        cb.cs.zero_selector = Some(selector);
        let mut chip = Chip::new_from_cb(cb);
        let ordinary = chip.final_out_evals.len();
        let mut layer = Layer::from_circuit_builder(
            cb,
            format!("{}_main", Self::name()),
            default_out_eval_groups(cb),
        );
        layer.add_matrix_identity_groups(
            [
                config.matrix_a_selector.expr(),
                config.matrix_w_selector.expr(),
                config.matrix_output_selector.expr(),
            ],
            [
                config.a.expr(),
                config.w.expr(),
                config.q.expr(),
                config.remainder.expr(),
            ],
        );
        chip.n_evaluations += 4;
        chip.final_out_evals = (0..ordinary + 4).collect();
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
            "production fused attention requires deterministic device replay".into(),
        ))
    }
}

#[cfg(not(feature = "llama-tiny"))]
const _: () = assert!(ACTIVE_ROWS == ceno_emul::tensor::production_attention::GROUP_SCORE_ROWS);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::ConstraintSystem,
        scheme::mock_prover::MockProver,
        tables::{LlamaTinyRom, ProductionSoftmaxExpHighRom, ProductionSoftmaxExpMiddleRom},
    };
    use ff_ext::{BabyBearExt4, FieldFrom};
    use multilinear_extensions::{
        mle::{ArcMultilinearExtension, MultilinearExtension},
        utils::eval_by_expr_with_instance,
    };
    use p3::field::PrimeField64;

    type E = BabyBearExt4;
    type F = <E as ExtensionField>::BaseField;

    fn circuit() -> (
        ConstraintSystem<E>,
        TensorProductionQkShiftSoftmaxCoreConfig,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| {
            TensorProductionQkShiftSoftmaxCoreInstruction::<E>::name()
        });
        let config = {
            let mut cb = CircuitBuilder::new(&mut cs);
            TensorProductionQkShiftSoftmaxCoreInstruction::construct_circuit(
                &mut cb,
                &ProgramParams::default(),
            )
            .unwrap()
        };
        (cs, config)
    }

    fn generic_circuit<const N: usize>() -> (
        ConstraintSystem<E>,
        TensorProductionQkShiftSoftmaxCoreConfig,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| TensorAttentionQkShiftSoftmax::<E, N>::name());
        let config = {
            let mut cb = CircuitBuilder::new(&mut cs);
            TensorAttentionQkShiftSoftmax::<E, N>::construct_circuit(
                &mut cb,
                &ProgramParams::default(),
            )
            .unwrap()
        };
        (cs, config)
    }

    fn canonical_row(config: &TensorProductionQkShiftSoftmaxCoreConfig) -> (Vec<F>, Vec<F>) {
        let mut witness = vec![F::ZERO; 41];
        let mut structural = vec![F::ZERO; 9];
        let key = 0_u64;
        let query = 1_u64;
        let physical = key + query * SEQUENCE;
        let set = |values: &mut [F], cell: WitIn, value: F| values[cell.id as usize] = value;
        let sset = |values: &mut [F], cell: StructuralWitIn, value: F| {
            values[cell.id as usize] = value;
        };

        set(&mut witness, config.a, F::from_u64(2));
        set(&mut witness, config.w, -F::from_u64(3));
        set(&mut witness, config.q, -F::ONE);
        set(&mut witness, config.remainder, F::from_u64(65_530));
        set(&mut witness, config.a_low7, F::from_u64(2));
        set(&mut witness, config.w_low7, F::from_u64(125));
        set(&mut witness, config.w_sign, F::ONE);
        set(&mut witness, config.axis_active, F::ONE);
        set(&mut witness, config.row_active, F::ONE);
        set(&mut witness, config.import_cycle, F::from_u64(3));
        set(&mut witness, config.input_id_lo, F::from_u64(4));
        set(&mut witness, config.input_id_hi, F::from_u64(5));
        set(&mut witness, config.input_version, F::from_u64(6));
        set(&mut witness, config.layer, F::from_u64(7));
        set(&mut witness, config.head_start, F::from_u64(8));
        set(&mut witness, config.output_id_lo, F::from_u64(9));
        set(&mut witness, config.output_id_hi, F::from_u64(10));
        set(&mut witness, config.output_version, F::from_u64(11));
        set(
            &mut witness,
            config.call_row_inverse,
            F::from_u64(physical).inverse(),
        );
        set(&mut witness, config.shift, F::from_u64(10));
        set(&mut witness, config.limbs[0], F::from_u64(16));
        let exp3 = F::from_u64(ProductionSoftmaxExpMiddleRom::output(0) as u64);
        let exp4 = F::from_u64(ProductionSoftmaxExpHighRom::output(0) as u64);
        set(&mut witness, config.exp3, exp3);
        set(&mut witness, config.exp4, exp4);
        set(&mut witness, config.causal, F::ONE);
        set(&mut witness, config.comparison_diff_bits[0], F::ONE);
        set(&mut witness, config.probability, exp3 * exp4);

        sset(&mut structural, config.axis_low7, F::from_u64(key));
        sset(&mut structural, config.axis_high4, F::from_u64(key));
        sset(
            &mut structural,
            config.row_low7,
            F::from_u64(key + (query & 127) * (1 << 11)),
        );
        sset(&mut structural, config.row_high4, F::from_u64(physical));
        sset(
            &mut structural,
            config.physical_index,
            F::from_u64(physical),
        );
        for cell in [
            config.matrix_a_selector,
            config.matrix_w_selector,
            config.matrix_output_selector,
            config.selector,
        ] {
            sset(&mut structural, cell, F::ONE);
        }
        (witness, structural)
    }

    fn eval(expr: &Expression<E>, witness: &[F], structural: &[F]) -> E {
        let witness = witness.iter().copied().map(E::from).collect::<Vec<_>>();
        let structural = structural.iter().copied().map(E::from).collect::<Vec<_>>();
        eval_by_expr_with_instance::<E>(
            &[],
            &witness,
            &structural,
            &[],
            &[E::from_v(7), E::from_v(11)],
            expr,
        )
        .unwrap_right()
    }

    fn named_zero<'a>(cs: &'a ConstraintSystem<E>, needle: &str) -> &'a Expression<E> {
        cs.assert_zero_expressions_namespace_map
            .iter()
            .zip(&cs.assert_zero_expressions)
            .chain(
                cs.assert_zero_sumcheck_expressions_namespace_map
                    .iter()
                    .zip(&cs.assert_zero_sumcheck_expressions),
            )
            .find_map(|(name, expression)| name.contains(needle).then_some(expression))
            .unwrap_or_else(|| panic!("missing fused constraint {needle}"))
    }

    fn one_row_mles(values: &[F]) -> Vec<ArcMultilinearExtension<'_, E>> {
        values
            .iter()
            .map(|value| MultilinearExtension::from_evaluation_vec_smart(0, vec![*value]).into())
            .collect()
    }

    fn structural_row(config: &TensorProductionQkShiftSoftmaxCoreConfig, physical: u64) -> Vec<F> {
        let mut structural = vec![F::ZERO; 9];
        let set = |values: &mut [F], cell: StructuralWitIn, value: u64| {
            values[cell.id as usize] = F::from_u64(value);
        };
        set(&mut structural, config.axis_low7, physical & 0x7f);
        set(&mut structural, config.axis_high4, physical & 0x7ff);
        set(&mut structural, config.row_low7, physical & 0x3ffff);
        set(&mut structural, config.row_high4, physical & 0x3fffff);
        set(&mut structural, config.physical_index, physical);
        structural
    }

    #[test]
    fn generic_head_geometry_and_domain_are_exact() {
        fn check<const N: usize>() {
            let (cs, config) = generic_circuit::<N>();
            let row_bits = 22 + N.trailing_zeros() as usize;
            match &cs.structural_witins[config.physical_index.id as usize].witin_type {
                StructuralWitInType::OuterRepeatingIncrementalSequence { k, n } => {
                    assert_eq!((*k, *n), (row_bits, row_bits));
                }
                other => panic!("unexpected physical-index formula: {other:?}"),
            }
            let witness = vec![F::ZERO; 41];
            for physical in [0, (1u64 << 22) - 1, ((N as u64) << 22) - 1] {
                let structural = structural_row(&config, physical);
                assert_eq!(
                    eval(
                        named_zero(&cs, "production_fused_physical_coordinate"),
                        &witness,
                        &structural,
                    ),
                    E::ZERO
                );
            }
        }
        check::<1>();
        check::<2>();
        check::<4>();
    }

    #[test]
    fn invalid_head_geometry_is_rejected_at_configuration() {
        for rejected in [
            std::panic::catch_unwind(generic_circuit::<0>),
            std::panic::catch_unwind(generic_circuit::<3>),
        ] {
            assert!(rejected.is_err());
        }
    }

    #[test]
    fn slot_head_and_call_descriptor_are_bound_per_slot() {
        let (cs, config) = generic_circuit::<2>();
        let mut witness = vec![F::ZERO; 41];
        witness[config.head_start.id as usize] = F::from_u64(8);
        witness[config.import_cycle.id as usize] = F::from_u64(101);
        witness[config.input_version.id as usize] = F::from_u64(7);
        witness[config.output_version.id as usize] = F::from_u64(9);
        let structural = structural_row(&config, 1 << 22);
        let record_index = cs
            .r_expressions_namespace_map
            .iter()
            .position(|name| name.ends_with("production_fused_attention_call_once"))
            .expect("fused call record");
        let record = &cs.r_ram_types[record_index].1;
        assert_eq!(eval(&record[2], &witness, &structural), E::from_v(101));
        assert_eq!(eval(&record[5], &witness, &structural), E::from_v(7));
        assert_eq!(eval(&record[8], &witness, &structural), E::from_v(9));
        assert_eq!(eval(&record[12], &witness, &structural), E::from_v(9));
        assert_eq!(eval(&record[13], &witness, &structural), E::ONE);
    }

    #[test]
    fn fused_signature_has_one_domain_and_only_external_records() {
        let mut cs = ConstraintSystem::<BabyBearExt4>::new(|| {
            TensorProductionQkShiftSoftmaxCoreInstruction::<BabyBearExt4>::name()
        });
        let mut cb = CircuitBuilder::new(&mut cs);
        TensorProductionQkShiftSoftmaxCoreInstruction::build_gkr_iop_circuit(
            &mut cb,
            &ProgramParams::default(),
        )
        .unwrap();
        assert_eq!((cb.cs.num_witin, cb.cs.num_structural_witin), (41, 9));
        assert_eq!(
            (cb.cs.r_expressions.len(), cb.cs.w_expressions.len()),
            (3, 1)
        );
        assert_eq!(ACTIVE_ROWS, ACTIVE_HEADS_PER_SHARD << 22);
    }

    #[test]
    fn fused_q_encoding_reconstruction_wiring_and_records_are_exact() {
        let (cs, config) = circuit();
        let (witness, structural) = canonical_row(&config);
        for expression in cs
            .assert_zero_expressions
            .iter()
            .chain(&cs.assert_zero_sumcheck_expressions)
        {
            assert_eq!(eval(expression, &witness, &structural), E::ZERO);
        }

        // The QK kernel emits only canonical 0 or BabyBear -1. Both the AIR
        // encoding and the signed reconstruction consumed by Softmax agree.
        assert_eq!(witness[config.q.id as usize], -F::ONE);
        assert_eq!(
            witness[config.q.id as usize].as_canonical_u64(),
            2_013_265_920
        );
        let signed_q = if witness[config.q.id as usize] == F::ZERO {
            0_i64
        } else {
            assert_eq!(witness[config.q.id as usize], -F::ONE);
            -1_i64
        };
        assert_eq!(
            signed_q * 65_536 + witness[config.remainder.id as usize].as_canonical_u64() as i64,
            -6
        );
        let descriptor = crate::scheme::matrix_reduction::descriptor(
            &TensorProductionQkShiftSoftmaxCoreInstruction::<E>::name(),
        )
        .unwrap();
        assert_eq!(descriptor.columns, [0, 1, 2, 3]);
        assert_eq!(descriptor.shift, 16);

        let read_names = cs.r_expressions_namespace_map.join("\n");
        let write_names = cs.w_expressions_namespace_map.join("\n");
        assert!(read_names.contains("production_fused_attention_call_once"));
        assert!(read_names.contains("production_fused_q_read"));
        assert!(read_names.contains("production_fused_k_read"));
        assert!(!read_names.contains("score") && !read_names.contains("shift"));
        assert!(write_names.contains("production_fused_softmax_probability_write"));
        assert!(!write_names.contains("score") && !write_names.contains("shift"));
        let probability_record = &cs.w_ram_types[0].1;
        assert_eq!(
            eval(&probability_record[6], &witness, &structural),
            E::from_v(13)
        );
        assert_eq!(
            eval(&probability_record[7], &witness, &structural),
            E::from_v((8 * SEQUENCE + 1) * SEQUENCE)
        );
    }

    #[test]
    fn fused_row_constraints_reject_each_internal_seam() {
        let (cs, config) = circuit();
        let (witness, structural) = canonical_row(&config);
        for (name, mutate_witness, mutate_structural) in [
            ("production_fused_qk_quotient", Some(config.q), None),
            (
                "production_fused_softmax_shifted_magnitude",
                Some(config.remainder),
                None,
            ),
            (
                "production_fused_softmax_shifted_magnitude",
                Some(config.shift),
                None,
            ),
            (
                "production_fused_softmax_causal_comparison",
                Some(config.causal),
                None,
            ),
            (
                "production_fused_softmax_masked_probability",
                Some(config.probability),
                None,
            ),
            (
                "production_fused_physical_coordinate",
                None,
                Some(config.physical_index),
            ),
        ] {
            let mut bad_witness = witness.clone();
            let mut bad_structural = structural.clone();
            if let Some(cell) = mutate_witness {
                bad_witness[cell.id as usize] += F::ONE;
            }
            if let Some(cell) = mutate_structural {
                bad_structural[cell.id as usize] += F::ONE;
            }
            assert_ne!(
                eval(named_zero(&cs, name), &bad_witness, &bad_structural),
                E::ZERO,
                "{name} accepted its tamper"
            );
        }
    }

    #[test]
    fn fused_mock_accepts_registered_lookups_and_rejects_lookup_tamper() {
        let (mut cs, config) = circuit();
        let (witness, structural) = canonical_row(&config);
        let challenge = [E::from_v(7), E::from_v(11)];
        {
            let cb = CircuitBuilder::new(&mut cs);
            MockProver::assert_satisfied(
                &cb,
                &one_row_mles(&witness),
                &one_row_mles(&structural),
                &[],
                Some(challenge),
                None,
            );
        }
        let mut bad = witness;
        bad[config.exp3.id as usize] += F::ONE;
        let cb = CircuitBuilder::new(&mut cs);
        assert!(
            MockProver::run_with_challenge(
                &cb,
                &[],
                &one_row_mles(&bad),
                &one_row_mles(&structural),
                challenge,
                None,
            )
            .is_err(),
            "registered exponential lookup accepted a tampered output"
        );
    }
}
