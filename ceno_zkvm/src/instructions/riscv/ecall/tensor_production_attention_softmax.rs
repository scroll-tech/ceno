//! Exact fused causal softmax for one four-head production attention group.

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
use p3::field::PrimeCharacteristicRing;

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
const SHIFT_BITS: usize = ROW_BITS;
const ROWS: usize = 1 << ROW_BITS;
const SHIFT_ROWS: usize = 1 << SHIFT_BITS;
const SEQUENCE: u64 = 2048;
const SCORE_VERSION_OFFSET: u64 = 1;
const PROBABILITY_VERSION_OFFSET: u64 = 2;
const SHIFT_VERSION_OFFSET: u64 = 3;

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
        E::BaseField::ONE.expr(),
        import_cycle,
        layer,
        tensor_id_lo,
        tensor_id_hi,
        version,
        index,
        value,
    ]
}

pub struct TensorProductionSoftmaxCoreInstruction<E>(PhantomData<E>);
pub struct TensorProductionShiftCoreInstruction<E>(PhantomData<E>);

#[derive(Debug)]
pub struct TensorProductionShiftCoreConfig {
    shift: WitIn,
    import_cycle: WitIn,
    layer: WitIn,
    head_start: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    query: StructuralWitIn,
    head: StructuralWitIn,
    selector: StructuralWitIn,
}

impl TensorProductionShiftCoreConfig {
    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionShiftColumnMap, ZKVMError> {
        use ceno_gpu::common::witgen::ProductionAttentionShiftColumnMap;
        let id = |cell: WitIn| cell.id as u32;
        let structural_id = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionShiftColumnMap {
            witness: [
                id(self.shift),
                id(self.import_cycle),
                id(self.layer),
                id(self.head_start),
                id(self.output_id_lo),
                id(self.output_id_hi),
                id(self.output_version),
            ],
            structural: [
                structural_id(self.query),
                structural_id(self.head),
                structural_id(self.selector),
            ],
            num_witin: num_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness("production shift witness width overflow".into())
            })?,
            num_structural_witin: num_structural_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness("production shift structural width overflow".into())
            })?,
        };
        if num_witin != 7
            || num_structural_witin != 3
            || map.witness != core::array::from_fn(|index| index as u32)
            || map.structural != core::array::from_fn(|index| index as u32)
        {
            return Err(ZKVMError::InvalidWitness(
                "production shift device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

impl<E: ExtensionField> Instruction<E> for TensorProductionShiftCoreInstruction<E> {
    type InstructionConfig = TensorProductionShiftCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        "TensorAttentionShift".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        assert_eq!(
            HEAD_GROUP_BITS, 0,
            "production shift formula map is heads-1"
        );
        let shift = cb.create_witin(|| "production_shift_value");
        let import_cycle = cb.create_witin(|| "production_shift_import_cycle");
        let layer = cb.create_witin(|| "production_shift_layer");
        let head_start = cb.create_witin(|| "production_shift_head_start");
        let output_id_lo = cb.create_witin(|| "production_shift_output_id_lo");
        let output_id_hi = cb.create_witin(|| "production_shift_output_id_hi");
        let output_version = cb.create_witin(|| "production_shift_output_version");
        let query = cb.create_structural_witin(
            || "production_shift_query",
            StructuralWitInType::InnerRepeatingIncrementalSequence {
                k: 11,
                n: SHIFT_BITS,
            },
        );
        let head = cb.create_structural_witin(
            || "production_shift_head",
            StructuralWitInType::InnerRepeatingIncrementalSequence {
                k: 22,
                n: SHIFT_BITS,
            },
        );
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let index = ((head_start.expr() + head.expr()) * SEQUENCE) + query.expr();
        cb.write_record(
            || "production_shift_write",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                layer.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + SHIFT_VERSION_OFFSET,
                index,
                shift.expr(),
            ),
        )?;
        Ok(TensorProductionShiftCoreConfig {
            shift,
            import_cycle,
            layer,
            head_start,
            output_id_lo,
            output_id_hi,
            output_version,
            query,
            head,
            selector,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        assert_eq!(
            cb.cs.num_witin as usize, 7,
            "production shift witness width changed"
        );
        assert_eq!(
            cb.cs.num_structural_witin as usize, 3,
            "production shift structural width changed"
        );
        assert_eq!(
            cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len(),
            0,
            "production shift read record count changed"
        );
        assert_eq!(
            cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len(),
            1,
            "production shift write record count changed"
        );
        let selector = SelectorType::Prefix(config.selector.expr());
        cb.cs.r_selector = Some(selector.clone());
        cb.cs.w_selector = Some(selector.clone());
        cb.cs.lk_selector = Some(selector.clone());
        cb.cs.zero_selector = Some(selector);
        let mut chip = Chip::new_from_cb(cb);
        chip.add_layer(Layer::from_circuit_builder(
            cb,
            format!("{}_main", Self::name()),
            default_out_eval_groups(cb),
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
            "production shift requires deterministic device replay".into(),
        ))
    }
}

#[derive(Debug)]
pub struct TensorProductionSoftmaxCoreConfig {
    score: WitIn,
    limbs: [WitIn; 4],
    exp3: WitIn,
    exp4: WitIn,
    causal: WitIn,
    comparison_diff_bits: [WitIn; 11],
    probability: WitIn,
    import_cycle: WitIn,
    layer: WitIn,
    head_start: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    key: StructuralWitIn,
    query: StructuralWitIn,
    head: StructuralWitIn,
    selector: StructuralWitIn,
}

impl TensorProductionSoftmaxCoreConfig {
    #[cfg(feature = "gpu")]
    pub(crate) fn device_column_map(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<ceno_gpu::common::witgen::ProductionAttentionSoftmaxColumnMap, ZKVMError> {
        use ceno_gpu::common::witgen::ProductionAttentionSoftmaxColumnMap;
        let id = |cell: WitIn| cell.id as u32;
        let structural_id = |cell: StructuralWitIn| cell.id as u32;
        let map = ProductionAttentionSoftmaxColumnMap {
            witness: [
                id(self.score),
                id(self.limbs[0]),
                id(self.limbs[1]),
                id(self.limbs[2]),
                id(self.limbs[3]),
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
                id(self.import_cycle),
                id(self.layer),
                id(self.head_start),
                id(self.output_id_lo),
                id(self.output_id_hi),
                id(self.output_version),
            ],
            structural: [
                structural_id(self.key),
                structural_id(self.query),
                structural_id(self.head),
                structural_id(self.selector),
            ],
            num_witin: num_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness("production softmax witness width overflow".into())
            })?,
            num_structural_witin: num_structural_witin.try_into().map_err(|_| {
                ZKVMError::InvalidWitness("production softmax structural width overflow".into())
            })?,
        };
        if num_witin != 26
            || num_structural_witin != 4
            || map.witness != core::array::from_fn(|index| index as u32)
            || map.structural != core::array::from_fn(|index| index as u32)
        {
            return Err(ZKVMError::InvalidWitness(
                "production softmax device columns do not exactly cover the VK".into(),
            ));
        }
        Ok(map)
    }
}

impl<E: ExtensionField> Instruction<E> for TensorProductionSoftmaxCoreInstruction<E> {
    type InstructionConfig = TensorProductionSoftmaxCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        "TensorAttentionSoftmax".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        assert_eq!(
            HEAD_GROUP_BITS, 0,
            "production softmax formula map is heads-1"
        );
        let score = cb.create_witin(|| "production_softmax_score");
        let limbs = core::array::from_fn(|index| {
            cb.create_witin(|| format!("production_softmax_limb_{index}"))
        });
        for (index, (limb, bits)) in limbs[..3].iter().zip([8_u32, 20, 20]).enumerate() {
            cb.lk_record(
                || format!("production_softmax_digit_{index}_range"),
                LookupTable::Dynamic,
                vec![limb.expr(), E::BaseField::from_u32(bits).expr()],
            )?;
        }
        let magnitude = limbs[0].expr()
            + limbs[1].expr() * E::BaseField::from_u64(1 << 8).expr()
            + limbs[2].expr() * E::BaseField::from_u64(1 << 28).expr();
        cb.require_equal(
            || "production_softmax_shifted_magnitude",
            limbs[3].expr() - score.expr(),
            magnitude,
        )?;

        let exp3 = cb.create_witin(|| "production_softmax_exp3");
        let exp4 = cb.create_witin(|| "production_softmax_exp4");
        cb.lk_record(
            || "production_softmax_exp3_lookup",
            LookupTable::LlamaProductionSoftmaxExpMiddle,
            vec![limbs[1].expr(), exp3.expr()],
        )?;
        cb.lk_record(
            || "production_softmax_exp4_lookup",
            LookupTable::LlamaProductionSoftmaxExpHigh,
            vec![limbs[2].expr(), exp4.expr()],
        )?;

        let causal = cb.create_witin(|| "production_softmax_causal");
        cb.assert_bit(|| "production_softmax_causal_bit", causal.expr())?;
        let comparison_diff_bits = core::array::from_fn(|index| {
            cb.create_witin(|| format!("production_softmax_comparison_diff_bit_{index}"))
        });
        for bit in comparison_diff_bits {
            cb.assert_bit(|| "production_softmax_comparison_diff_bit", bit.expr())?;
        }
        let comparison_diff: Expression<E> = comparison_diff_bits
            .iter()
            .enumerate()
            .map(|(index, bit)| bit.expr() * E::BaseField::from_u64(1 << index).expr())
            .sum();
        let probability = cb.create_witin(|| "production_softmax_probability");

        let key = cb.create_structural_witin(
            || "production_softmax_key",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 11, n: ROW_BITS },
        );
        let query = cb.create_structural_witin(
            || "production_softmax_query",
            StructuralWitInType::InnerRepeatingIncrementalSequence { k: 11, n: 22 },
        );
        let head = cb.create_structural_witin(
            || "production_softmax_head",
            StructuralWitInType::InnerRepeatingIncrementalSequence { k: 22, n: ROW_BITS },
        );
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        cb.require_equal(
            || "production_softmax_causal_comparison",
            query.expr() - key.expr(),
            causal.expr() * comparison_diff.clone()
                - (E::BaseField::ONE.expr() - causal.expr())
                    * (comparison_diff + E::BaseField::ONE.expr()),
        )?;
        cb.require_equal(
            || "production_softmax_masked_probability",
            probability.expr(),
            causal.expr() * exp3.expr() * exp4.expr(),
        )?;

        let import_cycle = cb.create_witin(|| "production_softmax_import_cycle");
        let layer = cb.create_witin(|| "production_softmax_layer");
        let head_start = cb.create_witin(|| "production_softmax_head_start");
        let output_id_lo = cb.create_witin(|| "production_softmax_output_id_lo");
        let output_id_hi = cb.create_witin(|| "production_softmax_output_id_hi");
        let output_version = cb.create_witin(|| "production_softmax_output_version");
        let global_head = head_start.expr() + head.expr();
        let index = (global_head.clone() * SEQUENCE + query.expr()) * SEQUENCE + key.expr();
        cb.read_record(
            || "production_softmax_score_read",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                layer.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + SCORE_VERSION_OFFSET,
                index.clone(),
                score.expr(),
            ),
        )?;
        let shift_index = global_head * SEQUENCE + query.expr();
        cb.read_record(
            || "production_softmax_shift_read",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                layer.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + SHIFT_VERSION_OFFSET,
                shift_index,
                limbs[3].expr(),
            ),
        )?;
        cb.write_record(
            || "production_softmax_probability_write",
            RAMType::Custom,
            tensor_space_record(
                import_cycle.expr(),
                layer.expr(),
                output_id_lo.expr(),
                output_id_hi.expr(),
                output_version.expr() + PROBABILITY_VERSION_OFFSET,
                index,
                probability.expr(),
            ),
        )?;

        Ok(Self::InstructionConfig {
            score,
            limbs,
            exp3,
            exp4,
            causal,
            comparison_diff_bits,
            probability,
            import_cycle,
            layer,
            head_start,
            output_id_lo,
            output_id_hi,
            output_version,
            key,
            query,
            head,
            selector,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, params)?;
        assert_eq!(
            cb.cs.num_witin as usize, 26,
            "production softmax witness width changed"
        );
        assert_eq!(
            cb.cs.num_structural_witin as usize, 4,
            "production softmax structural width changed"
        );
        assert_eq!(
            cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len(),
            2,
            "production softmax read record count changed"
        );
        assert_eq!(
            cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len(),
            1,
            "production softmax write record count changed"
        );
        let selector = SelectorType::Prefix(config.selector.expr());
        cb.cs.r_selector = Some(selector.clone());
        cb.cs.w_selector = Some(selector.clone());
        cb.cs.lk_selector = Some(selector.clone());
        cb.cs.zero_selector = Some(selector);
        let mut chip = Chip::new_from_cb(cb);
        chip.add_layer(Layer::from_circuit_builder(
            cb,
            format!("{}_main", Self::name()),
            default_out_eval_groups(cb),
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
            "production softmax requires deterministic device replay".into(),
        ))
    }
}

const _: () = assert!(ROWS == ceno_emul::tensor::production_attention::GROUP_SCORE_ROWS);
const _: () = assert!(SHIFT_ROWS == ceno_emul::tensor::production_attention::GROUP_SCORE_ROWS);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_builder::ConstraintSystem;
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    fn signature<I: Instruction<E>>() -> (String, usize, usize, usize, usize) {
        let mut cs = ConstraintSystem::<E>::new(|| I::name());
        let mut cb = CircuitBuilder::new(&mut cs);
        I::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).expect("build circuit");
        (
            I::name(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len(),
            cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len(),
        )
    }

    #[test]
    fn shift_and_softmax_have_one_descriptor_independent_signature() {
        let shift = signature::<TensorProductionShiftCoreInstruction<E>>();
        let softmax = signature::<TensorProductionSoftmaxCoreInstruction<E>>();
        for (layer, head) in [(0, 0), (0, 31), (31, 7)] {
            assert_eq!(
                shift,
                ("TensorAttentionShift".into(), 7, 3, 0, 1),
                "shift signature changed for descriptor layer={layer} head={head}"
            );
            assert_eq!(
                softmax,
                ("TensorAttentionSoftmax".into(), 26, 4, 2, 1),
                "softmax signature changed for descriptor layer={layer} head={head}"
            );
        }
        assert_eq!(ROWS, 1 << 22);
        assert_eq!(SHIFT_ROWS, 1 << 22);
    }
}
