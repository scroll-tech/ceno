#![feature(variant_count)]
use crate::{
    chip::Chip, circuit_builder::CircuitBuilder, error::CircuitBuilderError,
    selector::SelectorType, utils::lk_multiplicity::LkMultiplicity,
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{Expression, impl_expr_from_unsigned, mle::ArcMultilinearExtension};
use std::collections::BTreeMap;
use strum_macros::EnumIter;
use witness::RowMajorMatrix;

pub mod chip;
pub mod circuit_builder;
pub mod cpu;
pub mod error;
pub mod evaluation;
pub mod gadgets;
pub mod gkr;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod hal;
pub mod selector;
pub mod tables;
pub mod utils;

pub type Phase1WitnessGroup<'a, E> = Vec<ArcMultilinearExtension<'a, E>>;

// format: [r_records, w_records, lk_records, zero_records]
pub type OutEvalGroups<E> = BTreeMap<SelectorType<E>, [Vec<usize>; 3]>;
pub trait ProtocolBuilder<E: ExtensionField>: Sized {
    type Params;

    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        params: Self::Params,
    ) -> Result<Self, CircuitBuilderError>;

    fn finalize(&self, name: String, cb: &mut CircuitBuilder<E>) -> Chip<E>;
}
pub trait ProtocolWitnessGenerator<E: ExtensionField> {
    type Trace;

    /// The fixed witness.
    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField>;

    /// The vectors to be committed in the phase1.
    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    );
}

#[derive(Clone, Debug, Copy, EnumIter, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(usize)]
pub enum RAMType {
    GlobalState = 0,
    Register,
    Memory,
    Undefined,
}

impl_expr_from_unsigned!(RAMType);

pub fn default_out_eval_groups<E: ExtensionField>(cb: &CircuitBuilder<E>) -> OutEvalGroups<E> {
    let mut next_idx = 0usize;
    let mut evals = BTreeMap::new();
    for (selector, group) in cb.cs.expression_groups.iter() {
        let Some(selector) = selector else {
            assert!(group.is_empty(), "all expressions must have a selector");
            continue;
        };
        let r_len = group.r_expressions.len() + group.r_table_expressions.len();
        let r_evals = (next_idx..next_idx + r_len).collect_vec();
        next_idx += r_len;

        let w_len = group.w_expressions.len() + group.w_table_expressions.len();
        let w_evals = (next_idx..next_idx + w_len).collect_vec();
        next_idx += w_len;

        let lk_len = group.lk_expressions.len() + group.lk_table_expressions.len() * 2;
        let lk_evals = (next_idx..next_idx + lk_len).collect_vec();
        next_idx += lk_len;

        evals.insert(selector.clone(), [r_evals, w_evals, lk_evals]);
    }
    evals
}
