#![feature(variant_count)]
use crate::{
    chip::Chip, circuit_builder::CircuitBuilder, error::CircuitBuilderError,
    utils::lk_multiplicity::LkMultiplicity,
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{Expression, impl_expr_from_unsigned, mle::ArcMultilinearExtension};
use std::marker::PhantomData;
use strum_macros::EnumIter;
use transcript::Transcript;
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
pub type OutEvalGroups = [Vec<usize>; 4];

pub trait ProtocolBuilder<E: ExtensionField>: Sized {
    type Params;

    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        params: Self::Params,
    ) -> Result<Self, CircuitBuilderError>;

    fn finalize(&mut self, name: String, cb: &mut CircuitBuilder<E>) -> Chip<E>;

    fn n_committed(&self) -> usize {
        todo!()
    }
    fn n_fixed(&self) -> usize {
        todo!()
    }
    fn n_evaluations(&self) -> usize {
        todo!()
    }

    fn n_layers(&self) -> usize {
        todo!()
    }
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

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolProver<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);

pub fn default_out_eval_groups<E: ExtensionField>(cb: &CircuitBuilder<E>) -> OutEvalGroups {
    let r_len = cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len();
    let w_len = cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len();
    let lk_len = cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len() * 2;
    let zero_len =
        cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

    [
        (0..r_len).collect_vec(),
        (r_len..r_len + w_len).collect_vec(),
        (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
        (0..zero_len).collect_vec(),
    ]
}

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolVerifier<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);

#[derive(Clone, Debug, Copy, EnumIter, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(usize)]
pub enum RAMType {
    GlobalState = 0,
    Register,
    Memory,
    Undefined,
}

impl_expr_from_unsigned!(RAMType);
