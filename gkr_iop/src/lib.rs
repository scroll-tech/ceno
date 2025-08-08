#![feature(variant_count)]
#![feature(strict_overflow_ops)]
use crate::{
    chip::Chip,
    circuit_builder::CircuitBuilder,
    error::CircuitBuilderError,
    hal::{ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
    selector::SelectorType,
    utils::lk_multiplicity::LkMultiplicity,
};
use either::Either;
use ff_ext::ExtensionField;
use gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::LayerWitness};
use multilinear_extensions::{Expression, impl_expr_from_unsigned, mle::ArcMultilinearExtension};
use std::{marker::PhantomData, sync::Arc};
use transcript::Transcript;
use witness::RowMajorMatrix;

pub mod chip;
pub mod circuit_builder;
pub mod cpu;
pub mod gpu;
pub mod error;
pub mod evaluation;
pub mod gadgets;
pub mod gkr;
pub mod hal;
pub mod selector;
pub mod tables;
pub mod utils;

pub type Phase1WitnessGroup<'a, E> = Vec<ArcMultilinearExtension<'a, E>>;

// format: [r_records, w_records, lk_records, zero_records]
pub type OutEvalGroups<E> = [(SelectorType<E>, Vec<usize>); 4];

pub trait ProtocolBuilder<E: ExtensionField>: Sized {
    type Params;

    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        params: Self::Params,
    ) -> Result<Self, CircuitBuilderError>;

    fn finalize(&mut self, cb: &CircuitBuilder<E>) -> (OutEvalGroups<E>, Chip<E>);

    fn n_committed(&self) -> usize;
    fn n_fixed(&self) -> usize;
    fn n_challenges(&self) -> usize;
    fn n_evaluations(&self) -> usize;

    fn n_layers(&self) -> usize;
}

pub trait ProtocolWitnessGenerator<E: ExtensionField> {
    type Trace;

    /// return rmm height for phase 1 witness, which might include height for `multivariate rotation`
    fn phase1_witin_rmm_height(&self, num_instances: usize) -> usize;

    /// The fixed witness.
    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField>;

    /// The vectors to be committed in the phase1.
    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    );

    /// GKR witness.
    fn gkr_witness<'a, PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        circuit: &GKRCircuit<PB::E>,
        phase1_witness_group: &[Arc<PB::MultilinearPoly<'a>>],
        structural_witness: &[Arc<PB::MultilinearPoly<'a>>],
        fixed: &[Arc<PB::MultilinearPoly<'a>>],
        pub_io: &[Arc<PB::MultilinearPoly<'a>>],
        challenges: &[PB::E],
    ) -> (GKRCircuitWitness<'a, PB>, GKRCircuitOutput<'a, PB>) {
        <PD as ProtocolWitnessGeneratorProver<PB>>::gkr_witness(
            circuit,
            phase1_witness_group,
            structural_witness,
            fixed,
            pub_io,
            challenges,
        )
    }
}

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolProver<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolVerifier<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);

#[derive(Clone, Debug, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(usize)]
pub enum RAMType {
    GlobalState,
    Register,
    Memory,
}

impl_expr_from_unsigned!(RAMType);
