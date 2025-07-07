#![feature(variant_count)]
#![feature(strict_overflow_ops)]
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    hal::{ProtocolWitnessGeneratorProver, ProverDevice},
    utils::lk_multiplicity::LkMultiplicity,
};
use chip::Chip;
use either::Either;
use ff_ext::ExtensionField;
use gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::LayerWitness};
use multilinear_extensions::{Expression, impl_expr_from_unsigned, mle::ArcMultilinearExtension};
use transcript::Transcript;
use utils::infer_layer_witness;
use witness::RowMajorMatrix;

use crate::hal::ProverBackend;

pub mod chip;
pub mod circuit_builder;
pub mod cpu;
pub mod error;
pub mod evaluation;
pub mod gadgets;
pub mod gkr;
pub mod hal;
pub mod precompiles;
pub mod tables;
pub mod utils;

pub type Phase1WitnessGroup<'a, E> = Vec<ArcMultilinearExtension<'a, E>>;

pub trait ProtocolBuilder<E: ExtensionField>: Sized {
    type Params;

    fn init(cb: &mut CircuitBuilder<E>, params: Self::Params) -> Self;

    /// Build the protocol for GKR IOP.
    fn build(cb: &mut CircuitBuilder<E>, params: Self::Params) -> (Self, Chip<E>) {
        let chip_spec = Self::init(cb, params);
        let chip = chip_spec.build_gkr_chip(cb);

        (chip_spec, chip)
    }

    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_gkr_chip(&self, cb: &mut CircuitBuilder<E>) -> Chip<E>;

    fn n_committed(&self) -> usize;
    fn n_fixed(&self) -> usize;
    fn n_challenges(&self) -> usize;
    fn n_nonzero_out_evals(&self) -> usize;
    fn n_evaluations(&self) -> usize;

    fn n_layers(&self) -> usize;
}

pub trait ProtocolWitnessGenerator<E: ExtensionField> {
    type Trace;

    /// return rmm height for phase 1 witness, which might include height for `multivariate rotation`
    fn phase1_witin_rmm_height(&self, num_instances: usize) -> usize;

    /// The vectors to be committed in the phase1.
    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: &mut RowMajorMatrix<E::BaseField>,
        lk_multiplicity: &mut LkMultiplicity,
    );

    /// GKR witness.
    fn gkr_witness<'a, PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        circuit: &GKRCircuit<PB::E>,
        phase1_witness_group: &RowMajorMatrix<
            <<PB as ProverBackend>::E as ExtensionField>::BaseField,
        >,
        fixed: &[Vec<<<PB as ProverBackend>::E as ExtensionField>::BaseField>],
        challenges: &[PB::E],
    ) -> (GKRCircuitWitness<'a, PB>, GKRCircuitOutput<'a, PB>) {
        <PD as ProtocolWitnessGeneratorProver<PB>>::gkr_witness(
            circuit,
            phase1_witness_group,
            fixed,
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
