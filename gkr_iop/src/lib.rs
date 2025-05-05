use std::marker::PhantomData;

use chip::Chip;
use ff_ext::ExtensionField;
use gkr::GKRCircuitWitness;
use transcript::Transcript;

pub mod chip;
pub mod error;
pub mod evaluation;
pub mod gkr;
pub mod precompiles;
pub mod utils;

pub trait ProtocolBuilder: Sized {
    type Params;

    fn init(params: Self::Params) -> Self;

    /// Build the protocol for GKR IOP.
    fn build(params: Self::Params) -> (Self, Chip) {
        let mut chip_spec = Self::init(params);
        let mut chip = Chip::default();
        chip_spec.build_commit_phase(&mut chip);
        chip_spec.build_gkr_phase(&mut chip);

        (chip_spec, chip)
    }

    /// Specify the polynomials and challenges to be committed and generated in
    /// Phase 1.
    fn build_commit_phase(&mut self, spec: &mut Chip);
    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_gkr_phase(&mut self, spec: &mut Chip);
}

pub trait ProtocolWitnessGenerator<E>
where
    E: ExtensionField,
{
    type Trace;

    /// The vectors to be committed in the phase1.
    fn phase1_witness(&self, phase1: Self::Trace) -> Vec<Vec<E::BaseField>>;

    /// GKR witness.
    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], challenges: &[E]) -> GKRCircuitWitness<E>;
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
