use chip::Chip;
use ff_ext::ExtensionField;
use gkr::GKRCircuitWitness;
use transcript::Transcript;

pub mod chip;
pub mod error;
pub mod evaluation;
pub mod gkr;
pub mod utils;

pub trait ProtocolBuilder: Sized {
    type Params;

    fn init(params: Self::Params) -> Self;

    fn build(params: Self::Params) -> (Self, Chip) {
        let mut chip_spec = Self::init(params);
        let mut chip = Chip::default();
        chip_spec.build_commit_phase1(&mut chip);
        chip_spec.build_commit_phase2(&mut chip);
        chip_spec.build_gkr_phase(&mut chip);

        (chip_spec, chip)
    }

    fn build_commit_phase1(&mut self, spec: &mut Chip);
    fn build_commit_phase2(&mut self, _spec: &mut Chip) {}
    fn build_gkr_phase(&mut self, spec: &mut Chip);
}

pub trait ProtocolWitnessGenerator<E>
where
    E: ExtensionField,
{
    type Trace;

    /// The vectors to be committed in the phase1.
    fn phase1_witness(&self, phase1: &Self::Trace) -> Vec<Vec<E::BaseField>>;

    /// GKR witness.
    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], challenges: &[E]) -> GKRCircuitWitness<E>
    where
        E: ExtensionField;
}

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`, `gkr_phase` and `opening_phase`.
pub trait ProtocolProver<E: ExtensionField, Trans: Transcript<E>, PCS> {}

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`, `gkr_phase` and `opening_phase`.
pub trait ProtocolVerifier<E: ExtensionField, Trans: Transcript<E>, PCS> {}
