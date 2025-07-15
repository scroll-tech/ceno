use multilinear_extensions::mle::Point;
use transcript::Transcript;

use crate::{
    gkr::layer::{Layer, LayerWitness, sumcheck_layer::LayerProof},
    hal::ProverBackend,
};

pub trait LinearLayerProver<PB: ProverBackend> {
    fn prove(
        layer: &Layer<PB::E>,
        wit: LayerWitness<PB>,
        out_point: &Point<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E>;
}

pub trait SumcheckLayerProver<PB: ProverBackend> {
    fn prove(
        layer: &Layer<PB::E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<'_, PB>,
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E>;
}

pub trait ZerocheckLayerProver<PB: ProverBackend> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        layer: &Layer<PB::E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        num_instances: usize,
    ) -> (LayerProof<PB::E>, Point<PB::E>);
}
