use std::sync::Arc;

use multilinear_extensions::mle::Point;
use transcript::Transcript;

use crate::{
    gkr::layer::{Layer, LayerWitness, sumcheck_layer::LayerProof},
    gpu::CudaStream,
    hal::ProverBackend,
    selector::SelectorContext,
};

pub trait LinearLayerProver<PB: ProverBackend> {
    fn prove(
        layer: &Layer<PB::E>,
        wit: LayerWitness<PB>,
        out_point: &Point<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
        option_stream: Option<&Arc<CudaStream>>,
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
        option_stream: Option<&Arc<CudaStream>>,
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
        pub_io_evals: &[PB::E],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        selector_ctxs: &[SelectorContext],
        option_stream: Option<&Arc<CudaStream>>,
    ) -> (LayerProof<PB::E>, Point<PB::E>);
}
