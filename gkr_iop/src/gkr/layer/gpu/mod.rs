use crate::{
    cpu::{CpuBackend, CpuProver},
    gkr::layer::{
        Layer, LayerWitness,
        hal::{LinearLayerProver, SumcheckLayerProver, ZerocheckLayerProver},
    },
    gpu::{GpuBackend, GpuProver},
};
use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::mle::Point;
use transcript::Transcript;

use crate::{gkr::layer::sumcheck_layer::LayerProof, hal::ProverBackend};

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_point: &multilinear_extensions::mle::Point<E>,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>::new(wit.0, vec![]);
        <CpuProver<CpuBackend<E, PCS>> as LinearLayerProver<CpuBackend<E, PCS>>>::prove(
            layer, cpu_wit, out_point, transcript,
        )
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> SumcheckLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<'_, GpuBackend<E, PCS>>,
        challenges: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E> {
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>::new(wit.0, vec![]);
        <CpuProver<CpuBackend<E, PCS>> as SumcheckLayerProver<CpuBackend<E, PCS>>>::prove(
            layer,
            num_threads,
            max_num_variables,
            cpu_wit,
            challenges,
            transcript,
        )
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZerocheckLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<<GpuBackend<E, PCS> as ProverBackend>::E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_points: &[Point<<GpuBackend<E, PCS> as ProverBackend>::E>],
        pub_io_evals: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        challenges: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
        num_instances: usize,
    ) -> (
        LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E>,
        Point<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) {
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>::new(wit.0, vec![]);
        <CpuProver<CpuBackend<E, PCS>> as ZerocheckLayerProver<CpuBackend<E, PCS>>>::prove(
            layer,
            num_threads,
            max_num_variables,
            cpu_wit,
            out_points,
            pub_io_evals,
            challenges,
            transcript,
            num_instances,
        )
    }
}
