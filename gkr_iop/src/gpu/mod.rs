use crate::{
    LayerWitness,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use ff_ext::ExtensionField;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::mle::{ArcMultilinearExtension, MultilinearExtension, Point};
use p3::field::TwoAdicField;
use std::{rc::Rc, sync::Arc};
use witness::RowMajorMatrix;

use crate::cpu::{CpuBackend, CpuProver, default_backend_config};

#[cfg(feature = "gpu")]
use ceno_gpu::BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu;
#[cfg(feature = "gpu")]
use ceno_gpu::gl64::buffer::BufferImpl;

#[cfg(feature = "gpu")]
pub mod gpu_prover {
    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex};

    use ceno_gpu::gl64::CudaHalGL64;
    #[allow(unused_imports)]
    use ceno_gpu::gl64::GpuPolynomialExt;
    pub use ceno_gpu::gl64::convert_ceno_to_gpu_basefold_commitment;
    use cudarc::driver::{CudaDevice, DriverError};

    pub static CUDA_DEVICE: Lazy<Result<Arc<CudaDevice>, DriverError>> =
        Lazy::new(|| CudaDevice::new(0));

    pub static CUDA_HAL: Lazy<
        Result<Arc<Mutex<CudaHalGL64>>, Box<dyn std::error::Error + Send + Sync>>,
    > = Lazy::new(|| {
        let device = CUDA_DEVICE
            .as_ref()
            .map_err(|e| format!("Device init failed: {:?}", e))?;
        device.bind_to_thread()?;

        CudaHalGL64::new()
            .map(|hal| Arc::new(Mutex::new(hal)))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    });
}

#[cfg(feature = "gpu")]
pub use gpu_prover::*;

pub struct GpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: <PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    pub vp: <PCS as PolynomialCommitmentScheme<E>>::VerifierParam,
    pub max_poly_size_log2: usize,
    pub security_level: SecurityLevel,
    _marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for GpuBackend<E, PCS> {
    fn default() -> Self {
        let (max_poly_size_log2, security_level) = default_backend_config();
        Self::new(max_poly_size_log2, security_level)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> GpuBackend<E, PCS> {
    pub fn new(max_poly_size_log2: usize, security_level: SecurityLevel) -> Self {
        let param = PCS::setup(1 << E::BaseField::TWO_ADICITY, security_level).unwrap();
        let (pp, vp) = PCS::trim(param, 1 << max_poly_size_log2).unwrap();
        Self {
            pp,
            vp,
            max_poly_size_log2,
            security_level,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct MultilinearExtensionGpu<'a, E: ExtensionField> {
    mle: MultilinearExtension<'a, E>,
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtensionGpu<'a, E> {
    fn num_vars(&self) -> usize {
        self.mle.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.mle.evaluate(&point)
    }
}

impl<'a, E: ExtensionField> MultilinearExtensionGpu<'a, E> {
    pub fn inner(&self) -> &MultilinearExtension<'a, E> {
        &self.mle
    }

    /// Delegate to inner MultilinearExtension's evaluate method
    pub fn evaluate(&self, point: &[E]) -> E {
        self.mle.evaluate(point)
    }

    /// Delegate to inner MultilinearExtension's evaluations method
    pub fn evaluations(&self) -> &multilinear_extensions::mle::FieldType<E> {
        self.mle.evaluations()
    }

    /// Create a new MultilinearExtensionGpu from a MultilinearExtension
    pub fn from_inner(inner: MultilinearExtension<'a, E>) -> Self {
        Self { mle: inner }
    }

    pub fn get_ext_field_vec(&self) -> &[E] {
        self.mle.get_ext_field_vec()
    }
}

pub type ArcMultilinearExtensionGpu<'a, E> = Arc<MultilinearExtensionGpu<'a, E>>;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for GpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtensionGpu<'a, E>;
    type Matrix = RowMajorMatrix<E::BaseField>;
    #[cfg(feature = "gpu")]
    type PcsData = BasefoldCommitmentWithWitnessGpu<E::BaseField, BufferImpl<E::BaseField>>;
    #[cfg(not(feature = "gpu"))]
    type PcsData = <PCS as PolynomialCommitmentScheme<E>>::CommitmentWithWitness;

    fn get_pp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::ProverParam {
        &self.pp
    }

    fn get_vp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::VerifierParam {
        &self.vp
    }
}

pub struct GpuProver<PB: ProverBackend + 'static> {
    pub backend: Rc<PB>,
}

impl<PB: ProverBackend> GpuProver<PB> {
    pub fn new(backend: Rc<PB>) -> Self {
        Self { backend }
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    ProtocolWitnessGeneratorProver<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn gkr_witness<'a, 'b>(
        circuit: &GKRCircuit<E>,
        phase1_witness_group: &[Arc<MultilinearExtensionGpu<'b, E>>],
        structural_witness: &[Arc<MultilinearExtensionGpu<'b, E>>],
        fixed: &[Arc<MultilinearExtensionGpu<'b, E>>],
        pub_io: &[Arc<MultilinearExtensionGpu<'b, E>>],
        challenges: &[E],
    ) -> (
        GKRCircuitWitness<'a, GpuBackend<E, PCS>>,
        GKRCircuitOutput<'a, GpuBackend<E, PCS>>,
    )
    where
        'b: 'a,
    {
        // Convert GPU types to CPU types for processing
        let cpu_phase1_witness_group: Vec<ArcMultilinearExtension<'b, E>> = phase1_witness_group
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner().clone()))
            .collect();
        let cpu_structural_witness: Vec<ArcMultilinearExtension<'b, E>> = structural_witness
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner().clone()))
            .collect();
        let cpu_fixed: Vec<ArcMultilinearExtension<'b, E>> = fixed
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner().clone()))
            .collect();
        let cpu_pub_io: Vec<ArcMultilinearExtension<'b, E>> = pub_io
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner().clone()))
            .collect();

        // Use CPU version to generate witness
        let (cpu_witness, cpu_output) = <CpuProver<CpuBackend<E, PCS>> as ProtocolWitnessGeneratorProver<
            CpuBackend<E, PCS>,
        >>::gkr_witness(
            circuit,
            &cpu_phase1_witness_group,
            &cpu_structural_witness,
            &cpu_fixed,
            &cpu_pub_io,
            challenges,
        );

        // Convert CPU return type to GPU backend type
        let gpu_layers = cpu_witness
            .layers
            .into_iter()
            .map(|lw| {
                let gpu_wits: Vec<Arc<MultilinearExtensionGpu<'_, E>>> = lw.0
                    .into_iter()
                    .map(|cpu_mle| Arc::new(MultilinearExtensionGpu::from_inner((*cpu_mle).clone())))
                    .collect();
                LayerWitness::<GpuBackend<E, PCS>>(gpu_wits)
            })
            .collect();
        let GKRCircuitOutput(cpu_out_lw) = cpu_output;
        let gpu_out_wits: Vec<Arc<MultilinearExtensionGpu<'_, E>>> = cpu_out_lw.0
            .into_iter()
            .map(|cpu_mle| Arc::new(MultilinearExtensionGpu::from_inner((*cpu_mle).clone())))
            .collect();
        let gpu_output =
            GKRCircuitOutput::<GpuBackend<E, PCS>>(LayerWitness(gpu_out_wits));

        (GKRCircuitWitness { layers: gpu_layers }, gpu_output)
    }
}
