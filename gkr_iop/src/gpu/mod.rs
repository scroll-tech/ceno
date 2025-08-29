use crate::{
    LayerWitness,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use ff_ext::ExtensionField;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::mle::{ArcMultilinearExtension, FieldType, MultilinearExtension, Point};
use p3::field::TwoAdicField;
use std::{rc::Rc, sync::Arc};
use witness::RowMajorMatrix;

use crate::cpu::{CpuBackend, CpuProver, default_backend_config};

use ceno_gpu::BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu;
use ceno_gpu::gl64::buffer::BufferImpl;

use std::marker::PhantomData;

/// GPU version of field type enum, similar to FieldType in MultilinearExtension
pub enum GpuFieldType {
    /// Base field polynomial
    Base(GpuPolynomial),
    /// Extension field polynomial
    Ext(GpuPolynomialExt),
    Unreachable,
}

impl Default for GpuFieldType {
    fn default() -> Self {
        Self::Unreachable
    }
}

impl GpuFieldType {
    /// Get the number of variables
    pub fn num_vars(&self) -> usize {
        match self {
            GpuFieldType::Base(poly) => poly.num_vars(),
            GpuFieldType::Ext(poly) => poly.num_vars(),
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }

    /// Get the length of evaluation data
    pub fn evaluations_len(&self) -> usize {
        match self {
            GpuFieldType::Base(poly) => poly.evaluations().len(),
            GpuFieldType::Ext(poly) => poly.evaluations().len(),
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }
}

pub mod gpu_prover {
    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex};
    pub use ceno_gpu::Buffer;

    pub use ceno_gpu::gl64::CudaHalGL64;
    pub use ceno_gpu::gl64::{GpuPolynomial, GpuPolynomialExt};
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
pub struct MultilinearExtensionGpu<'a, E: ExtensionField> {
    /// GPU polynomial data, supporting both base field and extension field
    mle: GpuFieldType,
    _phantom: PhantomData<&'a E>,
}

impl<'a, E: ExtensionField> Default for MultilinearExtensionGpu<'a, E> {
    fn default() -> Self {
        Self {
            mle: GpuFieldType::default(),
            _phantom: PhantomData,
        }
    }
}

impl<'a, E: ExtensionField> Clone for MultilinearExtensionGpu<'a, E> {
    fn clone(&self) -> Self {
        match &self.mle {
            GpuFieldType::Base(poly) => Self {
                mle: GpuFieldType::Base(poly.clone()),
                _phantom: PhantomData,
            },
            GpuFieldType::Ext(_poly) => {
                // Since GpuPolynomialExt may not support Clone, we panic for now
                panic!("Clone not supported for GpuPolynomialExt variant")
            },
            GpuFieldType::Unreachable => Self::default(),
        }
    }
}

impl<'a, E: ExtensionField> std::fmt::Debug for MultilinearExtensionGpu<'a, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultilinearExtensionGpu")
            .field("num_vars", &self.mle.num_vars())
            .field("evaluations_len", &self.mle.evaluations_len())
            .finish()
    }
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtensionGpu<'a, E> {
    fn num_vars(&self) -> usize {
        self.mle.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.evaluate(&point)
    }
}

impl<'a, E: ExtensionField> MultilinearExtensionGpu<'a, E> {
    /// Get reference to internal GPU polynomial
    pub fn inner(&self) -> &GpuFieldType {
        &self.mle
    }

    /// Convert to CPU version of MultilinearExtension
    pub fn inner_to_mle(&self) -> MultilinearExtension<'a, E> {
        match &self.mle {
            GpuFieldType::Base(poly) => {
                // println!("GpuFieldType::Base: {}", poly.num_vars());
                let cpu_evaluations = poly.to_cpu_vec();
                let cpu_evaluations_base = unsafe { std::mem::transmute(cpu_evaluations) };
                MultilinearExtension::from_evaluations_vec(self.mle.num_vars(), cpu_evaluations_base)
            },
            GpuFieldType::Ext(poly) => {
                // println!("GpuFieldType::Ext: {}", poly.num_vars());
                let cpu_evaluations = poly.to_cpu_vec();
                let cpu_evaluations_ext = unsafe { std::mem::transmute(cpu_evaluations) };
                MultilinearExtension::from_evaluations_ext_vec(self.mle.num_vars(), cpu_evaluations_ext)
            },
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }

    /// Evaluate polynomial at given point
    pub fn evaluate(&self, point: &[E]) -> E {
        self.inner_to_mle().evaluate(point)
    }

    /// Get the length of evaluation data
    pub fn evaluations_len(&self) -> usize {
        self.mle.evaluations_len()
    }

    /// Create GPU version from CPU version of MultilinearExtension
    pub fn from_ceno(cuda_hal: &CudaHalGL64, mle: &MultilinearExtension<'a, E>) -> Self {
        // check type of mle
        match mle.evaluations {
            FieldType::Base(_) => {
                let mle_vec_ref = mle.get_base_field_vec();
                let mle_vec_ref_gl64 = unsafe { std::mem::transmute(mle_vec_ref) };
                let mle_gpu = GpuPolynomial::from_ceno_vec(&cuda_hal, mle_vec_ref_gl64, mle.num_vars()).unwrap();
                Self { 
                    mle: GpuFieldType::Base(mle_gpu), 
                    _phantom: PhantomData 
                }
            },
            FieldType::Ext(_) => {
                let mle_vec_ref = mle.get_ext_field_vec();
                let mle_vec_ref_gl64_ext = unsafe { std::mem::transmute(mle_vec_ref) };
                let mle_gpu = GpuPolynomialExt::from_ceno_vec(&cuda_hal, mle_vec_ref_gl64_ext, mle.num_vars()).unwrap();
                Self { 
                    mle: GpuFieldType::Ext(mle_gpu), 
                    _phantom: PhantomData 
                }
            },
            FieldType::Unreachable => panic!("Unreachable FieldType"),
        }
        
    }

    /// Create from base field GpuPolynomial
    pub fn from_ceno_gpu_base(mle_gpu: GpuPolynomial) -> Self {
        Self { 
            mle: GpuFieldType::Base(mle_gpu), 
            _phantom: PhantomData 
        }
    }

    /// Create from extension field GpuPolynomialExt
    pub fn from_ceno_gpu_ext(mle_gpu: GpuPolynomialExt) -> Self {
        Self { 
            mle: GpuFieldType::Ext(mle_gpu), 
            _phantom: PhantomData 
        }
    }

    /// Method for backward compatibility
    pub fn from_ceno_gpu(mle_gpu: GpuPolynomial) -> Self {
        Self::from_ceno_gpu_base(mle_gpu)
    }

    /// Get extension field vector
    pub fn get_ext_field_vec(&self) -> Vec<E> {
        let mle_cpu = self.inner_to_mle();
        match mle_cpu.evaluations() {
            FieldType::Ext(slice) => slice.to_vec(),
            _ => panic!("evaluation not in extension field"),
        }
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
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_structural_witness: Vec<ArcMultilinearExtension<'b, E>> = structural_witness
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_fixed: Vec<ArcMultilinearExtension<'b, E>> = fixed
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_pub_io: Vec<ArcMultilinearExtension<'b, E>> = pub_io
            .iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
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

        let cuda_hal = CUDA_HAL.as_ref().unwrap().lock().unwrap();

        // Convert CPU return type to GPU backend type
        let gpu_layers = cpu_witness
            .layers
            .into_iter()
            .map(|lw| {
                let gpu_wits: Vec<Arc<MultilinearExtensionGpu<'_, E>>> = lw.0
                    .iter()
                    .map(|cpu_mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, &cpu_mle)))
                    .collect();
                LayerWitness::<GpuBackend<E, PCS>>(gpu_wits)
            })
            .collect();
        let GKRCircuitOutput(cpu_out_lw) = cpu_output;
        let gpu_out_wits: Vec<Arc<MultilinearExtensionGpu<'_, E>>> = cpu_out_lw.0
            .iter()
            .map(|cpu_mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, &cpu_mle)))
            .collect();
        let gpu_output =
            GKRCircuitOutput::<GpuBackend<E, PCS>>(LayerWitness(gpu_out_wits));

        (GKRCircuitWitness { layers: gpu_layers }, gpu_output)
    }
}
