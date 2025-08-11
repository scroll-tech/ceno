use crate::{
    LayerWitness,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness},
    hal::{ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use ff_ext::ExtensionField;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel, SecurityLevel::Conjecture100bits};
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
};
use p3::field::TwoAdicField;
use std::rc::Rc;
use witness::RowMajorMatrix;

use crate::cpu::{CpuBackend, CpuProver};

#[cfg(feature = "gpu")]
use ceno_gpu::BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu;
#[cfg(feature = "gpu")]
use ceno_gpu::gl64::buffer::BufferImpl;

pub struct GpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: <PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    pub vp: <PCS as PolynomialCommitmentScheme<E>>::VerifierParam,
    pub max_poly_size_log2: usize,
    _marker: std::marker::PhantomData<E>,
}

pub const DEFAULT_MAX_NUM_VARIABLES: usize = 24;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for GpuBackend<E, PCS> {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_NUM_VARIABLES, Conjecture100bits)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> GpuBackend<E, PCS> {
    pub fn new(max_poly_size_log2: usize, security_level: SecurityLevel) -> Self {
        let param = PCS::setup(E::BaseField::TWO_ADICITY, security_level).unwrap();
        let (pp, vp) = PCS::trim(param, 1 << max_poly_size_log2).unwrap();
        Self {
            pp,
            vp,
            max_poly_size_log2,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for GpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtension<'a, E>;
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
        phase1_witness_group: &[ArcMultilinearExtension<'b, E>],
        structural_witness: &[ArcMultilinearExtension<'b, E>],
        fixed: &[ArcMultilinearExtension<'b, E>],
        pub_io: &[ArcMultilinearExtension<'b, E>],
        challenges: &[E],
    ) -> (
        GKRCircuitWitness<'a, GpuBackend<E, PCS>>,
        GKRCircuitOutput<'a, GpuBackend<E, PCS>>,
    )
    where
        'b: 'a,
    {
        // Use CPU version to generate witness
        let (cpu_witness, cpu_output) = <CpuProver<CpuBackend<E, PCS>> as ProtocolWitnessGeneratorProver<
            CpuBackend<E, PCS>,
        >>::gkr_witness(
            circuit,
            phase1_witness_group,
            structural_witness,
            fixed,
            pub_io,
            challenges,
        );

        // Convert CPU return type to GPU backend type (the specific type of multilinear polynomial is the same)
        let gpu_layers = cpu_witness
            .layers
            .into_iter()
            .map(|lw| LayerWitness::<GpuBackend<E, PCS>>::new(lw.0, vec![]))
            .collect();
        let GKRCircuitOutput(cpu_out_lw) = cpu_output;
        let gpu_output = GKRCircuitOutput::<GpuBackend<E, PCS>>(LayerWitness::new(cpu_out_lw.0, vec![]));

        (GKRCircuitWitness { layers: gpu_layers }, gpu_output)
    }
}
