use crate::gkr::layer::{
    Layer,
    hal::{LinearLayerProver, SumcheckLayerProver, ZerocheckLayerProver},
};
use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::mle::Point;
use std::{fmt::Debug, sync::Arc};
use either::Either;

pub trait MultilinearPolynomial<E: ExtensionField> {
    fn num_vars(&self) -> usize;
    fn eval(&self, point: Point<E>) -> E;

    /// Get the length of evaluation data
    fn evaluations_len(&self) -> usize;

    /// Debug utility: generate a semantic signature value to represent the whole boolean hypercube elements
    /// this function is very heavily as traverse whole boolean hypercube
    fn bh_signature(&self) -> E;
}

/// Defines basic types like field, pcs that are common among all devices
/// and also defines the types that are specific to device.
pub trait ProverBackend {
    /// types that are common across all devices
    type E: ExtensionField;
    type Pcs: PolynomialCommitmentScheme<Self::E>;

    /// device-specific types
    // TODO: remove lifetime bound
    type MultilinearPoly<'a>: Send + Sync + Clone + Debug + Default + MultilinearPolynomial<Self::E>;
    type Matrix: Send + Sync + Clone;
    type PcsData;

    fn get_pp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::ProverParam;
    fn get_vp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::VerifierParam;
}

pub trait ProverDevice<PB>:
    LinearLayerProver<PB>
    + SumcheckLayerProver<PB>
    + ZerocheckLayerProver<PB>
    + ProtocolWitnessGeneratorProver<PB>
where
    PB: ProverBackend,
{
}

pub trait ProtocolWitnessGeneratorProver<PB: ProverBackend> {
    fn layer_witness<'a>(
        layer: &Layer<PB::E>,
        layer_wits: &[Arc<PB::MultilinearPoly<'a>>],
        pub_io_evals: &[Either<<PB::E as ExtensionField>::BaseField, PB::E>],
        challenges: &[PB::E],
    ) -> Vec<Arc<PB::MultilinearPoly<'a>>>;
}
