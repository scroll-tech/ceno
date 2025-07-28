use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::mle::Point;
use std::{fmt::Debug, sync::Arc};

use crate::gkr::{
    GKRCircuit, GKRCircuitOutput, GKRCircuitWitness,
    layer::hal::{LinearLayerProver, SumcheckLayerProver, ZerocheckLayerProver},
};

pub trait MultilinearPolynomial<E: ExtensionField> {
    fn num_vars(&self) -> usize;
    fn eval(&self, point: Point<E>) -> E;
}

/// Defines basic types like field, pcs that are common among all devices
/// and also defines the types that are specific to device.
pub trait ProverBackend {
    /// types that are common across all devices
    type E: ExtensionField;
    type Pcs: PolynomialCommitmentScheme<Self::E>;

    /// device-specific types
    // TODO: remove lifetime bound
    type MultilinearPoly<'a>: Send + Sync + Clone + Debug + MultilinearPolynomial<Self::E>;
    type Matrix: Send + Sync + Clone;
    type PcsData;
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
    fn gkr_witness<'a, 'b>(
        circuit: &GKRCircuit<PB::E>,
        num_instance_with_rotation: usize,
        phase1_witness_group: &[Arc<PB::MultilinearPoly<'b>>],
        fixed: &[Arc<PB::MultilinearPoly<'b>>],
        pub_io: &[Arc<PB::MultilinearPoly<'b>>],
        challenges: &[PB::E],
    ) -> (GKRCircuitWitness<'a, PB>, GKRCircuitOutput<'a, PB>)
    where
        'b: 'a;
}
