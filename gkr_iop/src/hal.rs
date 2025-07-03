use std::fmt::Debug;

use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::mle::Point;
use witness::RowMajorMatrix;

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
    fn gkr_witness<'a>(
        circuit: &GKRCircuit<PB::E>,
        phase1_witness_group: &RowMajorMatrix<
            <<PB as ProverBackend>::E as ExtensionField>::BaseField,
        >,
        fixed: &[Vec<<<PB as ProverBackend>::E as ExtensionField>::BaseField>],
        challenges: &[PB::E],
    ) -> (GKRCircuitWitness<'a, PB>, GKRCircuitOutput<'a, PB>);
}
