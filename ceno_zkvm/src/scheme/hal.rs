use crate::{expression::Expression, structs::TowerProofs};
use ff_ext::ExtensionField;

pub trait ProverBackend {
    type E: ExtensionField;
    type Matrix: Send + Sync + Clone;
    type PcsData: Send + Sync;
    type MultilinearPoly: Send + Sync;
}

pub trait ProverDevice<PB>: TowerProver<PB> + MainSumcheckProver<PB> + OpeningProver<PB>
where
    PB: ProverBackend,
{
}

pub struct TowerProverSpec<PB: ProverBackend> {
    pub layers: Vec<Vec<PB::MultilinearPoly>>,
}

pub trait TowerProver<PB: ProverBackend> {
    // infer read/write/logup records from the read/write/logup expressions
    // and then build a complete binary tree to accumulate these records
    fn build_witness(
        &self,
        polys: &[PB::MultilinearPoly],
        read_exprs: &[Expression<PB::E>],
        write_exprs: &[Expression<PB::E>],
        lookup_exprs: &[Expression<PB::E>],
    ) -> (TowerProverSpec<PB>, TowerProverSpec<PB>);

    fn prove(
        &self,
        prod_specs: TowerProverSpec<PB>,
        logup_specs: TowerProverSpec<PB>,
    ) -> TowerProofs<PB::E>;
}

pub trait MainSumcheckProver<PB: ProverBackend> {}

pub trait OpeningProver<PB: ProverBackend> {}
