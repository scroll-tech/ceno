use crate::{scheme::expression::Expression, structs::TowerProofs};

pub trait ProverBackend {
    type E: ExtensionField;
    type Matrix: Send + Sync + Clone;
    type MultilinearPoly: Send + Sync;
}

pub struct TowerProverSpec<PB: ProverBackend> {
    pub layers: Vec<Vec<PB::MultilinearPoly>>,
}

pub trait TowerProver<PB: ProverBackend> {
    fn build_witness(
        &self,
        witness: &Vec<PB::MultilinearPoly>,
        read_exprs: &[Expression<PB::E>],
        write_exprs: &[Expression<PB::E>],
        lookup_exprs: &[Expression<PB::E>],
    ) -> (TowerProverSpec<PB>, TowerProverSpec<PB>);

    fn prove(&self, prod_specs: TowerProverSpec<PB>, logup_specs: TowerProverSpec<PB>) -> TowerProofs<PB::E>;
}

pub trait MainSumcheckProver<PB: ProverBackend> {
}

pub trait OpeningProver<PB: ProverBackend> {
}
