use crate::{
    expression::Expression,
    structs::{ProofInput, TowerProofs},
};
use ff_ext::ExtensionField;
use mpcs::Point;
use transcript::Transcript;

pub trait ProverBackend {
    type E: ExtensionField;
    type Matrix: Send + Sync + Clone;
    type MmcsProverData;
    type MultilinearPoly: Send + Sync;
}

pub trait ProverDevice<PB>: TowerProver<PB> + MainSumcheckProver<PB> + OpeningProver<PB>
where
    PB: ProverBackend,
{
}

pub struct TowerProverSpec<PB: ProverBackend> {
    pub witness: Vec<Vec<PB::MultilinearPoly>>,
}

pub trait TowerProver<PB: ProverBackend> {
    // infer read/write/logup records from the read/write/logup expressions
    // and then build a complete binary tree to accumulate these records
    fn build_tower_witness(
        &self,
        input: ProofInput<PB::E>,
        read_exprs: &[Expression<PB::E>],
        write_exprs: &[Expression<PB::E>],
        lookup_exprs: &[Expression<PB::E>],
        challenge: &[PB::E; 2],
    ) -> (Vec<TowerProverSpec<PB>>, Vec<TowerProverSpec<PB>>);

    fn prove_tower_relation(
        &self,
        prod_specs: Vec<TowerProverSpec<PB>>,
        logup_specs: Vec<TowerProverSpec<PB>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<PB::E>,
    ) -> (Point<PB::E>, TowerProofs<PB::E>);
}

pub trait MainSumcheckProver<PB: ProverBackend> {
    fn prove_main_constraints(
        &self,
        polys: &[PB::MultilinearPoly],
        transcript: &mut impl Transcript<PB::E>,
    ) -> (Point<PB::E>, TowerProofs<PB::E>);
}

pub trait OpeningProver<PB: ProverBackend> {}
