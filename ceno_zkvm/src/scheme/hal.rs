use crate::{
    circuit_builder::ConstraintSystem,
    expression::Expression,
    structs::{ProofInput, TowerProofs},
};
use ff_ext::ExtensionField;
use mpcs::{Point, PolynomialCommitmentScheme};
use rkyv::Serialize;
use serde::de::DeserializeOwned;
use transcript::Transcript;

pub trait ProverBackend {
    type E: ExtensionField;
    type PcsOpeningProof: Clone + Serialize + DeserializeOwned;
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
        input: ProofInput<PB>,
        read_exprs: &[Expression<PB::E>],
        write_exprs: &[Expression<PB::E>],
        lookup_exprs: &[Expression<PB::E>],
        challenge: &[PB::E; 2],
    ) -> (Vec<TowerProverSpec<PB>>, Vec<TowerProverSpec<PB>>);

    // the validity of value of first layer in the tower tree is reduced to
    // the validity of value of last layer in the tower tree through sumchecks
    fn prove_tower_relation(
        &self,
        prod_specs: Vec<TowerProverSpec<PB>>,
        logup_specs: Vec<TowerProverSpec<PB>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<PB::E>,
    ) -> (Point<PB::E>, TowerProofs<PB::E>);
}

pub trait MainSumcheckProver<PB: ProverBackend> {
    // this prover aims to achieve two goals:
    // 1. the validity of last layer in the tower tree is reduced to
    //    the validity of read/write/logup records through sumchecks;
    // 2. multiple multiplication relations between witness multilinear polynomials
    //    achieved via zerochecks.
    fn prove_main_constraints(
        &self,
        rt_tower: Vec<PB::E>,
        tower_proof: &TowerProofs<PB::E>,
        r_records: Vec<PB::MultilinearPoly>,
        w_records: Vec<PB::MultilinearPoly>,
        lk_records: Vec<PB::MultilinearPoly>,
        input: ProofInput<PB>,
        cs: ConstraintSystem<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> Point<PB::E>;
}

pub trait OpeningProver<PB: ProverBackend> {
    fn open(
        &self,
        inputs: Vec<ProofInput<PB>>,
        points: Vec<Point<PB::E>>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> PB::PcsOpeningProof;
}
