use std::{collections::BTreeMap, sync::Arc};

use crate::{
    circuit_builder::ConstraintSystem,
    structs::{ProofInput, TowerProofs, ZKVMProvingKey},
};
use ff_ext::ExtensionField;
use mpcs::{Point, PolynomialCommitmentScheme};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::structs::IOPProverMessage;
use transcript::Transcript;
use witness::RowMajorMatrix;

pub trait ProverBackend {
    type E: ExtensionField;
    type Pcs: PolynomialCommitmentScheme<Self::E>;
    type PcsOpeningProof: Clone + Serialize + DeserializeOwned;

    type MultilinearPoly: Send + Sync;
    type Matrix: Send + Sync + Clone;
    type PcsData;
}

pub trait ProverDevice<PB>:
    TraceCommitter<PB> + TowerProver<PB> + MainSumcheckProver<PB> + OpeningProver<PB>
where
    PB: ProverBackend,
{
}

pub struct TowerProverSpec<PB: ProverBackend> {
    pub witness: Vec<Vec<PB::MultilinearPoly>>,
}

pub trait TraceCommitter<PB: ProverBackend> {
    // commit to the traces using merkle tree and return
    // the traces in the form of multilinear polynomials
    fn commit_trace(
        &self,
        traces: Vec<RowMajorMatrix<PB::E>>,
    ) -> (Vec<Vec<PB::MultilinearPoly>>, PB::PcsData);
}

pub trait TowerProver<PB: ProverBackend> {
    // infer read/write/logup records from the read/write/logup expressions
    // and then build a complete binary tree to accumulate these records
    fn build_tower_witness(
        &self,
        pk: &DeviceProvingKey<PB>,
        cs: &ConstraintSystem<PB::E>,
        input: &ProofInput<PB>,
        challenge: &[PB::E; 2],
    ) -> (
        Vec<Vec<Vec<PB::E>>>,
        Vec<Vec<PB::MultilinearPoly>>,
        Vec<TowerProverSpec<PB>>,
        Vec<TowerProverSpec<PB>>,
    );

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
        cs: &ConstraintSystem<PB::E>,
        challenges: &[PB::E; 2],
        transcript: &mut impl Transcript<PB::E>,
    ) -> (Point<PB::E>, Option<Vec<IOPProverMessage<PB::E>>>);
}

pub trait OpeningProver<PB: ProverBackend> {
    fn open(
        &self,
        witness_data: PB::PcsData,
        fixed_data: Option<PB::PcsData>,
        points: Vec<Point<PB::E>>,
        evals: Vec<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> PB::PcsOpeningProof;
}

pub struct DeviceProvingKey<PB: ProverBackend> {
    pub fixed_polys: BTreeMap<String, Vec<PB::MultilinearPoly>>,
    pub pcs_data: PB::PcsData,
}

pub trait DeviceProvingKeyTransporter<PB: ProverBackend> {
    fn transport_proving_key(
        &self,
        proving_key: Arc<ZKVMProvingKey<PB::E, PB::Pcs>>,
    ) -> DeviceProvingKey<PB>;
}
