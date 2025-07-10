use std::{collections::BTreeMap, sync::Arc};

use crate::{
    error::ZKVMError,
    structs::{ComposedConstrainSystem, TowerProofs, ZKVMProvingKey},
};
use ff_ext::ExtensionField;
use gkr_iop::{gkr::GKRProof, hal::ProverBackend};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{mle::MultilinearExtension, util::ceil_log2};
use sumcheck::structs::IOPProverMessage;
use transcript::Transcript;
use witness::next_pow2_instance_padding;

pub trait ProverDevice<PB>:
    TraceCommitter<PB>
    + TowerProver<PB>
    + MainSumcheckProver<PB>
    + OpeningProver<PB>
    + DeviceTransporter<PB>
// + FixedMLEPadder<PB>
where
    PB: ProverBackend,
{
}

// TODO: remove the lifetime bound
pub struct ProofInput<'a, PB: ProverBackend> {
    pub witness: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub structural_witness: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub fixed: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub public_input: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub num_instances: usize,
}

impl<'a, PB: ProverBackend> ProofInput<'a, PB> {
    #[inline]
    pub fn log2_num_instances(&self) -> usize {
        ceil_log2(next_pow2_instance_padding(self.num_instances))
    }
}

pub struct TowerProverSpec<'a, PB: ProverBackend> {
    pub witness: Vec<Vec<PB::MultilinearPoly<'a>>>,
}

pub trait TraceCommitter<PB: ProverBackend> {
    // commit to the traces using merkle tree and return
    // the traces in the form of multilinear polynomials
    #[allow(clippy::type_complexity)]
    fn commit_traces<'a>(
        &mut self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<<PB::E as ExtensionField>::BaseField>>,
    ) -> (
        Vec<PB::MultilinearPoly<'a>>,
        PB::PcsData,
        <PB::Pcs as PolynomialCommitmentScheme<PB::E>>::Commitment,
    );
}

pub trait TowerProver<PB: ProverBackend> {
    // infer read/write/logup records from the read/write/logup expressions and then
    // build multiple complete binary trees (tower tree) to accumulate these records
    // either in product or fractional sum form.
    #[allow(clippy::type_complexity)]
    fn build_tower_witness<'a, 'b>(
        &self,
        cs: &ComposedConstrainSystem<PB::E>,
        input: &'b ProofInput<'a, PB>,
        challenge: &[PB::E; 2],
    ) -> (
        Vec<Vec<Vec<PB::E>>>,
        Vec<Arc<PB::MultilinearPoly<'b>>>,
        Vec<TowerProverSpec<'b, PB>>,
        Vec<TowerProverSpec<'b, PB>>,
    );

    // the validity of value of first layer in the tower tree is reduced to
    // the validity of value of last layer in the tower tree through sumchecks
    fn prove_tower_relation<'a>(
        &self,
        prod_specs: Vec<TowerProverSpec<'a, PB>>,
        logup_specs: Vec<TowerProverSpec<'a, PB>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<PB::E>,
    ) -> (Point<PB::E>, TowerProofs<PB::E>);
}

pub struct MainSumcheckEvals<E: ExtensionField> {
    pub wits_in_evals: Vec<E>,
    pub fixed_in_evals: Vec<E>,
}

pub trait MainSumcheckProver<PB: ProverBackend> {
    // this prover aims to achieve two goals:
    // 1. the validity of last layer in the tower tree is reduced to
    //    the validity of read/write/logup records through sumchecks;
    // 2. multiple multiplication relations between witness multilinear polynomials
    //    achieved via zerochecks.
    #[allow(clippy::type_complexity)]
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<PB::E>,
        records: Vec<Arc<PB::MultilinearPoly<'b>>>,
        input: &'b ProofInput<'a, PB>,
        cs: &ComposedConstrainSystem<PB::E>,
        challenges: &[PB::E; 2],
        transcript: &mut impl Transcript<PB::E>,
    ) -> Result<
        (
            Point<PB::E>,
            MainSumcheckEvals<PB::E>,
            Option<Vec<IOPProverMessage<PB::E>>>,
            Option<GKRProof<PB::E>>,
        ),
        ZKVMError,
    >;
}

pub trait OpeningProver<PB: ProverBackend> {
    #[allow(clippy::too_many_arguments)]
    fn open(
        &self,
        witness_data: PB::PcsData,
        fixed_data: Option<Arc<PB::PcsData>>,
        points: Vec<Point<PB::E>>,
        evals: Vec<Vec<PB::E>>,
        circuit_num_polys: &[(usize, usize)],
        num_instances: &[(usize, usize)],
        transcript: &mut impl Transcript<PB::E>,
    ) -> <PB::Pcs as PolynomialCommitmentScheme<PB::E>>::Proof;
}

pub struct DeviceProvingKey<'a, PB: ProverBackend> {
    pub fixed_mles: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub pcs_data: Arc<PB::PcsData>,
}

pub trait DeviceTransporter<PB: ProverBackend> {
    fn transport_proving_key(
        &self,
        proving_key: Arc<ZKVMProvingKey<PB::E, PB::Pcs>>,
    ) -> DeviceProvingKey<PB>;

    fn transport_mles<'a>(
        &self,
        mles: Vec<MultilinearExtension<'a, PB::E>>,
    ) -> Vec<Arc<PB::MultilinearPoly<'a>>>;
}

// pub trait FixedMLEPadder<PB: ProverBackend> {
//     fn padding_fixed_mle<'a, 'b>(
//         &self,
//         cs: &ComposedConstrainSystem<PB::E>,
//         fixed_mles: Vec<Arc<PB::MultilinearPoly<'b>>>,
//         num_instances: usize,
//     ) -> Vec<Arc<PB::MultilinearPoly<'a>>>
//     where
//         'b: 'a;
// }
