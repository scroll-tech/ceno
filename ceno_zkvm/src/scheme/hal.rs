use crate::{
    error::ZKVMError,
    scheme::cpu::TowerRelationOutput,
    structs::{ComposedConstrainSystem, EccQuarkProof, ZKVMProvingKey},
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    gkr::GKRProof,
    hal::{ProtocolWitnessGeneratorProver, ProverBackend},
};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{mle::MultilinearExtension, util::ceil_log2};
use std::{collections::BTreeMap, sync::Arc};
use sumcheck::structs::IOPProverMessage;
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

pub trait ProverDevice<PB>:
    TraceCommitter<PB>
    + TowerProver<PB>
    + MainSumcheckProver<PB>
    + OpeningProver<PB>
    + DeviceTransporter<PB>
    + ProtocolWitnessGeneratorProver<PB>
    + EccQuarkProver<PB>
    + ChipInputPreparer<PB>
// + FixedMLEPadder<PB>
where
    PB: ProverBackend,
{
    fn get_pb(&self) -> &PB;
}

/// Prepare a chip task's input for proving.
/// CPU: no-op (input already fully populated during task building).
/// GPU: deferred witness extraction + structural witness transport.
pub trait ChipInputPreparer<PB: ProverBackend> {
    fn prepare_chip_input(
        &self,
        task: &mut crate::scheme::scheduler::ChipTask<'_, PB>,
        pcs_data: &PB::PcsData,
    );
}

// TODO: remove the lifetime bound
pub struct ProofInput<'a, PB: ProverBackend> {
    pub witness: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub structural_witness: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub fixed: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub public_input: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub pub_io_evals: Vec<Either<<PB::E as ExtensionField>::BaseField, PB::E>>,
    pub num_instances: Vec<usize>,
    pub has_ecc_ops: bool,
}

impl<'a, PB: ProverBackend> ProofInput<'a, PB> {
    pub fn num_instances(&self) -> usize {
        self.num_instances.iter().sum()
    }

    #[inline]
    pub fn log2_num_instances(&self) -> usize {
        let num_instance = self.num_instances();
        let log2 = ceil_log2(next_pow2_instance_padding(num_instance));
        if self.has_ecc_ops {
            // the mles have one extra variable to store
            // the internal partial sums for ecc additions
            log2 + 1
        } else {
            log2
        }
    }
}

#[derive(Clone)]
pub struct TowerProverSpec<'a, PB: ProverBackend> {
    pub witness: Vec<Vec<PB::MultilinearPoly<'a>>>,
}

pub trait TraceCommitter<PB: ProverBackend> {
    // commit to the traces using merkle tree and return
    // the traces in the form of multilinear polynomials
    #[allow(clippy::type_complexity)]
    fn commit_traces<'a>(
        &self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<<PB::E as ExtensionField>::BaseField>>,
    ) -> (
        Vec<PB::MultilinearPoly<'a>>,
        PB::PcsData,
        <PB::Pcs as PolynomialCommitmentScheme<PB::E>>::Commitment,
    );

    /// Return an iterator over witness polynomials so backends can decide how to source them
    fn extract_witness_mles<'a, 'b>(
        &self,
        witness_mles: &'b mut Vec<PB::MultilinearPoly<'a>>,
        pcs_data: &'b PB::PcsData, // used by GPU backend
    ) -> Box<dyn Iterator<Item = Arc<PB::MultilinearPoly<'a>>> + 'b>;
}

/// Accumulate N (not necessarily power of 2) EC points into one EC point using affine coordinates
/// in one layer which borrows ideas from the [Quark paper](https://eprint.iacr.org/2020/1275.pdf)
/// Note that these points are defined over the septic extension field of BabyBear.
///
/// The main constraint enforced in this quark layer is:
///    p[1,b] = affine_add(p[b,0], p[b,1]) for all b < N
pub trait EccQuarkProver<PB: ProverBackend> {
    fn prove_ec_sum_quark<'a>(
        &self,
        num_instances: usize,
        xs: Vec<Arc<PB::MultilinearPoly<'a>>>,
        ys: Vec<Arc<PB::MultilinearPoly<'a>>>,
        invs: Vec<Arc<PB::MultilinearPoly<'a>>>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> Result<EccQuarkProof<PB::E>, ZKVMError>;
}

pub trait TowerProver<PB: ProverBackend> {
    // infer read/write/logup records from the read/write/logup expressions and then
    // build multiple complete binary trees (tower tree) to accumulate these records
    // either in product or fractional sum form.
    #[allow(clippy::type_complexity)]
    fn build_tower_witness<'a, 'b, 'c>(
        &self,
        cs: &ComposedConstrainSystem<PB::E>,
        input: &ProofInput<'a, PB>,
        records: &'c [Arc<PB::MultilinearPoly<'b>>],
    ) -> (
        Vec<Vec<Vec<PB::E>>>,
        Vec<TowerProverSpec<'c, PB>>,
        Vec<TowerProverSpec<'c, PB>>,
    )
    where
        'a: 'b,
        'b: 'c;

    // the validity of value of first layer in the tower tree is reduced to
    // the validity of value of last layer in the tower tree through sumchecks
    #[allow(clippy::type_complexity)]
    fn prove_tower_relation<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<PB::E>,
        input: &ProofInput<'a, PB>,
        records: &'c [Arc<PB::MultilinearPoly<'b>>],
        challenges: &[PB::E; 2],
        transcript: &mut impl Transcript<PB::E>,
    ) -> TowerRelationOutput<PB::E>
    where
        'a: 'b,
        'b: 'c;
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
        evals: Vec<Vec<Vec<PB::E>>>,
        transcript: &mut (impl Transcript<PB::E> + 'static),
    ) -> <PB::Pcs as PolynomialCommitmentScheme<PB::E>>::Proof;
}

pub struct DeviceProvingKey<'a, PB: ProverBackend> {
    pub fixed_mles: Vec<Arc<PB::MultilinearPoly<'a>>>,
    pub pcs_data: Arc<PB::PcsData>,
}

pub trait DeviceTransporter<PB: ProverBackend> {
    fn transport_proving_key(
        &self,
        is_first_shard: bool,
        proving_key: Arc<ZKVMProvingKey<PB::E, PB::Pcs>>,
    ) -> DeviceProvingKey<'static, PB>;

    fn transport_mles<'a>(
        &self,
        mles: &[MultilinearExtension<'a, PB::E>],
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
