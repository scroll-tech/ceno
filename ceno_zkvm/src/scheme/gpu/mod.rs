use super::hal::{
    DeviceTransporter, MainSumcheckProver, OpeningProver, ProverDevice, TowerProver, TraceCommitter,
};
use crate::{
    error::ZKVMError,
    scheme::{
        hal::{DeviceProvingKey, MainSumcheckEvals, ProofInput, TowerProverSpec},
    },
    structs::{ComposedConstrainSystem, TowerProofs},
};
use ff_ext::{GoldilocksExt2, ExtensionField};
use gkr_iop::{
    gpu::{GpuBackend, GpuProver},
    gkr::GKRProof,
    hal::ProverBackend,
};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
};
use rayon::iter::ParallelIterator;
use std::{collections::BTreeMap, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

use gkr_iop::cpu::{CpuBackend, CpuProver};
use crate::scheme::cpu::CpuTowerProver;
use mpcs::SecurityLevel::Conjecture100bits;

#[cfg(feature = "gpu")]
use ceno_gpu::gl64::CudaHalGL64;
#[cfg(feature = "gpu")]
use cudarc::driver::{CudaDevice, DriverError};
#[cfg(feature = "gpu")]
use ceno_gpu::gl64::convert_ceno_to_gpu_basefold_commitment;

use once_cell::sync::Lazy;
use std::sync::Mutex;
// static CUDA_HAL: Lazy<Mutex<CudaHalGL64>> = Lazy::new(|| {
//     Mutex::new(CudaHalGL64::new().unwrap())
// });

#[cfg(feature = "gpu")]
static CUDA_DEVICE: Lazy<Result<Arc<CudaDevice>, DriverError>> = Lazy::new(|| {
    CudaDevice::new(0)
});
#[cfg(feature = "gpu")]
static CUDA_HAL: Lazy<Result<Arc<Mutex<CudaHalGL64>>, Box<dyn std::error::Error + Send + Sync>>> = Lazy::new(|| {
    let device = CUDA_DEVICE.as_ref().map_err(|e| format!("Device init failed: {:?}", e))?;
    device.bind_to_thread()?;
    
    CudaHalGL64::new()
        .map(|hal| Arc::new(Mutex::new(hal)))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
});


pub struct GpuTowerProver;

/// Temporary wrapper for GPU prover that reuses CPU prover functionality
/// during development phase. This struct will be refactored once GPU 
/// implementation is complete and CPU dependencies are removed.
/// 
/// TODO: Remove this wrapper and consolidate into a single GPU prover
/// once all modules are fully migrated to GPU implementation.
pub struct TemporaryGpuProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static> {
    pub gpu: GpuProver<GpuBackend<E, PCS>>,
    /// CPU prover used temporarily for modules not yet fully ported to GPU
    pub inner_cpu: CpuProver<CpuBackend<E, PCS>>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static> TemporaryGpuProver<E, PCS> {
    pub fn new(backend: std::rc::Rc<GpuBackend<E, PCS>>, security_level: mpcs::SecurityLevel) -> Self {
        let gpu = GpuProver::new(backend.clone());
        let cpu_backend = std::rc::Rc::new(CpuBackend::<E, PCS>::new(
            backend.max_poly_size_log2,
            security_level,
        ));
        let inner_cpu = CpuProver::new(cpu_backend);
        Self { gpu, inner_cpu }
    }
}

impl GpuTowerProver {
    pub fn create_proof<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
        prod_specs: Vec<TowerProverSpec<'a, GpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<'a, GpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        let prod_specs_cpu: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>> = prod_specs
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        let logup_specs_cpu: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>> = logup_specs
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        CpuTowerProver::create_proof(prod_specs_cpu, logup_specs_cpu, num_fanin, transcript)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TraceCommitter<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn commit_traces<'a>(
        &mut self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<MultilinearExtension<'a, E>>,
        <GpuBackend<E, PCS> as ProverBackend>::PcsData, // PCS::CommitmentWithWitness = BasefoldCommitmentWithWitnessGpu
        PCS::Commitment,
    ) {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<p3::goldilocks::Goldilocks>() {
            panic!("GPU backend only supports Goldilocks base field");
        }

        let span = entered_span!("[gpu] init pp", profiling_2 = true);
        let max_poly_size_log2 = traces
            .values()
            .map(|trace| ceil_log2(next_pow2_instance_padding(trace.num_instances())))
            .max()
            .unwrap();
        if max_poly_size_log2 > self.gpu.backend.max_poly_size_log2 {
            panic!(
                "max_poly_size_log2 {} > max_poly_size_log2 backend {}",
                max_poly_size_log2,
                self.gpu.backend.max_poly_size_log2
            )
        }
        exit_span!(span);


        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2>>() == 
            std::mem::size_of::<PCS::CommitmentWithWitness>();
        let (mles, pcs_data, commit) = if is_pcs_match {
            let vec_traces: Vec<witness::RowMajorMatrix<E::BaseField>> = traces.into_values().collect();

            let span = entered_span!("[gpu] hal init", profiling_2 = true);
            // let cuda_hal = CUDA_HAL.lock().unwrap(); // CudaHalGL64::new().unwrap();
            let device = CUDA_DEVICE.as_ref().map_err(|e| format!("Device not available: {:?}", e)).unwrap();
            device.bind_to_thread().unwrap();
            let hal_arc = CUDA_HAL.as_ref().map_err(|e| format!("HAL not available: {:?}", e)).unwrap();
            let cuda_hal = hal_arc.lock().unwrap();
            exit_span!(span);
            

            let traces_gl64: Vec<witness::RowMajorMatrix<p3::goldilocks::Goldilocks>> = 
                unsafe { std::mem::transmute(vec_traces) };
   
            let span = entered_span!("[gpu] batch_commit", profiling_2 = true);
            let pcs_data = cuda_hal.basefold.batch_commit(traces_gl64).unwrap();
            exit_span!(span);

            let span = entered_span!("[gpu] get_pure_commitment", profiling_2 = true);
            let basefold_commit = cuda_hal.basefold.get_pure_commitment(&pcs_data);
            exit_span!(span);

            let span = entered_span!("[gpu] get_mle_witness_from_commitment", profiling_2 = true);
            let basefold_mles = cuda_hal.basefold.get_mle_witness_from_commitment(&pcs_data);
            exit_span!(span);

            let span = entered_span!("[gpu] transmute back", profiling_2 = true);
            let commit: PCS::Commitment = unsafe {
                    std::mem::transmute_copy(&basefold_commit)
            };
            std::mem::forget(basefold_commit);
            let mles: Vec<MultilinearExtension<'a, E>> = unsafe {
                std::mem::transmute_copy(&basefold_mles)
            };
            std::mem::forget(basefold_mles);
            // transmute pcs_data from GPU specific type to generic PcsData type
            let pcs_data_generic: <GpuBackend<E, PCS> as ProverBackend>::PcsData = unsafe {
                std::mem::transmute_copy(&pcs_data)
            };
            std::mem::forget(pcs_data);
            exit_span!(span);
            
            (mles, pcs_data_generic, commit)
        } else {
            panic!("GPU commitment data is not compatible with the PCS");
        };

        (mles, pcs_data, commit)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_tower_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_tower_witness<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        records: &'c [ArcMultilinearExtension<'b, E>],
        is_padded: bool,
        challenges: &[E; 2],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
    )
    where
        'a: 'b,
        'b: 'c,
    {
        // 零拷贝：将 &ProofInput<GpuBackend> 转为 &ProofInput<CpuBackend>
        let cpu_input: &ProofInput<'a, CpuBackend<E, PCS>> = unsafe {
            &*(input as *const ProofInput<'a, GpuBackend<E, PCS>>
                as *const ProofInput<'a, CpuBackend<E, PCS>>)
        };
        let (out_evals, prod_specs_cpu, logup_specs_cpu) = self.inner_cpu.build_tower_witness(
            composed_cs,
            cpu_input,
            records,
            is_padded,
            challenges,
        );
        let prod_specs = prod_specs_cpu
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        let logup_specs = logup_specs_cpu
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        (out_evals, prod_specs, logup_specs)
    }

    #[tracing::instrument(
        skip_all,
        name = "prove_tower_relation",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_tower_relation<'a>(
        &self,
        prod_specs: Vec<TowerProverSpec<'a, GpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<'a, GpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        let prod_specs_cpu: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>> = prod_specs
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        let logup_specs_cpu: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>> = logup_specs
            .into_iter()
            .map(|s| TowerProverSpec { witness: s.witness })
            .collect();
        CpuTowerProver::create_proof(prod_specs_cpu, logup_specs_cpu, num_fanin, transcript)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_main_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_main_witness<'a, 'b>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        challenges: &[E; 2],
    ) -> (Vec<ArcMultilinearExtension<'b, E>>, bool)
    where
        'a: 'b,
    {
        // 零拷贝：将 &ProofInput<GpuBackend> 转为 &ProofInput<CpuBackend>
        let cpu_input: &ProofInput<'a, CpuBackend<E, PCS>> = unsafe {
            &*(input as *const ProofInput<'a, GpuBackend<E, PCS>>
                as *const ProofInput<'a, CpuBackend<E, PCS>>)
        };
        self.inner_cpu.build_main_witness(composed_cs, cpu_input, challenges)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "prove_main_constraints",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<E>,
        _records: Vec<ArcMultilinearExtension<'b, E>>, // not used by GPU after delegation
        input: &'b ProofInput<'a, GpuBackend<E, PCS>>,
        composed_cs: &ComposedConstrainSystem<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Result<
        (
            Point<E>,
            MainSumcheckEvals<E>,
            Option<Vec<IOPProverMessage<E>>>,
            Option<GKRProof<E>>,
        ),
        ZKVMError,
    > {
        let cpu_input: &ProofInput<'a, CpuBackend<E, PCS>> = unsafe {
            &*(input as *const ProofInput<'a, GpuBackend<E, PCS>>
                as *const ProofInput<'a, CpuBackend<E, PCS>>)
        };
        self.inner_cpu.prove_main_constraints(rt_tower, vec![], cpu_input, composed_cs, challenges, transcript)
    }
}

use p3::field::extension::BinomialExtensionField;
type GL64 = p3::goldilocks::Goldilocks;
type EGL64 = BinomialExtensionField<GL64, 2>;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> OpeningProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn open(
        &self,
        witness_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        fixed_data: Option<Arc<<GpuBackend<E, PCS> as ProverBackend>::PcsData>>,
        points: Vec<Point<E>>,
        mut evals: Vec<Vec<E>>, // where each inner Vec<E> = wit_evals + fixed_evals
        circuit_num_polys: &[(usize, usize)],
        num_instances: &[(usize, usize)],
        transcript: &mut (impl Transcript<E> + 'static),
    ) -> PCS::Proof {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<p3::goldilocks::Goldilocks>() {
            panic!("GPU backend only supports Goldilocks base field");
        }

        // use p3::field::extension::BinomialExtensionField;
        // type GL64 = p3::goldilocks::Goldilocks;
        // type EGL64 = BinomialExtensionField<GL64, 2>;
        // let cuda_hal = CUDA_HAL.lock().unwrap(); //CudaHalGL64::new().unwrap();
        let device = CUDA_DEVICE.as_ref().map_err(|e| format!("Device not available: {:?}", e)).unwrap();
        device.bind_to_thread().unwrap();
        let hal_arc = CUDA_HAL.as_ref().map_err(|e| format!("HAL not available: {:?}", e)).unwrap();
        let cuda_hal = hal_arc.lock().unwrap();

        let mut rounds = vec![];
        rounds.push((
            &witness_data,
            points
                .iter()
                .zip_eq(evals.iter_mut())
                .zip_eq(num_instances.iter())
                .map(|((point, evals), (chip_idx, _))| {
                    let (num_witin, _) = circuit_num_polys[*chip_idx];
                    (point.clone(), evals.drain(..num_witin).collect_vec())
                })
                .collect_vec(),
        ));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((
                fixed_data,
                points
                    .iter()
                    .zip_eq(evals.iter_mut())
                    .zip_eq(num_instances.iter())
                    .filter(|(_, (chip_idx, _))| {
                        let (_, num_fixed) = circuit_num_polys[*chip_idx];
                        num_fixed > 0
                    })
                    .map(|((point, evals), _)| (point.clone(), evals.to_vec()))
                    .collect_vec(),
            ));
        }


        use ceno_gpu::gl64::buffer::BufferImpl;
        use ceno_gpu::BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu;

        // Type conversions using unsafe transmute
        let prover_param = &self.gpu.backend.pp;
        let pp_gl64: &mpcs::basefold::structure::BasefoldProverParams<EGL64, mpcs::BasefoldRSParams> = 
            unsafe { std::mem::transmute(prover_param) };
        let rounds_gl64: Vec<_> = rounds
            .iter()
            .map(|(commitment, point_eval_pairs)| {
                let commitment_gl64: &BasefoldCommitmentWithWitnessGpu<GL64, BufferImpl<GL64>> = 
                    unsafe { std::mem::transmute(*commitment) };
                let point_eval_pairs_gl64: Vec<_> = point_eval_pairs
                    .iter()
                    .map(|(point, evals)| {
                        let point_gl64: &Vec<EGL64> = unsafe { std::mem::transmute(point) };
                        let evals_gl64: &Vec<EGL64> = unsafe { std::mem::transmute(evals) };
                        (point_gl64.clone(), evals_gl64.clone())
                    })
                    .collect();
                (commitment_gl64, point_eval_pairs_gl64)
            })
            .collect();

        let gpu_proof = if std::any::TypeId::of::<E>() == std::any::TypeId::of::<GoldilocksExt2>() {
                let transcript_any = transcript as &mut dyn std::any::Any;
                let basic_transcript = transcript_any.downcast_mut::<BasicTranscript<GoldilocksExt2>>()
                    .expect("Type should match");

                let gpu_proof_basefold = cuda_hal
                    .basefold
                    .batch_open(
                        &cuda_hal,
                        pp_gl64,
                        rounds_gl64,
                        basic_transcript,
                    )
                    .unwrap();

                let gpu_proof: PCS::Proof = unsafe {
                    std::mem::transmute_copy(&gpu_proof_basefold)
                };
                std::mem::forget(gpu_proof_basefold);
                println!("construct cpu commitment from gpu data");
                gpu_proof
            } else {
                panic!("GPU backend only supports Goldilocks base field");
            };
        gpu_proof

        // PCS::batch_open(
        //     self.pp.as_ref().unwrap(),
        //     rounds,
        //     transcript
        // )
        // .unwrap()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> DeviceTransporter<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn transport_proving_key(
        &self,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <GpuBackend<E, PCS> as ProverBackend>::E,
                <GpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<GpuBackend<E, PCS>> {
        let pcs_data_original = pk.fixed_commit_wd.clone().unwrap();

        // assert pcs match 
        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2>>() == 
            std::mem::size_of::<PCS::CommitmentWithWitness>();
        assert!(is_pcs_match, "pcs mismatch");

        // 1. transmute from PCS::CommitmentWithWitness to BasefoldCommitmentWithWitness<E>
        let basefold_commitment: &mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2> = unsafe {
            std::mem::transmute_copy(&pcs_data_original.as_ref())
        };
        // 2. convert from BasefoldCommitmentWithWitness<E> to BasefoldCommitmentWithWitness<GL64>
        let hal_arc = CUDA_HAL.as_ref().map_err(|e| format!("HAL not available: {:?}", e)).unwrap();
        let cuda_hal = hal_arc.lock().unwrap();
        let pcs_data_basefold = convert_ceno_to_gpu_basefold_commitment(&cuda_hal, basefold_commitment);
        let pcs_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData = unsafe {
            std::mem::transmute_copy(&pcs_data_basefold)
        };
        std::mem::forget(pcs_data_basefold);
        let pcs_data = Arc::new(pcs_data);
        
        let fixed_mles =
            PCS::get_arc_mle_witness_from_commitment(pk.fixed_commit_wd.as_ref().unwrap());

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: Vec<MultilinearExtension<'a, E>>,
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        mles.into_iter().map(|mle| mle.into()).collect_vec()
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for TemporaryGpuProver<E, PCS>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    fn get_pb(&self) -> &GpuBackend<E, PCS> {
        self.gpu.backend.as_ref()
    }
}
