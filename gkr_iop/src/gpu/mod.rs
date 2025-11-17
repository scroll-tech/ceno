use crate::{
    gkr::layer::gpu::utils::extract_mle_relationships_from_monomial_terms,
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use ff_ext::ExtensionField;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::{
    macros::{entered_span, exit_span},
    mle::{FieldType, MultilinearExtension, Point},
};
use p3::field::TwoAdicField;
use std::{rc::Rc, sync::Arc};
use witness::RowMajorMatrix;

use crate::cpu::default_backend_config;

use either::Either;
use itertools::{Itertools, izip};
use std::marker::PhantomData;

pub mod gpu_prover {
    pub use ceno_gpu::{
        BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu, Buffer, CudaHal,
        bb31::{
            CudaHalBB31, GpuDigestLayer, GpuFieldType, GpuMatrix, GpuPolynomial, GpuPolynomialExt,
        },
        common::{
            basefold::utils::convert_ceno_to_gpu_basefold_commitment,
            buffer::BufferImpl,
            get_ceno_gpu_device_id,
            mle::{
                build_mle_as_ceno, ordered_sparse32_selector_gpu, rotation_next_base_mle_gpu,
                rotation_selector_gpu,
            },
        },
    };

    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex, MutexGuard};

    pub type BB31Base = p3::babybear::BabyBear;
    pub type BB31Ext = ff_ext::BabyBearExt4;

    #[allow(clippy::type_complexity)]
    pub static CUDA_HAL: Lazy<
        Result<Arc<Mutex<CudaHalBB31>>, Box<dyn std::error::Error + Send + Sync>>,
    > = Lazy::new(|| {
        // can be overridden by env variable `CENO_GPU_DEVICE_ID`
        let device_id: usize = get_ceno_gpu_device_id(0);
        CudaHalBB31::new(device_id)
            .map(|hal| Arc::new(Mutex::new(hal)))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    });

    pub fn get_cuda_hal() -> Result<MutexGuard<'static, CudaHalBB31>, String> {
        let hal_arc = CUDA_HAL
            .as_ref()
            .map_err(|e| format!("HAL not available: {:?}", e))?;

        hal_arc
            .lock()
            .map_err(|e| format!("Failed to lock HAL: {:?}", e))
    }
}

use crate::{evaluation::EvalExpression, gkr::layer::Layer};
pub use gpu_prover::*;

/// Stores a multilinear polynomial in dense evaluation form.
pub struct MultilinearExtensionGpu<'a, E: ExtensionField> {
    /// GPU polynomial data, supporting both base field and extension field
    pub mle: GpuFieldType<'a>,
    _phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> Default for MultilinearExtensionGpu<'a, E> {
    fn default() -> Self {
        Self {
            mle: GpuFieldType::default(),
            _phantom: PhantomData,
        }
    }
}

impl<'a, E: ExtensionField> Clone for MultilinearExtensionGpu<'a, E> {
    fn clone(&self) -> Self {
        match &self.mle {
            GpuFieldType::Base(poly) => Self {
                mle: GpuFieldType::Base(poly.clone()),
                _phantom: PhantomData,
            },
            GpuFieldType::Ext(_poly) => {
                // Since GpuPolynomialExt may not support Clone, we panic for now
                panic!("Clone not supported for GpuPolynomialExt variant")
            }
            GpuFieldType::Unreachable => Self::default(),
        }
    }
}

impl<'a, E: ExtensionField> std::fmt::Debug for MultilinearExtensionGpu<'a, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultilinearExtensionGpu")
            .field("num_vars", &self.mle.num_vars())
            .field("evaluations_len", &self.mle.evaluations_len())
            .finish()
    }
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtensionGpu<'a, E> {
    fn num_vars(&self) -> usize {
        self.mle.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.evaluate(&point)
    }

    /// Get the length of evaluation data
    fn evaluations_len(&self) -> usize {
        self.mle.evaluations_len()
    }

    fn bh_signature(&self) -> E {
        if std::any::TypeId::of::<E::BaseField>()
            != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
        {
            panic!("GPU backend only supports Goldilocks");
        }

        match &self.mle {
            GpuFieldType::Base(poly) => {
                let res: Vec<E> = unsafe { std::mem::transmute(vec![poly.bh_signature()]) };
                res[0]
            }
            GpuFieldType::Ext(poly) => {
                let res: Vec<E> = unsafe { std::mem::transmute(vec![poly.bh_signature()]) };
                res[0]
            }
            GpuFieldType::Unreachable => unreachable!(),
        }
    }
}

impl<'a, E: ExtensionField> MultilinearExtensionGpu<'a, E> {
    /// Get reference to internal GPU polynomial
    pub fn inner(&self) -> &GpuFieldType<'_> {
        &self.mle
    }

    pub fn as_view_chunks(&self, num_fanin: usize) -> Vec<GpuPolynomialExt<'a>> {
        match &self.mle {
            GpuFieldType::Base(_) => panic!("not supported yet"),
            GpuFieldType::Ext(poly) => poly.as_view_chunk(num_fanin),
            // .into_iter().map(|chunk| Self {
            //     mle: GpuFieldType::Ext(chunk),
            //     _phantom: PhantomData,
            // }).collect(),
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }

    /// Convert to CPU version of MultilinearExtension
    pub fn inner_to_mle(&self) -> MultilinearExtension<'a, E> {
        match &self.mle {
            GpuFieldType::Base(poly) => {
                let cpu_evaluations = poly.to_cpu_vec();
                let cpu_evaluations_base: Vec<E::BaseField> =
                    unsafe { std::mem::transmute(cpu_evaluations) };
                MultilinearExtension::from_evaluations_vec(
                    self.mle.num_vars(),
                    cpu_evaluations_base,
                )
            }
            GpuFieldType::Ext(poly) => {
                let cpu_evaluations = poly.to_cpu_vec();
                let cpu_evaluations_ext: Vec<E> = unsafe { std::mem::transmute(cpu_evaluations) };
                MultilinearExtension::from_evaluations_ext_vec(
                    self.mle.num_vars(),
                    cpu_evaluations_ext,
                )
            }
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }

    /// Evaluate polynomial at given point
    pub fn evaluate(&self, point: &[E]) -> E {
        self.inner_to_mle().evaluate(point)
    }

    /// Create GPU version from CPU version of MultilinearExtension
    pub fn from_ceno(cuda_hal: &CudaHalBB31, mle: &MultilinearExtension<'a, E>) -> Self {
        // check type of mle
        match mle.evaluations {
            FieldType::Base(_) => {
                let mle_vec_ref = mle.get_base_field_vec();
                let mle_vec_ref_gl64: &[BB31Base] = unsafe { std::mem::transmute(mle_vec_ref) };
                let mle_gpu =
                    GpuPolynomial::from_ceno_vec(cuda_hal, mle_vec_ref_gl64, mle.num_vars())
                        .unwrap();
                Self {
                    mle: GpuFieldType::Base(mle_gpu),
                    _phantom: PhantomData,
                }
            }
            FieldType::Ext(_) => {
                let mle_vec_ref = mle.get_ext_field_vec();
                let mle_vec_ref_gl64_ext: &[BB31Ext] = unsafe { std::mem::transmute(mle_vec_ref) };
                let mle_gpu =
                    GpuPolynomialExt::from_ceno_vec(cuda_hal, mle_vec_ref_gl64_ext, mle.num_vars())
                        .unwrap();
                Self {
                    mle: GpuFieldType::Ext(mle_gpu),
                    _phantom: PhantomData,
                }
            }
            FieldType::Unreachable => panic!("Unreachable FieldType"),
        }
    }

    /// Create from base field GpuPolynomial
    pub fn from_ceno_gpu_base(mle_gpu: GpuPolynomial<'a>) -> Self {
        Self {
            mle: GpuFieldType::Base(mle_gpu),
            _phantom: PhantomData,
        }
    }

    /// Create from extension field GpuPolynomialExt
    pub fn from_ceno_gpu_ext(mle_gpu: GpuPolynomialExt<'a>) -> Self {
        Self {
            mle: GpuFieldType::Ext(mle_gpu),
            _phantom: PhantomData,
        }
    }

    /// Method for backward compatibility
    pub fn from_ceno_gpu(mle_gpu: GpuPolynomial<'a>) -> Self {
        Self::from_ceno_gpu_base(mle_gpu)
    }

    /// get inner poly reference with base field claim
    pub fn as_ceno_gpu_base(&self) -> &GpuPolynomial<'_> {
        match &self.mle {
            GpuFieldType::Base(poly) => poly,
            GpuFieldType::Ext(_) => panic!("poly in ext field"),
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }

    /// get inner poly reference with ext field claim
    pub fn as_ceno_gpu_ext(&self) -> &GpuPolynomialExt<'_> {
        match &self.mle {
            GpuFieldType::Base(_) => panic!("poly in base field"),
            GpuFieldType::Ext(poly) => poly,
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        }
    }
}

pub struct GpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: <PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    pub vp: <PCS as PolynomialCommitmentScheme<E>>::VerifierParam,
    pub max_poly_size_log2: usize,
    pub security_level: SecurityLevel,
    _marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for GpuBackend<E, PCS> {
    fn default() -> Self {
        let (max_poly_size_log2, security_level) = default_backend_config();
        Self::new(max_poly_size_log2, security_level)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> GpuBackend<E, PCS> {
    pub fn new(max_poly_size_log2: usize, security_level: SecurityLevel) -> Self {
        let param = PCS::setup(1 << E::BaseField::TWO_ADICITY, security_level).unwrap();
        let (pp, vp) = PCS::trim(param, 1 << max_poly_size_log2).unwrap();
        Self {
            pp,
            vp,
            max_poly_size_log2,
            security_level,
            _marker: std::marker::PhantomData,
        }
    }
}

pub type ArcMultilinearExtensionGpu<'a, E> = Arc<MultilinearExtensionGpu<'a, E>>;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for GpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtensionGpu<'a, E>;
    type Matrix = RowMajorMatrix<E::BaseField>;
    #[cfg(feature = "gpu")]
    type PcsData = BasefoldCommitmentWithWitnessGpu<
        E::BaseField,
        BufferImpl<'static, E::BaseField>,
        GpuDigestLayer,
        GpuMatrix<'static>,
        GpuPolynomial<'static>,
    >;
    #[cfg(not(feature = "gpu"))]
    type PcsData = <PCS as PolynomialCommitmentScheme<E>>::CommitmentWithWitness;

    fn get_pp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::ProverParam {
        &self.pp
    }

    fn get_vp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::VerifierParam {
        &self.vp
    }
}

pub struct GpuProver<PB: ProverBackend + 'static> {
    pub backend: Rc<PB>,
}

impl<PB: ProverBackend> GpuProver<PB> {
    pub fn new(backend: Rc<PB>) -> Self {
        Self { backend }
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    ProtocolWitnessGeneratorProver<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    #[tracing::instrument(skip_all, name = "layer_witness", fields(profiling_2), level = "trace")]
    fn layer_witness<'a>(
        layer: &Layer<E>,
        layer_wits: &[Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>],
        pub_io_evals: &[Either<E::BaseField, E>],
        challenges: &[E],
    ) -> Vec<Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> {
        let span = entered_span!("preprocess", profiling_2 = true);
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports Goldilocks base field");
        }

        let out_evals: Vec<_> = layer
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(sel_type, out_eval)| izip!(std::iter::repeat(sel_type), out_eval.iter()))
            .collect();

        // pre-process and flatten indices into friendly GPU format
        let (num_non_zero_expr, term_coefficients, mle_indices_per_term, mle_size_info) = layer
            .exprs_with_selector_out_eval_monomial_form
            .iter()
            .zip_eq(out_evals.iter())
            .filter(|(_, (_, out_eval))| {
                match out_eval {
                    // only take linear/single to process
                    EvalExpression::Linear(_, _, _) | EvalExpression::Single(_) => true,
                    EvalExpression::Partition(..) => unimplemented!("Partition"),
                    EvalExpression::Zero => false,
                }
            })
            .map(|(expr, _)| {
                let (coeffs, indices, size_info) = extract_mle_relationships_from_monomial_terms(
                    expr,
                    &layer_wits.iter().map(|mle| mle.as_ref()).collect_vec(),
                    &pub_io_evals,
                    challenges,
                );
                let coeffs_gl64: Vec<BB31Ext> = unsafe { std::mem::transmute(coeffs) };
                (coeffs_gl64, indices, size_info)
            })
            .fold(
                (0, Vec::new(), Vec::new(), Vec::new()),
                |(mut num_non_zero_expr, mut coeff_acc, mut indices_acc, mut size_acc),
                 (coeffs, indices, size_info)| {
                    num_non_zero_expr += 1;
                    coeff_acc.push(coeffs);
                    indices_acc.push(indices);
                    size_acc.push(size_info);
                    (num_non_zero_expr, coeff_acc, indices_acc, size_acc)
                },
            );

        let num_vars = mle_size_info
            .first()
            .and_then(|f| f.first())
            .as_ref()
            .unwrap()
            .0;
        exit_span!(span);

        let span = entered_span!("witness_infer", profiling_2 = true);
        // process & transmute poly
        let all_witins_gpu = layer_wits.iter().map(|mle| mle.as_ref()).collect_vec();
        let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
            unsafe { std::mem::transmute(all_witins_gpu) };
        let all_witins_gpu_type_gl64 = all_witins_gpu_gl64.iter().map(|mle| &mle.mle).collect_vec();

        // buffer for output witness from gpu
        let cuda_hal = get_cuda_hal().unwrap();
        let mut next_witness_buf = (0..num_non_zero_expr)
            .map(|_| {
                cuda_hal
                    .alloc_ext_elems_on_device(1 << num_vars)
                    .map_err(|e| format!("Failed to allocate prod GPU buffer: {:?}", e))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        cuda_hal
            .witness_infer
            .wit_infer_by_monomial_expr(
                &*cuda_hal,
                all_witins_gpu_type_gl64,
                &term_coefficients,
                &mle_indices_per_term,
                &mut next_witness_buf,
            )
            .unwrap();
        exit_span!(span);

        // recover it back and interleaving with default gpu
        let mut next_iter = next_witness_buf.into_iter();

        out_evals
            .into_iter()
            .map(|(_, out_eval)| {
                if matches!(
                    out_eval,
                    EvalExpression::Linear(..) | EvalExpression::Single(_)
                ) {
                    // take next element from next_witness_buf
                    MultilinearExtensionGpu::from_ceno_gpu_ext(GpuPolynomialExt::new(
                        next_iter
                            .next()
                            .expect("not enough elements in next_witness_buf"),
                        num_vars,
                    ))
                } else {
                    MultilinearExtensionGpu::default()
                }
            })
            .map(Arc::new)
            .collect_vec()
    }
}
