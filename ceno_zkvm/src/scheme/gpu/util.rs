use std::{any::TypeId, sync::Arc};

use ceno_gpu::{
    Buffer, CudaHal,
    bb31::{CudaHalBB31, GpuFieldType, GpuPolynomial},
    common::mle::filter_mle_even_odd_batch,
};
use ff_ext::ExtensionField;
use gkr_iop::{
    error::BackendError,
    gpu::{BB31Base, MultilinearExtensionGpu},
};
use multilinear_extensions::{Expression, WitnessId, mle::MultilinearExtension};
use p3::field::{FieldAlgebra, PrimeField32};
use transcript::{BasicTranscript, Transcript};

use crate::{
    error::ZKVMError,
    scheme::septic_curve::{SepticExtension, SymbolicSepticExtension},
};

use crate::scheme::gpu::BB31Ext;

pub fn expect_basic_transcript<E: ExtensionField, T: Transcript<E>>(
    transcript: &mut T,
) -> &mut BasicTranscript<BB31Ext> {
    let actual = std::any::type_name::<T>();
    let expected = std::any::type_name::<BasicTranscript<BB31Ext>>();
    assert_eq!(
        actual, expected,
        "GPU backend requires BasicTranscript<BB31Ext>; got {actual}"
    );
    unsafe { &mut *(transcript as *mut T as *mut BasicTranscript<BB31Ext>) }
}

pub fn read_septic_value_from_gpu<'a, E: ExtensionField>(
    polys: &[Arc<MultilinearExtensionGpu<'a, E>>],
    index: usize,
) -> Result<SepticExtension<E::BaseField>, ZKVMError> {
    let coords = polys
        .iter()
        .map(|poly| read_base_value_from_gpu(poly, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(coords.into())
}

fn read_base_value_from_gpu<'a, E: ExtensionField>(
    poly: &Arc<MultilinearExtensionGpu<'a, E>>,
    index: usize,
) -> Result<E::BaseField, ZKVMError> {
    let stream = gkr_iop::gpu::get_thread_stream();
    match &poly.mle {
        GpuFieldType::Base(base_poly) => {
            let buffer = base_poly.evaluations();
            let raw = buffer
                .get(index, stream.as_ref())
                .map_err(|e| hal_to_backend_error(format!("failed to read GPU buffer: {e:?}")))?;
            let canonical = raw.as_canonical_u32();
            Ok(E::BaseField::from_canonical_u32(canonical))
        }
        GpuFieldType::Ext(_) => Err(hal_to_backend_error(
            "expected base-field polynomial for final-sum extraction",
        )),
        GpuFieldType::Unreachable => {
            Err(hal_to_backend_error("unreachable GPU polynomial variant"))
        }
    }
}

pub fn batch_mles_take_half<'a, E: ExtensionField>(
    polynomials: &[Arc<MultilinearExtensionGpu<'a, E>>],
    chunk_index: usize,
) -> Result<Vec<Arc<MultilinearExtensionGpu<'a, E>>>, ZKVMError> {
    if polynomials.is_empty() {
        return Ok(Vec::new());
    }

    debug_assert!(
        chunk_index < 2,
        "only two chunks are supported when splitting in half"
    );
    debug_assert_eq!(
        TypeId::of::<E::BaseField>(),
        TypeId::of::<BB31Base>(),
        "GPU backend only supports BabyBear base field"
    );

    polynomials
        .iter()
        .map(|poly| {
            let gpu_poly = match &poly.mle {
                GpuFieldType::Base(base) => base
                    .as_view_chunk(2)
                    .into_iter()
                    .nth(chunk_index)
                    .expect("chunk index must be valid"),
                GpuFieldType::Ext(_) => {
                    return Err(hal_to_backend_error(
                        "expected base-field polynomial for EC witness splitting",
                    ));
                }
                GpuFieldType::Unreachable => {
                    return Err(hal_to_backend_error("unreachable GPU polynomial variant"));
                }
            };
            let gpu_mle = MultilinearExtensionGpu::from_ceno_gpu_base(gpu_poly);
            Ok(Arc::new(gpu_mle))
        })
        .collect()
}

pub fn symbolic_from_mle<'a, E: ExtensionField>(
    registry: &mut WitnessRegistry<'a, E>,
    polys: &[Arc<MultilinearExtensionGpu<'a, E>>],
) -> SymbolicSepticExtension<E> {
    SymbolicSepticExtension::new(
        polys
            .iter()
            .cloned()
            .map(|poly| registry.register(poly))
            .collect(),
    )
}

#[derive(Default)]
pub struct WitnessRegistry<'a, E: ExtensionField> {
    gpu_mles: Vec<Arc<MultilinearExtensionGpu<'a, E>>>,
}

impl<'a, E: ExtensionField> WitnessRegistry<'a, E> {
    pub fn register(&mut self, mle: Arc<MultilinearExtensionGpu<'a, E>>) -> Expression<E> {
        let idx_u16 = u16::try_from(self.gpu_mles.len())
            .expect("witness identifier overflow in EC sum quark");
        self.gpu_mles.push(mle);
        Expression::WitIn(idx_u16 as WitnessId)
    }

    pub fn gpu_refs(&self) -> Vec<&MultilinearExtensionGpu<'a, E>> {
        self.gpu_mles.iter().map(|arc| arc.as_ref()).collect()
    }
}

pub fn hal_to_backend_error(message: impl Into<String>) -> ZKVMError {
    ZKVMError::BackendError(BackendError::CircuitError(message.into().into_boxed_str()))
}

pub fn mle_host_to_gpu<'a, E: ExtensionField>(
    cuda_hal: &CudaHalBB31,
    mle: &MultilinearExtension<'a, E>,
) -> Arc<MultilinearExtensionGpu<'static, E>> {
    if TypeId::of::<E::BaseField>() != TypeId::of::<BB31Base>() {
        panic!("GPU backend only supports BabyBear base field");
    }
    let gpu = MultilinearExtensionGpu::from_ceno(cuda_hal, mle);
    Arc::new(unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<'_, E>, MultilinearExtensionGpu<'static, E>>(
            gpu,
        )
    })
}

pub fn mle_filter_even_odd_batch<'a, E: ExtensionField>(
    cuda_hal: &CudaHalBB31,
    requests: &[(&[Arc<MultilinearExtensionGpu<'a, E>>], bool)],
) -> Result<Vec<Vec<Arc<MultilinearExtensionGpu<'static, E>>>>, ZKVMError> {
    let stream = gkr_iop::gpu::get_thread_stream();
    if requests.iter().all(|(polys, _)| polys.is_empty()) {
        return Ok(vec![Vec::new(); requests.len()]);
    }

    debug_assert_eq!(
        TypeId::of::<E::BaseField>(),
        TypeId::of::<BB31Base>(),
        "GPU backend only supports Babybear base field"
    );

    let mut flattened_refs = Vec::new();
    let mut flags = Vec::new();
    let mut result_num_vars = Vec::new();

    let expected_len = requests
        .first()
        .map(|(polys, _)| polys.len())
        .unwrap_or_default();
    assert!(
        requests
            .iter()
            .all(|(polys, _)| polys.len() == expected_len),
        "all filter requests must contain the same number of MLEs"
    );

    for (polys, flag) in requests {
        for poly in *polys {
            let num_vars = poly
                .mle
                .num_vars()
                .checked_sub(1)
                .expect("polynomial must have at least one variable");
            result_num_vars.push(num_vars);
            flattened_refs.push(&poly.mle);
            flags.push(*flag);
        }
    }

    if flattened_refs.is_empty() {
        return Ok(vec![Vec::new(); requests.len()]);
    }

    let stride = 1usize << result_num_vars[0];
    assert!(
        flattened_refs
            .iter()
            .zip(result_num_vars.iter())
            .all(|(poly, vars)| poly.num_vars() == vars + 1),
        "all MLEs must share the same number of variables before filtering"
    );

    let mut output_buffers = flattened_refs
        .iter()
        .map(|_| {
            cuda_hal
                .alloc_elems_on_device(stride, false, stream.as_ref())
                .map_err(|e| hal_to_backend_error(format!("failed to allocate GPU buffer: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let flattened_refs: Vec<&GpuFieldType<'static>> =
        unsafe { std::mem::transmute(flattened_refs) };

    filter_mle_even_odd_batch::<
        CudaHalBB31,
        BB31Ext,
        BB31Base,
        GpuFieldType<'static>,
        GpuPolynomial<'static>,
    >(
        cuda_hal,
        flattened_refs,
        &flags,
        &mut output_buffers,
        stream.as_ref(),
    )
    .map_err(|e| hal_to_backend_error(format!("GPU filter kernel failed: {e:?}")))?;

    let mut outputs = Vec::with_capacity(requests.len());
    let mut idx = 0;
    for _ in requests {
        let mut segment = Vec::with_capacity(expected_len);
        for _ in 0..expected_len {
            let buf = output_buffers
                .get(idx)
                .expect("missing buffer for filter result")
                .clone();
            let num_vars = result_num_vars[idx];
            let gpu_poly = GpuPolynomial::new(buf, num_vars);
            let gpu_mle = MultilinearExtensionGpu::from_ceno_gpu_base(gpu_poly);
            let gpu_mle_static = unsafe {
                std::mem::transmute::<
                    MultilinearExtensionGpu<'_, E>,
                    MultilinearExtensionGpu<'static, E>,
                >(gpu_mle)
            };
            segment.push(Arc::new(gpu_mle_static));
            idx += 1;
        }
        outputs.push(segment);
    }

    Ok(outputs)
}
