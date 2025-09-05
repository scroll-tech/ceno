use crate::{
    gkr::{booleanhypercube::BooleanHypercube, layer::LayerWitness},
    gpu::GpuBackend,
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, mle::Point, monomial::Term, utils::eval_by_expr_constant,
};

use crate::selector::SelectorType;

use crate::gpu::{MultilinearExtensionGpu, gpu_prover::*};

use crate::hal::MultilinearPolynomial;

#[allow(clippy::type_complexity)]
pub fn extract_mle_relationships_from_monomial_terms<'a, E: ExtensionField>(
    monomial_terms: &[Term<Expression<E>, Expression<E>>],
    all_mles: &[&MultilinearExtensionGpu<'a, E>],
    public_io_evals: &[Either<E::BaseField, E>],
    challenges: &[E],
) -> (Vec<E>, Vec<Vec<usize>>, Vec<(usize, usize)>) {
    let mut term_coefficients = Vec::new();
    let mut mle_indices_per_term = Vec::new();
    let mut mle_size_info = Vec::new();

    for term in monomial_terms {
        // scalar - convert Either<E::BaseField, E> to E
        let scalar_either = eval_by_expr_constant(public_io_evals, challenges, &term.scalar);
        let scalar = match scalar_either {
            Either::Left(base_field_val) => E::from(base_field_val),
            Either::Right(ext_field_val) => ext_field_val,
        };
        term_coefficients.push(scalar);

        // MLE indices
        let mut indices = Vec::new();
        for expr in &term.product {
            match expr {
                Expression::WitIn(witin_id) => {
                    indices.push(*witin_id as usize);
                }
                _ => panic!("Unsupported expression in product: {:?}", expr),
            }
        }

        // MLE size - get this before moving indices
        let first_idx = indices.first().copied();
        mle_indices_per_term.push(indices);

        if let Some(first_idx) = first_idx {
            let num_vars = all_mles[first_idx].mle.num_vars();
            mle_size_info.push((num_vars, num_vars));
        }
    }

    (term_coefficients, mle_indices_per_term, mle_size_info)
}

pub fn build_eq_x_r_with_sel_gpu<'a, E: ExtensionField>(
    hal: &'a CudaHalGL64,
    point: &Point<E>,
    num_instances: usize,
    selector: &SelectorType<E>,
) -> MultilinearExtensionGpu<'a, E> {
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
    {
        panic!("GPU backend only supports Goldilocks base field");
    }

    let eq_len = 1 << point.len();
    let (num_instances, is_sp32, indices) = match selector {
        SelectorType::None => panic!("SelectorType::None"),
        SelectorType::Whole(_expr) => (eq_len, false, vec![]),
        SelectorType::Prefix(_, _expr) => (num_instances, false, vec![]),
        SelectorType::OrderedSparse32 { indices, .. } => (num_instances, true, indices.clone()),
    };

    // type eq
    let eq_mle = if is_sp32 {
        let eq = build_eq_x_r_gpu(hal, point);
        let mut eq_buf = match eq.mle {
            GpuFieldType::Base(_) => panic!("should be ext field"),
            GpuFieldType::Ext(mle) => mle,
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        };
        let indices_u32 = indices.iter().map(|x| *x as u32).collect_vec();
        ordered_sparse32_selector_gpu(&hal.inner, &mut eq_buf.buf, &indices_u32, num_instances)
            .unwrap();
        eq_buf
    } else {
        let point_gl64: &Point<GL64Ext> = unsafe { std::mem::transmute(point) };
        let mut gpu_output = hal.alloc_ext_elems_on_device(eq_len).unwrap();
        let gpu_points = hal.alloc_ext_elems_from_host(point_gl64).unwrap();
        build_mle_as_ceno(&hal.inner, &gpu_points, &mut gpu_output, num_instances).unwrap();
        GpuPolynomialExt::new(gpu_output, point.len())
    };
    let mle_gl64 = MultilinearExtensionGpu::from_ceno_gpu_ext(eq_mle);
    unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<'a, GL64Ext>, MultilinearExtensionGpu<'a, E>>(
            mle_gl64,
        )
    }
}

pub fn build_eq_x_r_gpu<'a, E: ExtensionField>(
    hal: &'a CudaHalGL64,
    point: &Point<E>,
) -> MultilinearExtensionGpu<'a, E> {
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
    {
        panic!("GPU backend only supports Goldilocks base field");
    }

    let eq_len = 1 << point.len();
    // type eq
    let point_gl64: &Point<GL64Ext> = unsafe { std::mem::transmute(point) };
    let eq_mle = {
        let mut gpu_output = hal.alloc_ext_elems_on_device(eq_len).unwrap();
        let gpu_points = hal.alloc_ext_elems_from_host(point_gl64).unwrap();
        build_mle_as_ceno(&hal.inner, &gpu_points, &mut gpu_output, eq_len).unwrap();
        GpuPolynomialExt::new(gpu_output, point.len())
    };
    let mle_gl64 = MultilinearExtensionGpu::from_ceno_gpu_ext(eq_mle);
    unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<'a, GL64Ext>, MultilinearExtensionGpu<'a, E>>(
            mle_gl64,
        )
    }
}

pub fn build_rotation_mles_gpu<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    cuda_hal: &'a CudaHalGL64,
    raw_rotation_exprs: &[(Expression<E>, Expression<E>)],
    wit: &LayerWitness<GpuBackend<E, PCS>>,
    bh: &BooleanHypercube,
    rotation_cyclic_group_log2: usize,
) -> Vec<MultilinearExtensionGpu<'a, E>> {
    raw_rotation_exprs
        .iter()
        .map(|rotation_expr| match rotation_expr {
            (Expression::WitIn(source_wit_id), _) => {
                let cyclic_group_size = 1 << rotation_cyclic_group_log2;
                let rotation_index = bh
                    .into_iter()
                    .take(cyclic_group_size)
                    .map(|x| x as u32)
                    .collect_vec();
                let input_mle = wit[*source_wit_id as usize].as_ref();
                let input_buf = match &input_mle.mle {
                    GpuFieldType::Base(poly) => poly.evaluations(),
                    GpuFieldType::Ext(_) => panic!("should be base field"),
                    _ => panic!("unimplemented input mle"),
                };
                let mut output_buf = cuda_hal.alloc_elems_on_device(input_buf.len()).unwrap();
                rotation_next_base_mle_gpu(
                    &cuda_hal.inner,
                    &mut output_buf,
                    input_buf,
                    &rotation_index,
                    cyclic_group_size,
                )
                .unwrap();
                let output_mle = MultilinearExtensionGpu::from_ceno_gpu_base(GpuPolynomial::new(
                    output_buf,
                    input_mle.mle.num_vars(),
                ));
                unsafe {
                    std::mem::transmute::<
                        MultilinearExtensionGpu<GL64Ext>,
                        MultilinearExtensionGpu<'_, E>,
                    >(output_mle)
                }
            }
            _ => unimplemented!("unimplemented rotation"),
        })
        .collect::<Vec<_>>()
}

pub fn build_rotation_selector_gpu<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    cuda_hal: &'a CudaHalGL64,
    wit: &LayerWitness<GpuBackend<E, PCS>>,
    rt: &Point<E>,
    bh: &BooleanHypercube,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
) -> MultilinearExtensionGpu<'a, E> {
    let total_len = wit[0].evaluations_len(); // Take first mle just to retrieve total length
    assert!(total_len.is_power_of_two());
    let mut output_buf = cuda_hal.alloc_ext_elems_on_device(total_len).unwrap();
    let eq = build_eq_x_r_gpu(cuda_hal, rt);
    let eq_buf = match &eq.mle {
        GpuFieldType::Base(_) => panic!("should be ext field"),
        GpuFieldType::Ext(mle) => mle.evaluations(),
        GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
    };
    let rotation_index = bh
        .into_iter()
        .take(rotation_cyclic_subgroup_size)
        .map(|x| x as u32)
        .collect_vec();
    rotation_selector_gpu(
        &cuda_hal.inner,
        &mut output_buf,
        eq_buf,
        &rotation_index,
        1 << rotation_cyclic_group_log2,
        rotation_cyclic_subgroup_size,
    )
    .unwrap();
    let output_mle = MultilinearExtensionGpu::from_ceno_gpu_ext(GpuPolynomialExt::new(
        output_buf,
        total_len.ilog2() as usize,
    ));
    unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<GL64Ext>, MultilinearExtensionGpu<'_, E>>(
            output_mle,
        )
    }
}
