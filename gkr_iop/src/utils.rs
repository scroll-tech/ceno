use std::sync::Arc;

use ff_ext::ExtensionField;
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    wit_infer_by_expr,
};
use p3_field::PrimeCharacteristicRing;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{evaluation::EvalExpression, gkr::layer::Layer};

pub fn infer_layer_witness<'a, E>(
    layer: &Layer<E>,
    layer_wits: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
) -> Vec<ArcMultilinearExtension<'a, E>>
where
    E: ExtensionField,
{
    let out_evals: Vec<_> = layer
        .outs
        .iter()
        .flat_map(|(_, out_eval)| out_eval.iter())
        .collect();
    layer
        .exprs
        .par_iter()
        .zip_eq(layer.expr_names.par_iter())
        .zip_eq(out_evals.par_iter())
        .map(|((expr, expr_name), out_eval)| match out_eval {
            EvalExpression::Single(_) => {
                wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr)
            }
            EvalExpression::Linear(0, _, _) => {
                if cfg!(debug_assertions) {
                    let out_mle = wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr);
                    let all_zero = match out_mle.evaluations() {
                        multilinear_extensions::mle::FieldType::Base(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::BaseField::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Ext(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Unreachable => unreachable!(),
                    };
                    if !all_zero {
                        panic!(
                            "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                            layer.name
                        );
                    }
                }
                MultilinearExtension::default().into() // this is zero mle
            }
            _ => unimplemented!(),
        })
        .collect::<Vec<_>>()
}

pub trait SliceVector<T> {
    fn slice_vector(&self) -> Vec<&[T]>;
}

pub trait SliceVectorMut<T> {
    fn slice_vector_mut(&mut self) -> Vec<&mut [T]>;
}

pub trait SliceIterator<'a, T: 'a> {
    fn slice_iter(&'a self) -> impl Iterator<Item = &'a [T]> + Clone;
}

impl<T> SliceVector<T> for Vec<Vec<T>> {
    fn slice_vector(&self) -> Vec<&[T]> {
        self.iter().map(|v| v.as_slice()).collect()
    }
}

impl<T> SliceVector<T> for Vec<Arc<Vec<T>>> {
    fn slice_vector(&self) -> Vec<&[T]> {
        self.iter().map(|v| v.as_slice()).collect()
    }
}

impl<'a, T: 'a> SliceIterator<'a, T> for Vec<Vec<T>> {
    fn slice_iter(&'a self) -> impl Iterator<Item = &'a [T]> + Clone {
        self.iter().map(|v| v.as_slice())
    }
}

impl<'a, T: 'a> SliceIterator<'a, T> for Vec<Arc<Vec<T>>> {
    fn slice_iter(&'a self) -> impl Iterator<Item = &'a [T]> + Clone {
        self.iter().map(|v| v.as_slice())
    }
}

impl<T> SliceVectorMut<T> for Vec<Vec<T>> {
    fn slice_vector_mut(&mut self) -> Vec<&mut [T]> {
        self.iter_mut().map(|v| v.as_mut_slice()).collect()
    }
}
