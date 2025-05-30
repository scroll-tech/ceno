use std::sync::Arc;

use ff_ext::ExtensionField;
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    wit_infer_by_expr,
};
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
        .zip_eq(out_evals.par_iter())
        .map(|(expr, out_eval)| match out_eval {
            EvalExpression::Single(_) => {
                wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr)
            }
            EvalExpression::Linear(0, _, _) => MultilinearExtension::default().into(), // this is zero mle
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
