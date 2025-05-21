use std::sync::Arc;

use ff_ext::ExtensionField;
use multilinear_extensions::{mle::ArcMultilinearExtension, wit_infer_by_expr};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::gkr::layer::Layer;

pub fn infer_layer_witness<'a, E>(
    layer: &Layer<E>,
    layer_wits: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
) -> Vec<ArcMultilinearExtension<'a, E>>
where
    E: ExtensionField,
{
    layer
        .exprs
        .par_iter()
        .map(|expr| wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr))
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
