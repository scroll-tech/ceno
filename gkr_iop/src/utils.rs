use std::sync::Arc;

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
