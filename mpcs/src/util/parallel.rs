pub fn num_threads() -> usize {
    #[cfg(feature = "parallel")]
    let nt = rayon::current_num_threads();
    return nt;

    #[cfg(not(feature = "parallel"))]
    return 1;
}

pub fn parallelize_iter<I, T, F>(iter: I, f: F)
where
    I: Send + Iterator<Item = T>,
    T: Send,
    F: Fn(T) + Send + Sync + Clone,
{

    #[cfg(feature = "parallel")]
    rayon::scope(|scope| {
        iter.for_each(|item| {
            let f = &f;
            scope.spawn(move |_| f(item))
        })
    });

    #[cfg(not(feature = "parallel"))]

    iter.for_each(f);
}

pub fn parallelize<T, F>(v: &mut [T], f: F)
where
    T: Send,
    F: Fn((&mut [T], usize)) + Send + Sync + Clone,
{

    #[cfg(feature = "parallel")]
    {
        use crate::util::arithmetic::div_ceil;
        let num_threads = num_threads();
        let chunk_size = div_ceil(v.len(), num_threads);
        if chunk_size < num_threads {
            f((v, 0));
        } else {
            parallelize_iter(v.chunks_mut(chunk_size).zip((0..).step_by(chunk_size)), f);
        }
    }

    #[cfg(not(feature = "parallel"))]

    f((v, 0));
}

pub fn par_sort_unstable<T>(v: &mut [T])
where
    T: Ord + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::slice::ParallelSliceMut;
        v.par_sort_unstable();
    }

    #[cfg(not(feature = "parallel"))]
    v.sort_unstable();
}

#[cfg(feature = "parallel")]
pub fn par_map_collect<T, R, C>(
    v: impl rayon::prelude::IntoParallelIterator<Item = T>,
    f: impl Fn(T) -> R + Send + Sync,
) -> C
where
    T: Send + Sync,
    R: Send,
    C: rayon::prelude::FromParallelIterator<R>,
{
    use rayon::prelude::ParallelIterator;
    v.into_par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn par_map_collect<T, R, C>(v: impl IntoIterator<Item = T>, f: impl Fn(T) -> R) -> C
where
    C: FromIterator<R>,
{
    v.into_iter().map(f).collect()
}
