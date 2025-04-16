use crate::ntt::matrix_skip::MatrixMutSkip;

use super::{super::utils::is_power_of_two, MatrixMut, utils::workload_size};
use std::mem::swap;

use p3::matrix::{Matrix, dense::RowMajorMatrix};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
#[cfg(feature = "parallel")]
use rayon::join;
use sumcheck::macros::{entered_span, exit_span};

// NOTE: The assumption that rows and cols are a power of two are actually only relevant for the square matrix case.
// (This is because the algorithm recurses into 4 sub-matrices of half dimension; we assume those to be square matrices as well, which only works for powers of two).

/// Transpose a matrix in-place.
/// Will batch transpose multiple matrices if the length of the slice is a multiple of rows * cols.
/// This algorithm assumes that both rows and cols are powers of two.
pub fn transpose<F: Sized + Copy + Send>(matrix: &mut [F], rows: usize, cols: usize) {
    debug_assert_eq!(matrix.len() % (rows * cols), 0);
    // eprintln!(
    //     "Transpose {} x {rows} x {cols} matrix.",
    //     matrix.len() / (rows * cols)
    // );
    if rows == cols {
        debug_assert!(is_power_of_two(rows));
        debug_assert!(is_power_of_two(cols));
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            let matrix = MatrixMut::from_mut_slice(matrix, rows, cols);
            transpose_square(matrix);
        }
    } else {
        // TODO: Special case for rows = 2 * cols and cols = 2 * rows.
        // TODO: Special case for very wide matrices (e.g. n x 16).
        let mut scratch = Vec::with_capacity(rows * cols);
        #[allow(clippy::uninit_vec)]
        unsafe {
            scratch.set_len(rows * cols);
        }
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            scratch.copy_from_slice(matrix);
            let src = MatrixMut::from_mut_slice(scratch.as_mut_slice(), rows, cols);
            let dst = MatrixMut::from_mut_slice(matrix, cols, rows);
            transpose_copy(src, dst);
        }
    }
}

/// Transpose each column of the rmm as if it is a matrix
pub fn transpose_rmm_column_wise<F: Sized + Copy + Send + Sync>(
    matrix: &mut RowMajorMatrix<F>,
    rows: usize,
    cols: usize,
) {
    debug_assert_eq!(matrix.height(), rows * cols);
    let skip = matrix.width();
    let mut scratch: Vec<F> = Vec::with_capacity(matrix.height() * matrix.width());
    #[allow(clippy::uninit_vec)]
    unsafe {
        scratch.set_len(matrix.height() * matrix.width());
    }
    let copy_timer = entered_span!("Copy to scratch");
    scratch.copy_from_slice(&matrix.values);
    exit_span!(copy_timer);
    let src = MatrixMutSkip::from_mut_slice(scratch.as_mut_slice(), rows, cols, skip, 0);
    let dst = MatrixMutSkip::from_mut_slice(matrix.values.as_mut_slice(), cols, rows, skip, 0);
    let copy_timer = entered_span!("Transpose copy");
    transpose_copy_batch(src, dst);
    exit_span!(copy_timer);
}

pub fn transpose_bench_allocate<F: Sized + Copy + Send>(
    matrix: &mut [F],
    rows: usize,
    cols: usize,
) {
    debug_assert_eq!(matrix.len() % (rows * cols), 0);
    // eprintln!(
    //     "Transpose {} x {rows} x {cols} matrix.",
    //     matrix.len() / (rows * cols)
    // );
    if rows == cols {
        debug_assert!(is_power_of_two(rows));
        debug_assert!(is_power_of_two(cols));
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            let matrix = MatrixMut::from_mut_slice(matrix, rows, cols);
            transpose_square(matrix);
        }
    } else {
        // TODO: Special case for rows = 2 * cols and cols = 2 * rows.
        // TODO: Special case for very wide matrices (e.g. n x 16).
        let allocate_timer = entered_span!("Allocate scratch.");
        let mut scratch = Vec::with_capacity(rows * cols);
        #[allow(clippy::uninit_vec)]
        unsafe {
            scratch.set_len(rows * cols);
        }
        exit_span!(allocate_timer);
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            let copy_timer = entered_span!("Copy from slice.");
            scratch.copy_from_slice(matrix);
            exit_span!(copy_timer);
            let src = MatrixMut::from_mut_slice(scratch.as_mut_slice(), rows, cols);
            let dst = MatrixMut::from_mut_slice(matrix, cols, rows);
            let transpose_copy_timer = entered_span!("Transpose Copy.");
            transpose_copy(src, dst);
            exit_span!(transpose_copy_timer);
        }
    }
}

pub fn transpose_test<F: Sized + Copy + Send>(
    matrix: &mut [F],
    rows: usize,
    cols: usize,
    buffer: &mut [F],
) {
    debug_assert_eq!(matrix.len() % (rows * cols), 0);
    // eprintln!(
    //     "Transpose {} x {rows} x {cols} matrix.",
    //     matrix.len() / (rows * cols)
    // );
    if rows == cols {
        debug_assert!(is_power_of_two(rows));
        debug_assert!(is_power_of_two(cols));
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            let matrix = MatrixMut::from_mut_slice(matrix, rows, cols);
            transpose_square(matrix);
        }
    } else {
        let buffer = &mut buffer[0..rows * cols];
        // TODO: Special case for rows = 2 * cols and cols = 2 * rows.
        // TODO: Special case for very wide matrices (e.g. n x 16).
        let transpose_timer = entered_span!("Transpose");
        for matrix in matrix.chunks_exact_mut(rows * cols) {
            let copy_timer = entered_span!("Copy from slice");
            // buffer.copy_from_slice(matrix);
            buffer
                .par_iter_mut()
                .zip(matrix.par_iter_mut())
                .for_each(|(dst, src)| {
                    *dst = *src;
                });
            exit_span!(copy_timer);
            let transform_timer = entered_span!("From mut slice");
            let src = MatrixMut::from_mut_slice(buffer, rows, cols);
            let dst = MatrixMut::from_mut_slice(matrix, cols, rows);
            exit_span!(transform_timer);
            let transpose_copy_timer = entered_span!("Transpose copy");
            transpose_copy(src, dst);
            exit_span!(transpose_copy_timer);
        }
        exit_span!(transpose_timer);
    }
}

// The following function have both a parallel and a non-parallel implementation.
// We fuly split those in a parallel and a non-parallel functions (rather than using #[cfg] within a single function)
// and have main entry point fun that just calls the appropriate version (either fun_parallel or fun_not_parallel).
// The sole reason is that this simplifies unit tests: We otherwise would need to build twice to cover both cases.
// For effiency, we assume the compiler inlines away the extra "indirection" that we add to the entry point function.

// NOTE: We could lift the Send constraints on non-parallel build.

fn transpose_copy<F: Sized + Copy + Send>(src: MatrixMut<F>, dst: MatrixMut<F>) {
    #[cfg(not(feature = "parallel"))]
    transpose_copy_not_parallel(src, dst);
    #[cfg(feature = "parallel")]
    transpose_copy_parallel(src, dst);
}

fn transpose_copy_batch<F: Sized + Copy + Send>(src: MatrixMutSkip<F>, dst: MatrixMutSkip<F>) {
    #[cfg(feature = "parallel")]
    transpose_copy_parallel_batch(src, dst);
}

/// Sets `dst` to the transpose of `src`. This will panic if the sizes of `src` and `dst` are not compatible.
#[cfg(feature = "parallel")]
fn transpose_copy_parallel<F: Sized + Copy + Send>(
    src: MatrixMut<'_, F>,
    mut dst: MatrixMut<'_, F>,
) {
    assert_eq!(src.rows(), dst.cols());
    assert_eq!(src.cols(), dst.rows());
    if src.rows() * src.cols() > workload_size::<F>() {
        // Split along longest axis and recurse.
        // This results in a cache-oblivious algorithm.
        let ((a, b), (x, y)) = if src.rows() > src.cols() {
            let n = src.rows() / 2;
            (src.split_vertical(n), dst.split_horizontal(n))
        } else {
            let n = src.cols() / 2;
            (src.split_horizontal(n), dst.split_vertical(n))
        };
        join(
            || transpose_copy_parallel(a, x),
            || transpose_copy_parallel(b, y),
        );
    } else {
        for i in 0..src.rows() {
            for j in 0..src.cols() {
                dst[(j, i)] = src[(i, j)];
            }
        }
    }
}

#[cfg(feature = "parallel")]
fn transpose_copy_parallel_batch<'a, F: Sized + Copy + Send>(
    src: MatrixMutSkip<'a, F>,
    mut dst: MatrixMutSkip<'a, F>,
) {
    assert_eq!(src.rows(), dst.cols());
    assert_eq!(src.cols(), dst.rows());
    if src.rows() * src.cols() > workload_size::<F>() {
        // Split along longest axis and recurse.
        // This results in a cache-oblivious algorithm.
        let ((a, b), (x, y)) = if src.rows() > src.cols() {
            let n = src.rows() / 2;
            (src.split_vertical(n), dst.split_horizontal(n))
        } else {
            let n = src.cols() / 2;
            (src.split_horizontal(n), dst.split_vertical(n))
        };
        join(
            || transpose_copy_parallel_batch(a, x),
            || transpose_copy_parallel_batch(b, y),
        );
    } else {
        for i in 0..src.rows() {
            for j in 0..src.cols() {
                dst.copy_from_another_matrix_batch(&src, j, i, i, j);
            }
        }
    }
}

/// Sets `dst` to the transpose of `src`. This will panic if the sizes of `src` and `dst` are not compatible.
/// This is the non-parallel version
fn transpose_copy_not_parallel<F: Sized + Copy>(src: MatrixMut<'_, F>, mut dst: MatrixMut<'_, F>) {
    assert_eq!(src.rows(), dst.cols());
    assert_eq!(src.cols(), dst.rows());
    if src.rows() * src.cols() > workload_size::<F>() {
        // Split along longest axis and recurse.
        // This results in a cache-oblivious algorithm.
        let ((a, b), (x, y)) = if src.rows() > src.cols() {
            let n = src.rows() / 2;
            (src.split_vertical(n), dst.split_horizontal(n))
        } else {
            let n = src.cols() / 2;
            (src.split_horizontal(n), dst.split_vertical(n))
        };
        transpose_copy_not_parallel(a, x);
        transpose_copy_not_parallel(b, y);
    } else {
        for i in 0..src.rows() {
            for j in 0..src.cols() {
                dst[(j, i)] = src[(i, j)];
            }
        }
    }
}

/// Transpose a square matrix in-place. Asserts that the size of the matrix is a power of two.
fn transpose_square<F: Sized + Send>(m: MatrixMut<F>) {
    #[cfg(feature = "parallel")]
    transpose_square_parallel(m);
    #[cfg(not(feature = "parallel"))]
    transpose_square_non_parallel(m);
}

/// Transpose a square matrix in-place. Asserts that the size of the matrix is a power of two.
/// This is the parallel version.
#[cfg(feature = "parallel")]
fn transpose_square_parallel<F: Sized + Send>(mut m: MatrixMut<F>) {
    debug_assert!(m.is_square());
    debug_assert!(m.rows().is_power_of_two());
    let size = m.rows();
    if size * size > workload_size::<F>() {
        // Recurse into quadrants.
        // This results in a cache-oblivious algorithm.
        let n = size / 2;
        let (a, b, c, d) = m.split_quadrants(n, n);

        join(
            || transpose_square_swap_parallel(b, c),
            || {
                join(
                    || transpose_square_parallel(a),
                    || transpose_square_parallel(d),
                )
            },
        );
    } else {
        for i in 0..size {
            for j in (i + 1)..size {
                // unsafe needed due to lack of bounds-check by swap. We are guaranteed that (i,j) and (j,i) are within the bounds.
                unsafe {
                    m.swap((i, j), (j, i));
                }
            }
        }
    }
}

/// Transpose a square matrix in-place. Asserts that the size of the matrix is a power of two.
/// This is the non-parallel version.
fn transpose_square_non_parallel<F: Sized>(mut m: MatrixMut<F>) {
    debug_assert!(m.is_square());
    debug_assert!(m.rows().is_power_of_two());
    let size = m.rows();
    if size * size > workload_size::<F>() {
        // Recurse into quadrants.
        // This results in a cache-oblivious algorithm.
        let n = size / 2;
        let (a, b, c, d) = m.split_quadrants(n, n);
        transpose_square_non_parallel(a);
        transpose_square_non_parallel(d);
        transpose_square_swap_non_parallel(b, c);
    } else {
        for i in 0..size {
            for j in (i + 1)..size {
                // unsafe needed due to lack of bounds-check by swap. We are guaranteed that (i,j) and (j,i) are within the bounds.
                unsafe {
                    m.swap((i, j), (j, i));
                }
            }
        }
    }
}

/// Transpose and swap two square size matrices. Sizes must be equal and a power of two.
fn transpose_square_swap<F: Sized + Send>(a: MatrixMut<F>, b: MatrixMut<F>) {
    #[cfg(feature = "parallel")]
    transpose_square_swap_parallel(a, b);
    #[cfg(not(feature = "parallel"))]
    transpose_square_swap_non_parallel(a, b);
}

/// Transpose and swap two square size matrices (parallel version). The size must be a power of two.
#[cfg(feature = "parallel")]
fn transpose_square_swap_parallel<F: Sized + Send>(mut a: MatrixMut<F>, mut b: MatrixMut<F>) {
    debug_assert!(a.is_square());
    debug_assert_eq!(a.rows(), b.cols());
    debug_assert_eq!(a.cols(), b.rows());
    debug_assert!(is_power_of_two(a.rows()));
    debug_assert!(workload_size::<F>() >= 2); // otherwise, we would recurse even if size == 1.
    let size = a.rows();
    if 2 * size * size > workload_size::<F>() {
        // Recurse into quadrants.
        // This results in a cache-oblivious algorithm.
        let n = size / 2;
        let (aa, ab, ac, ad) = a.split_quadrants(n, n);
        let (ba, bb, bc, bd) = b.split_quadrants(n, n);

        join(
            || {
                join(
                    || transpose_square_swap_parallel(aa, ba),
                    || transpose_square_swap_parallel(ab, bc),
                )
            },
            || {
                join(
                    || transpose_square_swap_parallel(ac, bb),
                    || transpose_square_swap_parallel(ad, bd),
                )
            },
        );
    } else {
        for i in 0..size {
            for j in 0..size {
                swap(&mut a[(i, j)], &mut b[(j, i)])
            }
        }
    }
}

/// Transpose and swap two square size matrices, whose sizes are a power of two (non-parallel version)
fn transpose_square_swap_non_parallel<F: Sized>(mut a: MatrixMut<F>, mut b: MatrixMut<F>) {
    debug_assert!(a.is_square());
    debug_assert_eq!(a.rows(), b.cols());
    debug_assert_eq!(a.cols(), b.rows());
    debug_assert!(is_power_of_two(a.rows()));
    debug_assert!(workload_size::<F>() >= 2); // otherwise, we would recurse even if size == 1.

    let size = a.rows();
    if 2 * size * size > workload_size::<F>() {
        // Recurse into quadrants.
        // This results in a cache-oblivious algorithm.
        let n = size / 2;
        let (aa, ab, ac, ad) = a.split_quadrants(n, n);
        let (ba, bb, bc, bd) = b.split_quadrants(n, n);
        transpose_square_swap_non_parallel(aa, ba);
        transpose_square_swap_non_parallel(ab, bc);
        transpose_square_swap_non_parallel(ac, bb);
        transpose_square_swap_non_parallel(ad, bd);
    } else {
        for i in 0..size {
            for j in 0..size {
                swap(&mut a[(i, j)], &mut b[(j, i)])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::utils::workload_size, *};

    type Pair = (usize, usize);
    type Triple = (usize, usize, usize);

    // create a vector (intended to be viewed as a matrix) whose (i,j)'th entry is the pair (i,j) itself.
    // This is useful to debug transposition algorithms.
    fn make_example_matrix(rows: usize, columns: usize) -> Vec<Pair> {
        let mut v: Vec<Pair> = vec![(0, 0); rows * columns];
        let mut view = MatrixMut::from_mut_slice(&mut v, rows, columns);
        for i in 0..rows {
            for j in 0..columns {
                view[(i, j)] = (i, j);
            }
        }
        v
    }

    // create a vector (intended to be viewed as a sequence of `instances` of matrices) where (i,j)'th entry of the `index`th matrix
    // is the triple (index, i,j).
    fn make_example_matrices(rows: usize, columns: usize, instances: usize) -> Vec<Triple> {
        let mut v: Vec<Triple> = vec![(0, 0, 0); rows * columns * instances];
        for index in 0..instances {
            let mut view = MatrixMut::from_mut_slice(
                &mut v[rows * columns * index..rows * columns * (index + 1)],
                rows,
                columns,
            );
            for i in 0..rows {
                for j in 0..columns {
                    view[(i, j)] = (index, i, j);
                }
            }
        }
        v
    }

    #[test]
    fn test_transpose_copy() {
        // iterate over both parallel and non-parallel implementation.
        // Needs HRTB, otherwise it won't work.
        #[allow(clippy::type_complexity)]
        let mut funs: Vec<&dyn for<'a, 'b> Fn(MatrixMut<'a, Pair>, MatrixMut<'b, Pair>)> = vec![
            &transpose_copy_not_parallel::<Pair>,
            &transpose_copy::<Pair>,
        ];
        #[cfg(feature = "parallel")]
        funs.push(&transpose_copy_parallel::<Pair>);

        for f in funs {
            let rows: usize = workload_size::<Pair>() + 1; // intentionally not a power of two: The function is not described as only working for powers of two.
            let columns: usize = 4;
            let mut srcarray = make_example_matrix(rows, columns);
            let mut dstarray: Vec<(usize, usize)> = vec![(0, 0); rows * columns];

            let src1 = MatrixMut::<Pair>::from_mut_slice(&mut srcarray[..], rows, columns);
            let dst1 = MatrixMut::<Pair>::from_mut_slice(&mut dstarray[..], columns, rows);

            f(src1, dst1);
            let dst1 = MatrixMut::<Pair>::from_mut_slice(&mut dstarray[..], columns, rows);

            for i in 0..rows {
                for j in 0..columns {
                    assert_eq!(dst1[(j, i)], (i, j));
                }
            }
        }
    }

    #[test]
    fn test_transpose_square_swap() {
        // iterate over parallel and non-parallel variants:
        #[allow(clippy::type_complexity)]
        let mut funs: Vec<&dyn for<'a> Fn(MatrixMut<'a, Triple>, MatrixMut<'a, Triple>)> = vec![
            &transpose_square_swap::<Triple>,
            &transpose_square_swap_non_parallel::<Triple>,
        ];
        #[cfg(feature = "parallel")]
        funs.push(&transpose_square_swap_parallel::<Triple>);

        for f in funs {
            // Set rows manually. We want to be sure to trigger the actual recursion.
            // (Computing this from workload_size was too much hassle.)
            let rows = 1024; // workload_size::<Triple>();
            assert!(rows * rows > 2 * workload_size::<Triple>());

            let examples: Vec<Triple> = make_example_matrices(rows, rows, 2);
            // Make copies for simplicity, because we borrow different parts.
            let mut examples1 = Vec::from(&examples[0..rows * rows]);
            let mut examples2 = Vec::from(&examples[rows * rows..2 * rows * rows]);

            let view1 = MatrixMut::from_mut_slice(&mut examples1, rows, rows);
            let view2 = MatrixMut::from_mut_slice(&mut examples2, rows, rows);
            for i in 0..rows {
                for j in 0..rows {
                    assert_eq!(view1[(i, j)], (0, i, j));
                    assert_eq!(view2[(i, j)], (1, i, j));
                }
            }
            f(view1, view2);
            let view1 = MatrixMut::from_mut_slice(&mut examples1, rows, rows);
            let view2 = MatrixMut::from_mut_slice(&mut examples2, rows, rows);
            for i in 0..rows {
                for j in 0..rows {
                    assert_eq!(view1[(i, j)], (1, j, i));
                    assert_eq!(view2[(i, j)], (0, j, i));
                }
            }
        }
    }

    #[test]
    fn test_transpose_square() {
        let mut funs: Vec<&dyn for<'a> Fn(MatrixMut<'a, _>)> = vec![
            &transpose_square::<Pair>,
            &transpose_square_parallel::<Pair>,
        ];
        #[cfg(feature = "parallel")]
        funs.push(&transpose_square::<Pair>);
        for f in funs {
            // Set rows manually. We want to be sure to trigger the actual recursion.
            // (Computing this from workload_size was too much hassle.)
            let size = 1024;
            assert!(size * size > 2 * workload_size::<Pair>());

            let mut example = make_example_matrix(size, size);
            let view = MatrixMut::from_mut_slice(&mut example, size, size);
            f(view);
            let view = MatrixMut::from_mut_slice(&mut example, size, size);
            for i in 0..size {
                for j in 0..size {
                    assert_eq!(view[(i, j)], (j, i));
                }
            }
        }
    }

    #[test]
    fn test_transpose() {
        let size = 1024;

        // rectangular matrix:
        let rows = size;
        let cols = 16;
        let mut example = make_example_matrix(rows, cols);
        transpose(&mut example, rows, cols);
        let view = MatrixMut::from_mut_slice(&mut example, cols, rows);
        for i in 0..cols {
            for j in 0..rows {
                assert_eq!(view[(i, j)], (j, i));
            }
        }

        // square matrix:
        let rows = size;
        let cols = size;
        let mut example = make_example_matrix(rows, cols);
        transpose(&mut example, rows, cols);
        let view = MatrixMut::from_mut_slice(&mut example, cols, rows);
        for i in 0..cols {
            for j in 0..rows {
                assert_eq!(view[(i, j)], (j, i));
            }
        }

        // 20 rectangular matrices:
        let number_of_matrices = 20;
        let rows = size;
        let cols = 16;
        let mut example = make_example_matrices(rows, cols, number_of_matrices);
        transpose(&mut example, rows, cols);
        for index in 0..number_of_matrices {
            let view = MatrixMut::from_mut_slice(
                &mut example[index * rows * cols..(index + 1) * rows * cols],
                cols,
                rows,
            );
            for i in 0..cols {
                for j in 0..rows {
                    assert_eq!(view[(i, j)], (index, j, i));
                }
            }
        }

        // 20 square matrices:
        let number_of_matrices = 20;
        let rows = size;
        let cols = size;
        let mut example = make_example_matrices(rows, cols, number_of_matrices);
        transpose(&mut example, rows, cols);
        for index in 0..number_of_matrices {
            let view = MatrixMut::from_mut_slice(
                &mut example[index * rows * cols..(index + 1) * rows * cols],
                cols,
                rows,
            );
            for i in 0..cols {
                for j in 0..rows {
                    assert_eq!(view[(i, j)], (index, j, i));
                }
            }
        }
    }
}
