//! Minimal matrix class that supports strided access.
//! This abstracts over the unsafe pointer arithmetic required for transpose-like algorithms.

#![allow(unsafe_code)]

use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
    ptr, slice,
};

/// The same as MatrixMut, except that data[skip * i] is treated as data[i],
/// and the other positions in data should not be accessed.
pub struct MatrixMutSkip<'a, T> {
    data: *mut T,
    skip: usize,
    rows: usize,
    cols: usize,
    row_stride: usize,
    _lifetime: PhantomData<&'a mut T>,
}

unsafe impl<T: Send> Send for MatrixMutSkip<'_, T> {}

unsafe impl<T: Sync> Sync for MatrixMutSkip<'_, T> {}

impl<'a, T> MatrixMutSkip<'a, T> {
    /// creates a MatrixMut from `slice`, where slice is the concatenations of `rows` rows, each consisting of `cols` many entries.
    pub fn from_mut_slice(
        slice: &'a mut [T],
        rows: usize,
        cols: usize,
        skip: usize,
        offset: usize,
    ) -> Self {
        assert_eq!(slice.len(), rows * cols * skip);
        // Safety: The input slice is valid for the lifetime `'a` and has
        // `rows` contiguous rows of length `cols`.
        Self {
            data: unsafe { slice.as_mut_ptr().add(offset) },
            skip,
            rows,
            cols,
            row_stride: cols,
            _lifetime: PhantomData,
        }
    }

    /// returns the number of rows
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// returns the number of columns
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// checks whether the matrix is a square matrix
    pub fn is_square(&self) -> bool {
        self.rows == self.cols
    }

    /// returns a mutable reference to the `row`'th row of the MatrixMutSkip,
    /// together with the skip to remind the users that the row
    pub fn row(&mut self, row: usize) -> (&mut [T], usize) {
        assert!(row < self.rows);
        // Safety: The structure invariant guarantees that at offset `row * self.row_stride`
        // there is valid data of length `self.cols`.
        unsafe {
            (
                slice::from_raw_parts_mut(
                    self.data.add(row * self.row_stride * self.skip),
                    self.cols * self.skip,
                ),
                self.skip,
            )
        }
    }

    /// Split the matrix into two vertically at the `row`'th row (meaning that in the returned pair (A,B), the matrix A has `row` rows).
    ///
    /// [A]
    /// [ ] = self
    /// [B]
    pub fn split_vertical(self, row: usize) -> (Self, Self) {
        assert!(row <= self.rows);
        (
            Self {
                data: self.data,
                skip: self.skip,
                rows: row,
                cols: self.cols,
                row_stride: self.row_stride,
                _lifetime: PhantomData,
            },
            Self {
                data: unsafe { self.data.add(row * self.row_stride * self.skip) },
                skip: self.skip,
                rows: self.rows - row,
                cols: self.cols,
                row_stride: self.row_stride,
                _lifetime: PhantomData,
            },
        )
    }

    /// Split the matrix into two horizontally at the `col`th column (meaning that in the returned pair (A,B), the matrix A has `col` columns).
    ///
    /// [A B] = self
    pub fn split_horizontal(self, col: usize) -> (Self, Self) {
        assert!(col <= self.cols);
        (
            // Safety: This reduces the number of cols, keeping all else the same.
            Self {
                data: self.data,
                skip: self.skip,
                rows: self.rows,
                cols: col,
                row_stride: self.row_stride,
                _lifetime: PhantomData,
            },
            // Safety: This reduces the number of cols and offsets and, keeping all else the same.
            Self {
                data: unsafe { self.data.add(col * self.skip) },
                skip: self.skip,
                rows: self.rows,
                cols: self.cols - col,
                row_stride: self.row_stride,
                _lifetime: PhantomData,
            },
        )
    }

    /// Split the matrix into four quadrants at the indicated `row` and `col` (meaning that in the returned 4-tuple (A,B,C,D), the matrix A is a `row`x`col` matrix)
    ///
    /// self = [A B]
    ///        [C D]
    pub fn split_quadrants(self, row: usize, col: usize) -> (Self, Self, Self, Self) {
        let (u, l) = self.split_vertical(row); // split into upper and lower parts
        let (a, b) = u.split_horizontal(col);
        let (c, d) = l.split_horizontal(col);
        (a, b, c, d)
    }

    /// Swap two elements `a` and `b` in the matrix.
    /// Each of `a`, `b` is given as (row,column)-pair.
    /// If the given coordinates are out-of-bounds, the behaviour is undefined.
    pub unsafe fn swap(&mut self, a: (usize, usize), b: (usize, usize)) {
        if a != b {
            unsafe {
                let a = self.ptr_at_mut(a.0, a.1);
                let b = self.ptr_at_mut(b.0, b.1);
                ptr::swap_nonoverlapping(a, b, 1)
            }
        }
    }

    /// returns an immutable pointer to the element at (`row`, `col`). This performs no bounds checking and provining indices out-of-bounds is UB.
    unsafe fn ptr_at(&self, row: usize, col: usize) -> *const T {
        // Safe to call under the following assertion (checked by caller)
        // assert!(row < self.rows);
        // assert!(col < self.cols);

        // Safety: The structure invariant guarantees that at offset `row * self.row_stride + col`
        // there is valid data.
        self.data.add((row * self.row_stride + col) * self.skip)
    }

    /// returns a mutable pointer to the element at (`row`, `col`). This performs no bounds checking and provining indices out-of-bounds is UB.
    unsafe fn ptr_at_mut(&mut self, row: usize, col: usize) -> *mut T {
        // Safe to call under the following assertion (checked by caller)
        //
        // assert!(row < self.rows);
        // assert!(col < self.cols);

        // Safety: The structure invariant guarantees that at offset `row * self.row_stride + col`
        // there is valid data.
        self.data.add((row * self.row_stride + col) * self.skip)
    }
}

// Use MatrixMut::ptr_at and MatrixMut::ptr_at_mut to implement Index and IndexMut. The latter are not unsafe, since they contain bounds-checks.

impl<T> Index<(usize, usize)> for MatrixMutSkip<'_, T> {
    type Output = T;

    fn index(&self, (row, col): (usize, usize)) -> &T {
        assert!(row < self.rows);
        assert!(col < self.cols);
        // Safety: The structure invariant guarantees that at offset `row * self.row_stride + col`
        // there is valid data.
        unsafe { &*self.ptr_at(row, col) }
    }
}

impl<T> IndexMut<(usize, usize)> for MatrixMutSkip<'_, T> {
    fn index_mut(&mut self, (row, col): (usize, usize)) -> &mut T {
        assert!(row < self.rows);
        assert!(col < self.cols);
        // Safety: The structure invariant guarantees that at offset `row * self.row_stride + col`
        // there is valid data.
        unsafe { &mut *self.ptr_at_mut(row, col) }
    }
}
