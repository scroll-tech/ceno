use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::ops::{Index, IndexMut};

/// a chunked vector that grows in fixed-size chunks.
#[derive(Default, Debug, Clone)]
pub struct ChunkedVec<T> {
    chunks: Vec<Vec<T>>,
    chunk_size: usize,
    len: usize,
}

impl<T: Default + Send> ChunkedVec<T> {
    /// create a new ChunkedVec with a given chunk size.
    pub fn new(chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be > 0");
        Self {
            chunks: Vec::new(),
            chunk_size,
            len: 0,
        }
    }

    /// get the current number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// returns true if the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// access element by index (immutable).
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        let chunk_idx = index / self.chunk_size;
        let within_idx = index % self.chunk_size;
        self.chunks.get(chunk_idx)?.get(within_idx)
    }

    /// access element by index (mutable).
    /// get mutable reference to element at index, auto-creating chunks as needed
    pub fn get_or_create(&mut self, index: usize) -> &mut T {
        let chunk_idx = index / self.chunk_size;
        let within_idx = index % self.chunk_size;

        // Ensure enough chunks exist
        if chunk_idx >= self.chunks.len() {
            let to_create = chunk_idx + 1 - self.chunks.len();

            // Use rayon to create all missing chunks in parallel
            let mut new_chunks: Vec<Vec<T>> = (0..to_create)
                .map(|_| {
                    (0..self.chunk_size)
                        .into_par_iter()
                        .map(|_| Default::default())
                        .collect::<Vec<_>>()
                })
                .collect();

            self.chunks.append(&mut new_chunks);
        }

        let chunk = &mut self.chunks[chunk_idx];

        // Update the overall length
        if index >= self.len {
            self.len = index + 1;
        }

        &mut chunk[within_idx]
    }
}

impl<T: Default + Send> Index<usize> for ChunkedVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

impl<T: Default + Send> IndexMut<usize> for ChunkedVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_or_create(index)
    }
}
