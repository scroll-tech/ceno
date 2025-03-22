use std::sync::Arc;

use ff_ext::ExtensionField;
use itertools::izip;

type Point<E> = Arc<Vec<E>>;

pub trait PointBeforeMerge<E: ExtensionField> {
    fn point_before_merge(&self, pos: &[usize]) -> Point<E>;
}

pub trait PointBeforePartition<E: ExtensionField> {
    fn point_before_partition(
        &self,
        pos_and_var_ids: &[(usize, usize)],
        challenges: &[E],
    ) -> Point<E>;
}

/// Suppose we have several vectors v_0, ..., v_{N-1}, and want to merge it through n = log(N) variables,
/// x_0, ..., x_{n-1}, at the positions i_0, ..., i_{n - 1}. Suppose the output point is P, then the point
/// before it is P_0, ..., P_{i_0 - 1}, P_{i_0 + 1}, ..., P_{i_1 - 1}, ..., P_{i_{n - 1} + 1}, ..., P_{N - 1}.
impl<E: ExtensionField> PointBeforeMerge<E> for Point<E> {
    fn point_before_merge(&self, pos: &[usize]) -> Point<E> {
        if pos.is_empty() {
            return self.clone();
        }

        assert!(izip!(pos.iter(), pos.iter().skip(1)).all(|(i, j)| i < j));

        let mut new_point = Vec::with_capacity(self.len() - pos.len());
        let mut i = 0usize;
        for (j, p) in self.iter().enumerate() {
            if j != pos[i] {
                new_point.push(*p);
            } else {
                i += 1;
            }
        }

        Arc::new(new_point)
    }
}

/// Suppose we have a vector v, and want to partition it through n = log(N) variables
/// x_0, ..., x_{n-1}, at the positions i_0, ..., i_{n - 1}. Suppose the output point
/// is P, then the point before it is P after calling P.insert(i_0, x_0), ...
impl<E: ExtensionField> PointBeforePartition<E> for Point<E> {
    fn point_before_partition(
        &self,
        pos_and_var_ids: &[(usize, usize)],
        challenges: &[E],
    ) -> Point<E> {
        if pos_and_var_ids.is_empty() {
            return self.clone();
        }

        assert!(
            izip!(pos_and_var_ids.iter(), pos_and_var_ids.iter().skip(1)).all(|(i, j)| i.0 < j.0)
        );

        let mut new_point = Vec::with_capacity(self.len() + pos_and_var_ids.len());
        let mut i = 0usize;
        for (j, p) in self.iter().enumerate() {
            if i + j != pos_and_var_ids[i].0 {
                new_point.push(*p);
            } else {
                new_point.push(challenges[pos_and_var_ids[i].1]);
                i += 1;
            }
        }

        Arc::new(new_point)
    }
}
