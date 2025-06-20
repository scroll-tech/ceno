use crate::{
    ntt::{intt_batch, intt_batch_rmm},
    parameters::FoldType,
};

use p3::{
    field::{Field, TwoAdicField},
    matrix::Matrix,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Given the evaluation of f on the coset specified by coset_offset * <coset_gen>
/// Compute the fold on that point
pub fn compute_fold<F: Field>(
    answers: &[F],
    folding_randomness: &[F],
    mut coset_offset_inv: F,
    mut coset_gen_inv: F,
    two_inv: F,
    folding_factor: usize,
) -> F {
    let mut answers = answers.to_vec();

    // We recursively compute the fold, rec is where it is
    for rec in folding_randomness.iter().take(folding_factor) {
        let offset = answers.len() / 2;
        let mut new_answers = vec![F::ZERO; offset];
        let mut coset_index_inv = F::ONE;
        for i in 0..offset {
            let f_value_0 = answers[i];
            let f_value_1 = answers[i + offset];
            let point_inv = coset_offset_inv * coset_index_inv;

            let left = f_value_0 + f_value_1;
            let right = point_inv * (f_value_0 - f_value_1);

            new_answers[i] = two_inv * (left + *rec * right);
            coset_index_inv *= coset_gen_inv;
        }
        answers = new_answers;

        // Update for next one
        coset_offset_inv = coset_offset_inv * coset_offset_inv;
        coset_gen_inv = coset_gen_inv * coset_gen_inv;
    }

    answers[0]
}

pub fn restructure_evaluations<F: TwoAdicField>(
    mut stacked_evaluations: Vec<F>,
    fold_type: FoldType,
    domain_gen_inv: F,
    folding_factor: usize,
) -> Vec<F> {
    let folding_size = 1_u64 << folding_factor;
    assert_eq!(stacked_evaluations.len() % (folding_size as usize), 0);
    match fold_type {
        FoldType::Naive => stacked_evaluations,
        FoldType::ProverHelps => {
            // TODO: This partially undoes the NTT transform from tne encoding.
            // Maybe there is a way to not do the full transform in the first place.

            // Batch inverse NTTs
            intt_batch(&mut stacked_evaluations, folding_size as usize);

            // Apply coset and size correction.
            // Stacked evaluation at i is f(B_l) where B_l = w^i * <w^n/k>
            let size_inv = F::from_canonical_u64(folding_size).inverse();
            #[cfg(not(feature = "parallel"))]
            {
                let mut coset_offset_inv = F::ONE;
                for answers in stacked_evaluations.chunks_exact_mut(folding_size as usize) {
                    let mut scale = size_inv;
                    for v in answers.iter_mut() {
                        *v *= scale;
                        scale *= coset_offset_inv;
                    }
                    coset_offset_inv *= domain_gen_inv;
                }
            }
            #[cfg(feature = "parallel")]
            stacked_evaluations
                .par_chunks_exact_mut(folding_size as usize)
                .enumerate()
                .for_each_with(F::ZERO, |offset, (i, answers)| {
                    if *offset == F::ZERO {
                        *offset = domain_gen_inv.exp_u64(i as u64);
                    } else {
                        *offset *= domain_gen_inv;
                    }
                    let mut scale = size_inv;
                    for v in answers.iter_mut() {
                        *v *= scale;
                        scale *= *offset;
                    }
                });

            stacked_evaluations
        }
    }
}

pub fn restructure_evaluations_mut<F: TwoAdicField>(
    stacked_evaluations: &mut [F],
    fold_type: FoldType,
    domain_gen_inv: F,
    folding_factor: usize,
) {
    let folding_size = 1_u64 << folding_factor;
    assert_eq!(stacked_evaluations.len() % (folding_size as usize), 0);
    match fold_type {
        FoldType::Naive => {}
        FoldType::ProverHelps => {
            // TODO: This partially undoes the NTT transform from tne encoding.
            // Maybe there is a way to not do the full transform in the first place.

            // Batch inverse NTTs
            intt_batch(stacked_evaluations, folding_size as usize);

            // Apply coset and size correction.
            // Stacked evaluation at i is f(B_l) where B_l = w^i * <w^n/k>
            let size_inv = F::from_canonical_u64(folding_size).inverse();
            #[cfg(not(feature = "parallel"))]
            {
                let mut coset_offset_inv = F::ONE;
                for answers in stacked_evaluations.chunks_exact_mut(folding_size as usize) {
                    let mut scale = size_inv;
                    for v in answers.iter_mut() {
                        *v *= scale;
                        scale *= coset_offset_inv;
                    }
                    coset_offset_inv *= domain_gen_inv;
                }
            }
            #[cfg(feature = "parallel")]
            stacked_evaluations
                .par_chunks_exact_mut(folding_size as usize)
                .enumerate()
                .for_each_with(F::ZERO, |offset, (i, answers)| {
                    if *offset == F::ZERO {
                        *offset = domain_gen_inv.exp_u64(i as u64);
                    } else {
                        *offset *= domain_gen_inv;
                    }
                    let mut scale = size_inv;
                    for v in answers.iter_mut() {
                        *v *= scale;
                        scale *= *offset;
                    }
                });
        }
    }
}

pub fn restructure_evaluations_mut_rmm<F: TwoAdicField + Ord>(
    stacked_evaluations: &mut witness::RowMajorMatrix<F>,
    fold_type: FoldType,
    domain_gen_inv: F,
    folding_factor: usize,
) {
    let folding_size = 1_u64 << folding_factor;
    let num_polys = stacked_evaluations.width();
    assert_eq!(stacked_evaluations.height() % (folding_size as usize), 0);
    match fold_type {
        FoldType::Naive => {}
        FoldType::ProverHelps => {
            // TODO: This partially undoes the NTT transform from tne encoding.
            // Maybe there is a way to not do the full transform in the first place.

            // Batch inverse NTTs
            intt_batch_rmm(stacked_evaluations, folding_size as usize);

            // Apply coset and size correction.
            // Stacked evaluation at i is f(B_l) where B_l = w^i * <w^n/k>
            let size_inv = F::from_canonical_u64(folding_size).inverse();
            #[cfg(not(feature = "parallel"))]
            {
                let mut coset_offset_inv = F::ONE;
                for answers in
                    stacked_evaluations.chunks_exact_mut(folding_size as usize * num_polys)
                {
                    let mut scale = size_inv;
                    for v in answers.chunks_mut(num_polys) {
                        v.iter_mut().for_each(|v| *v *= scale);
                        scale *= coset_offset_inv;
                    }
                    coset_offset_inv *= domain_gen_inv;
                }
            }
            #[cfg(feature = "parallel")]
            stacked_evaluations
                .values
                .par_chunks_exact_mut(folding_size as usize * num_polys)
                .enumerate()
                .for_each_with(F::ZERO, |offset, (i, answers)| {
                    if *offset == F::ZERO {
                        *offset = domain_gen_inv.exp_u64(i as u64);
                    } else {
                        *offset *= domain_gen_inv;
                    }
                    let mut scale = size_inv;
                    for v in answers.chunks_mut(num_polys) {
                        v.iter_mut().for_each(|v| *v *= scale);
                        scale *= *offset;
                    }
                });
        }
    }
}

pub fn expand_from_univariate<F: Field>(point: F, num_variables: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(num_variables);
    let mut cur = point;
    for _ in 0..num_variables {
        res.push(cur);
        cur = cur * cur;
    }

    res
}

/// There is an alternative (possibly more efficient) implementation that iterates over the x in Gray code ordering.
///
/// LagrangePolynomialIterator for a given multilinear n-dimensional `point` iterates over pairs (x, y)
/// where x ranges over all possible {0,1}^n
/// and y equals the product y_1 * ... * y_n where
///
/// y_i = point[i] if x_i == 1
/// y_i = 1-point[i] if x_i == 0
///
/// This means that y == eq_poly(point, x)
pub struct LagrangePolynomialIterator<F: Field> {
    last_position: Option<usize>, /* the previously output BinaryHypercubePoint (encoded as usize). None before the first output. */
    point: Vec<F>, /* stores a copy of the `point` given when creating the iterator. For easier(?) bit-fiddling, we store in in reverse order. */
    point_negated: Vec<F>, /* stores the precomputed values 1-point[i] in the same ordering as point. */
    /// stack Stores the n+1 values (in order) 1, y_1, y_1*y_2, y_1*y_2*y_3, ..., y_1*...*y_n for the previously output y.
    /// Before the first iteration (if last_position == None), it stores the values for the next (i.e. first) output instead.
    stack: Vec<F>,
    num_variables: usize, // dimension
}

impl<F: Field> LagrangePolynomialIterator<F> {
    pub fn new(point: &[F]) -> Self {
        let mut point = point.to_owned();
        point.reverse();

        let num_variables = point.len();

        // Initialize a stack with capacity for messages/ message_hats and the identity element
        let mut stack: Vec<F> = Vec::with_capacity(point.len() + 1);
        stack.push(F::ONE);

        let mut point = point.clone();
        let mut point_negated: Vec<_> = point.iter().map(|x| F::ONE - *x).collect();
        // Iterate over the message_hats, update the running product, and push it onto the stack
        let mut running_product: F = F::ONE;
        for point_neg in &point_negated {
            running_product *= *point_neg;
            stack.push(running_product);
        }

        point.reverse();
        point_negated.reverse();

        // Return
        Self {
            num_variables,
            point,
            point_negated,
            stack,
            last_position: None,
        }
    }
}

impl<F: Field> Iterator for LagrangePolynomialIterator<F> {
    type Item = (usize, F);
    // Iterator implementation for the struct
    fn next(&mut self) -> Option<Self::Item> {
        // a) Check if this is the first iteration
        if self.last_position.is_none() {
            // Initialize last position
            self.last_position = Some(0);
            // Return the top of the stack
            return Some((0, *self.stack.last().unwrap()));
        }

        // b) Check if in the last iteration we finished iterating
        if self.last_position.unwrap() + 1 >= 1 << self.num_variables {
            return None;
        }

        // c) Everything else, first get bit diff
        let last_position = self.last_position.unwrap();
        let next_position = last_position + 1;
        let bit_diff = last_position ^ next_position;

        // Determine the shared prefix of the most significant bits
        let low_index_of_prefix = (bit_diff + 1).trailing_zeros() as usize;

        // Discard any stack values outside of this prefix
        self.stack.truncate(self.stack.len() - low_index_of_prefix);

        // Iterate up to this prefix computing lag poly correctly
        for bit_index in (0..low_index_of_prefix).rev() {
            let last_element = self.stack.last().unwrap();
            let next_bit: bool = (next_position & (1 << bit_index)) != 0;
            self.stack.push(match next_bit {
                true => *last_element * self.point[bit_index],
                false => *last_element * self.point_negated[bit_index],
            });
        }

        // Don't forget to update the last position
        self.last_position = Some(next_position);

        // Return the top of the stack
        Some((next_position, *self.stack.last().unwrap()))
    }
}

// TODO: Precompute two_inv?
// Alternatively, compute it directly without the general (and slow) .inverse() map.

/// Compute eq3(coords,point), where eq3 is the equality polynomial for {0,1,2}^n and point is interpreted as an element from {0,1,2}^n via (big Endian) ternary decomposition.
///
/// eq3(coords, point) is the unique polynomial of degree <=2 in each variable, s.t.
/// for coords, point in {0,1,2}^n, we have:
/// eq3(coords,point) = 1 if coords == point and 0 otherwise.
pub fn eq_poly3<F>(coords: &[F], mut point: usize) -> F
where
    F: Field,
{
    let two = F::ONE + F::ONE;
    let two_inv = two.inverse();

    let n_variables = coords.len();
    assert!(point < 3usize.pow(n_variables as u32));

    let mut acc = F::ONE;

    // Note: This iterates over the ternary decomposition least-significant trit(?) first.
    // Since our convention is big endian, we reverse the order of coords to account for this.
    for &val in coords.iter() {
        let b = point % 3;
        acc *= match b {
            0 => (val - F::ONE) * (val - two) * two_inv,
            1 => val * (val - two) * (-F::ONE),
            2 => val * (val - F::ONE) * two_inv,
            _ => unreachable!(),
        };
        point /= 3;
    }

    acc
}

#[cfg(test)]
mod tests {
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::mle::MultilinearExtension;
    use p3::field::{Field, FieldAlgebra, TwoAdicField};

    use crate::{
        utils::{evaluate_over_hypercube, stack_evaluations},
        whir::fold::expand_from_univariate,
    };

    use super::{compute_fold, restructure_evaluations};

    type F = GoldilocksExt2;

    #[test]
    fn test_folding() {
        let num_variables = 5;
        let num_coeffs = 1 << num_variables;

        let domain_size = 256;
        let folding_factor = 3; // We fold in 8
        let folding_factor_exp = 1 << folding_factor;

        let poly = MultilinearExtension::from_evaluations_ext_vec(
            num_variables,
            (0..num_coeffs)
                .map(F::from_canonical_u64)
                .collect::<Vec<_>>(),
        );

        let root_of_unity = F::two_adic_generator(p3::util::log2_strict_usize(domain_size));

        let index = 15;
        let folding_randomness: Vec<_> = (0..folding_factor)
            .map(|i| F::from_canonical_u64(i as u64))
            .collect();

        let coset_offset = root_of_unity.exp_u64(index);
        let coset_gen = root_of_unity.exp_u64((domain_size / folding_factor_exp) as u64);

        // Evaluate the polynomial on the coset
        let poly_eval: Vec<_> = (0..folding_factor_exp)
            .map(|i| {
                poly.evaluate(&expand_from_univariate(
                    coset_offset * coset_gen.exp_u64(i as u64),
                    num_variables,
                ))
            })
            .collect();

        let fold_value = compute_fold(
            &poly_eval,
            &folding_randomness,
            coset_offset.inverse(),
            coset_gen.inverse(),
            F::from_canonical_u64(2).inverse(),
            folding_factor,
        );

        let truth_value =
            poly.fix_variables(&folding_randomness)
                .evaluate(&expand_from_univariate(
                    root_of_unity.exp_u64(folding_factor_exp as u64 * index),
                    2,
                ));

        assert_eq!(fold_value, truth_value);
    }

    #[test]
    fn test_folding_optimised() {
        let num_variables = 5;
        let num_coeffs = 1 << num_variables;

        let domain_size = 256;
        let folding_factor = 3; // We fold in 8
        let folding_factor_exp = 1 << folding_factor;

        let poly = MultilinearExtension::from_evaluations_ext_vec(
            num_variables,
            (0..num_coeffs)
                .map(F::from_canonical_u64)
                .collect::<Vec<_>>(),
        );

        let root_of_unity = F::two_adic_generator(p3::util::log2_strict_usize(domain_size));
        let root_of_unity_inv = root_of_unity.inverse();

        let folding_randomness: Vec<_> = (0..folding_factor)
            .map(|i| F::from_canonical_u64(i as u64))
            .collect();

        // Evaluate the polynomial on the domain
        let domain_evaluations: Vec<_> = (0..domain_size)
            .map(|w| root_of_unity.exp_u64(w as u64))
            .map(|point| poly.evaluate(&expand_from_univariate(point, num_variables)))
            .collect();

        let unprocessed = stack_evaluations(domain_evaluations, folding_factor);

        let processed = restructure_evaluations(
            unprocessed.clone(),
            crate::parameters::FoldType::ProverHelps,
            root_of_unity_inv,
            folding_factor,
        );

        let num = domain_size / folding_factor_exp;
        let coset_gen_inv = root_of_unity_inv.exp_u64(num as u64);

        for index in 0..num {
            let offset_inv = root_of_unity_inv.exp_u64(index as u64);
            let span = (index * folding_factor_exp)..((index + 1) * folding_factor_exp);

            let answer_unprocessed = compute_fold(
                &unprocessed[span.clone()],
                &folding_randomness,
                offset_inv,
                coset_gen_inv,
                F::from_canonical_u64(2).inverse(),
                folding_factor,
            );

            let mut processed_evals = processed[span.clone()].to_vec();
            evaluate_over_hypercube(&mut processed_evals);
            let answer_processed = MultilinearExtension::from_evaluations_ext_vec(
                p3::util::log2_strict_usize(processed_evals.len()),
                processed_evals.to_vec(),
            )
            .evaluate(&folding_randomness.clone());

            assert_eq!(answer_processed, answer_unprocessed);
        }
    }
}
