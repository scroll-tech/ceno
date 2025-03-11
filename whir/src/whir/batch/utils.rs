use crate::{
    crypto::MerkleConfig as Config,
    end_timer,
    error::Error,
    ntt::{transpose, transpose_test},
    start_timer,
    utils::expand_randomness,
};
use ff_ext::ExtensionField;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use transcript::Transcript;

pub fn stack_evaluations<E: ExtensionField>(
    mut evals: Vec<E>,
    folding_factor: usize,
    buffer: &mut [E],
) -> Vec<E> {
    assert!(evals.len() % folding_factor == 0);
    let size_of_new_domain = evals.len() / folding_factor;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose_test(&mut evals, folding_factor, size_of_new_domain, buffer);
    evals
}

/// Takes the vector of evaluations (assume that evals[i] = E(omega^i))
/// and folds them into a vector of such that folded_evals[i] = [E(omega^(i + k * j)) for j in 0..folding_factor]
/// This function will mutate the function without return
pub fn stack_evaluations_mut<E: ExtensionField>(evals: &mut [E], folding_factor: usize) {
    let folding_factor_exp = 1 << folding_factor;
    assert!(evals.len() % folding_factor_exp == 0);
    let size_of_new_domain = evals.len() / folding_factor_exp;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose(evals, folding_factor_exp, size_of_new_domain);
}

/// Takes a vector of matrix and stacking them horizontally
/// Use in-place matrix transposes to avoid data copy
/// each matrix has domain_size elements
/// each matrix has shape (*, 1<<folding_factor)
pub fn horizontal_stacking<E: ExtensionField>(
    evals: Vec<E>,
    domain_size: usize,
    folding_factor: usize,
    buffer: &mut [E],
) -> Vec<E> {
    let fold_size = 1 << folding_factor;
    let num_polys: usize = evals.len() / domain_size;

    let stack_evaluation_timer = start_timer!(|| "Stack Evaluation");
    let mut evals = stack_evaluations(evals, num_polys, buffer);
    end_timer!(stack_evaluation_timer);
    #[cfg(not(feature = "parallel"))]
    let stacked_evals = evals.chunks_exact_mut(fold_size * num_polys);
    #[cfg(feature = "parallel")]
    let stacked_evals = evals.par_chunks_exact_mut(fold_size * num_polys);
    let stack_evaluation_mut_timer = start_timer!(|| "Stack Evaluation Mut");
    stacked_evals.for_each(|eval| stack_evaluations_mut(eval, folding_factor));
    end_timer!(stack_evaluation_mut_timer);
    evals
}

// generate a random vector for batching open
pub fn generate_random_vector_batch_open<E: ExtensionField, T: Transcript<E>, MerkleConfig>(
    transcript: &mut T,
    size: usize,
) -> Result<Vec<E>, Error>
where
    E: ExtensionField,
    MerkleConfig: Config<E>,
{
    if size == 1 {
        return Ok(vec![E::one()]);
    }
    let [gamma] = transcript.challenge_scalars()?;
    let res = expand_randomness(gamma, size);
    Ok(res)
}

// generate a random vector for batching verify
pub fn generate_random_vector_batch_verify<E: ExtensionField, T: Transcript<E>, MerkleConfig>(
    arthur: &mut T,
    size: usize,
) -> Result<Vec<E>, Error>
where
    E: ExtensionField,
    MerkleConfig: Config<E>,
{
    if size == 1 {
        return Ok(vec![E::one()]);
    }
    let [gamma] = arthur.challenge_scalars()?;
    let res = expand_randomness(gamma, size);
    Ok(res)
}
