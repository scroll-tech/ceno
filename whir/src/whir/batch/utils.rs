use crate::{
    error::Error,
    ntt::{transpose, transpose_test},
    utils::expand_randomness,
};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;
use transcript::Transcript;

pub fn stack_evaluations<E: ExtensionField>(
    mut evals: Vec<E>,
    row_size: usize,
    buffer: &mut [E],
) -> Vec<E> {
    assert!(evals.len() % row_size == 0);
    let size_of_new_domain = evals.len() / row_size;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose_test(&mut evals, row_size, size_of_new_domain, buffer);
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

// generate a random vector for batching open
pub fn generate_random_vector_batch_open<E: ExtensionField, T: Transcript<E>>(
    transcript: &mut T,
    size: usize,
) -> Result<Vec<E>, Error> {
    if size == 1 {
        return Ok(vec![E::ONE]);
    }
    let gamma = transcript.sample_and_append_challenge(b"gamma").elements;
    let res = expand_randomness(gamma, size);
    Ok(res)
}

// generate a random vector for batching verify
pub fn generate_random_vector_batch_verify<E: ExtensionField, T: Transcript<E>>(
    transcript: &mut T,
    size: usize,
) -> Result<Vec<E>, Error> {
    if size == 1 {
        return Ok(vec![E::ONE]);
    }
    let gamma = transcript.sample_and_append_challenge(b"gamma").elements;
    let res = expand_randomness(gamma, size);
    Ok(res)
}

pub fn field_type_index_ext<E: ExtensionField>(poly: &FieldType<E>, index: usize) -> E {
    match &poly {
        FieldType::Ext(coeffs) => coeffs[index],
        FieldType::Base(coeffs) => E::from(coeffs[index]),
        _ => unreachable!(),
    }
}
