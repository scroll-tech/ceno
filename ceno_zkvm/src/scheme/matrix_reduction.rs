use ff_ext::ExtensionField;
use gkr_iop::hal::MultilinearPolynomial;
use multilinear_extensions::{
    mle::Point,
    virtual_poly::{VPAuxInfo, eq_eval},
};
use sumcheck::structs::{IOPProof, IOPProverMessage, IOPVerifierState};
use transcript::Transcript;

use crate::{error::ZKVMError, scheme::MatrixReductionProof};

pub const MATRIX_REDUCTION_DEGREE: usize = 3;
pub const MATRIX_REDUCTION_SCALE: u64 = 1 << 16;
pub const MATRIX_REDUCTION_COLUMNS: [usize; 4] = [0, 3, 6, 9];

#[derive(Clone, Debug)]
pub struct MatrixOpeningClaims<E: ExtensionField> {
    pub points: [Point<E>; 3],
    pub expected_evals: [E; 4],
}

fn invalid(message: impl Into<Box<str>>) -> ZKVMError {
    ZKVMError::InvalidProof(message.into())
}

fn checked_shape<E: ExtensionField, P: MultilinearPolynomial<E>>(
    witness: &[std::sync::Arc<P>],
    num_instances: usize,
    columns: [usize; 4],
) -> Result<usize, ZKVMError> {
    if num_instances == 0 || num_instances % 4 != 0 {
        return Err(ZKVMError::InvalidWitness(
            format!("matrix Core row count {num_instances} is not complete 4-row sections").into(),
        ));
    }
    let polys = columns.map(|column| {
        witness.get(column).ok_or_else(|| {
            ZKVMError::InvalidWitness(
                format!("matrix Core witness column {column} is missing").into(),
            )
        })
    });
    let [a, w, q, r] = polys.map(|poly| poly.map(std::sync::Arc::as_ref));
    let [a, w, q, r] = [a?, w?, q?, r?];
    let num_vars = a.num_vars();
    let expected_num_vars = num_instances.next_power_of_two().ilog2() as usize;
    if num_vars != expected_num_vars
        || [w.num_vars(), q.num_vars(), r.num_vars()] != [expected_num_vars; 3]
    {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "matrix Core A/W/Q/R polynomial variable counts [{num_vars}, {}, {}, {}] \
                 do not match the expected {expected_num_vars}",
                w.num_vars(),
                q.num_vars(),
                r.num_vars()
            )
            .into(),
        ));
    }
    Ok(num_vars - 2)
}

fn sum_over_remaining<E: ExtensionField, P: MultilinearPolynomial<E>>(
    a: &P,
    w: &P,
    r_n: E,
    r_m: E,
    r_section: &[E],
    fixed: &[E],
    round_value: E,
    remaining: usize,
) -> E {
    (0..(1usize << remaining))
        .map(|assignment| {
            let mut sum_point = Vec::with_capacity(fixed.len() + 1 + remaining);
            sum_point.extend_from_slice(fixed);
            sum_point.push(round_value);
            sum_point
                .extend((0..remaining).map(|bit| E::from_bool(((assignment >> bit) & 1) != 0)));
            let r_k = sum_point[0];
            let section = &sum_point[1..];
            let mut a_point = Vec::with_capacity(2 + section.len());
            a_point.extend([r_k, r_m]);
            a_point.extend_from_slice(section);
            let mut w_point = Vec::with_capacity(2 + section.len());
            w_point.extend([r_n, r_k]);
            w_point.extend_from_slice(section);
            a.eval(a_point) * w.eval(w_point) * eq_eval(r_section, section)
        })
        .sum()
}

pub fn prove<E: ExtensionField, P: MultilinearPolynomial<E>>(
    witness: &[std::sync::Arc<P>],
    num_instances: usize,
    columns: [usize; 4],
    transcript: &mut impl Transcript<E>,
) -> Result<(MatrixReductionProof<E>, MatrixOpeningClaims<E>), ZKVMError> {
    let section_vars = checked_shape(witness, num_instances, columns)?;
    let [a_col, w_col, q_col, r_col] = columns;
    let a = witness[a_col].as_ref();
    let w = witness[w_col].as_ref();
    let q = witness[q_col].as_ref();
    let remainder = witness[r_col].as_ref();

    let output_point =
        transcript.sample_and_append_vec(b"tensor matrix output point", 2 + section_vars);
    let r_n = output_point[0];
    let r_m = output_point[1];
    let r_section = &output_point[2..];
    let q_eval = q.eval(output_point.clone());
    let r_eval = remainder.eval(output_point.clone());
    transcript.append_field_element_ext(&q_eval);
    transcript.append_field_element_ext(&r_eval);

    let num_sumcheck_vars = 1 + section_vars;
    transcript.append_message(&num_sumcheck_vars.to_le_bytes());
    transcript.append_message(&MATRIX_REDUCTION_DEGREE.to_le_bytes());
    let mut fixed = Vec::with_capacity(num_sumcheck_vars);
    let mut messages = Vec::with_capacity(num_sumcheck_vars);
    for round in 0..num_sumcheck_vars {
        let remaining = num_sumcheck_vars - round - 1;
        let evaluations = (1..=MATRIX_REDUCTION_DEGREE)
            .map(|value| {
                sum_over_remaining(
                    a,
                    w,
                    r_n,
                    r_m,
                    r_section,
                    &fixed,
                    E::from_usize(value),
                    remaining,
                )
            })
            .collect::<Vec<_>>();
        transcript.append_field_element_exts(&evaluations);
        messages.push(IOPProverMessage { evaluations });
        fixed.push(
            transcript
                .sample_and_append_challenge(b"Internal round")
                .elements,
        );
    }

    let r_k = fixed[0];
    let final_section = &fixed[1..];
    let mut a_point = vec![r_k, r_m];
    a_point.extend_from_slice(final_section);
    let mut w_point = vec![r_n, r_k];
    w_point.extend_from_slice(final_section);
    let a_eval = a.eval(a_point.clone());
    let w_eval = w.eval(w_point.clone());
    transcript.append_field_element_ext(&a_eval);
    transcript.append_field_element_ext(&w_eval);

    Ok((
        MatrixReductionProof {
            output_evals: [q_eval, r_eval],
            sumcheck_proof: messages,
            final_evals: [a_eval, w_eval],
        },
        MatrixOpeningClaims {
            points: [a_point, w_point, output_point],
            expected_evals: [a_eval, w_eval, q_eval, r_eval],
        },
    ))
}

pub fn verify<E: ExtensionField>(
    proof: &MatrixReductionProof<E>,
    num_instances: usize,
    transcript: &mut impl Transcript<E>,
) -> Result<MatrixOpeningClaims<E>, ZKVMError> {
    if num_instances == 0 || num_instances % 4 != 0 {
        return Err(invalid(format!(
            "matrix Core row count {num_instances} is not complete 4-row sections"
        )));
    }
    let padded_rows = num_instances.next_power_of_two();
    let total_vars = padded_rows.trailing_zeros() as usize;
    if total_vars < 2 {
        return Err(invalid("matrix Core needs at least four padded rows"));
    }
    let section_vars = total_vars - 2;
    let output_point =
        transcript.sample_and_append_vec(b"tensor matrix output point", 2 + section_vars);
    let r_n = output_point[0];
    let r_m = output_point[1];
    let r_section = &output_point[2..];
    transcript.append_field_element_ext(&proof.output_evals[0]);
    transcript.append_field_element_ext(&proof.output_evals[1]);

    let num_sumcheck_vars = 1 + section_vars;
    if proof.sumcheck_proof.len() != num_sumcheck_vars
        || proof
            .sumcheck_proof
            .iter()
            .any(|message| message.evaluations.len() != MATRIX_REDUCTION_DEGREE)
    {
        return Err(invalid(format!(
            "matrix sumcheck shape mismatch: {} rounds for {num_sumcheck_vars} variables",
            proof.sumcheck_proof.len()
        )));
    }
    let claimed_sum =
        proof.output_evals[0] * E::from_u64(MATRIX_REDUCTION_SCALE) + proof.output_evals[1];
    let subclaim = IOPVerifierState::verify(
        claimed_sum,
        &IOPProof {
            proofs: proof.sumcheck_proof.clone(),
        },
        &VPAuxInfo {
            max_degree: MATRIX_REDUCTION_DEGREE,
            max_num_variables: num_sumcheck_vars,
            phantom: std::marker::PhantomData,
        },
        transcript,
    );
    let sumcheck_point = subclaim
        .point
        .iter()
        .map(|challenge| challenge.elements)
        .collect::<Vec<_>>();
    transcript.append_field_element_ext(&proof.final_evals[0]);
    transcript.append_field_element_ext(&proof.final_evals[1]);
    let expected_final =
        proof.final_evals[0] * proof.final_evals[1] * eq_eval(r_section, &sumcheck_point[1..]);
    if subclaim.expected_evaluation != expected_final {
        return Err(invalid("matrix sumcheck final evaluation mismatch"));
    }

    let r_k = sumcheck_point[0];
    let final_section = &sumcheck_point[1..];
    let mut a_point = vec![r_k, r_m];
    a_point.extend_from_slice(final_section);
    let mut w_point = vec![r_n, r_k];
    w_point.extend_from_slice(final_section);
    Ok(MatrixOpeningClaims {
        points: [a_point, w_point, output_point],
        expected_evals: [
            proof.final_evals[0],
            proof.final_evals[1],
            proof.output_evals[0],
            proof.output_evals[1],
        ],
    })
}
