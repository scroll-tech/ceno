//! HyperPlonk-style multi-point to single-point opening reduction.
//!
//! Given N = 2^k polynomials f_0, ..., f_{N-1}, each with the same number of
//! variables n, together with opening claims f_i(z_i) = y_i at (possibly
//! distinct) points z_i, this module reduces the check of all N claims to
//! opening every f_i at a single point alpha_2. The reduction follows
//! HyperPlonk Section 3.8 (https://eprint.iacr.org/2022/1355).
//!
//! Protocol sketch:
//! 1. Verifier samples t in E^k via transcript.
//! 2. Initial claim s = sum_i eq(t, i) * y_i.
//! 3. Define g(i, b) = eq(t, i) * f_i(b) and h(i, b) = eq(z_i, b) over
//!    B_{k+n}. Then s = sum_{i,b} g(i,b) * h(i,b).
//! 4. Run a (k+n)-round sumcheck on g * h. It yields a random point
//!    (alpha_1, alpha_2) and the claimed product G(alpha_1, alpha_2) *
//!    H(alpha_1, alpha_2).
//! 5. The verifier computes H(alpha_1, alpha_2) = sum_i eq(alpha_1, i) *
//!    eq(alpha_2, z_i) directly. Given f_i(alpha_2) values from the prover,
//!    it computes G(alpha_1, alpha_2) = sum_i eq(alpha_1, i) * eq(t, i) *
//!    f_i(alpha_2) and checks G * H against the sumcheck claim.
//!
//! This keeps every f_i opening at the shared point alpha_2, so downstream
//! PCS opening only needs a single-point batch opening.

use either::Either;
use ff_ext::ExtensionField;
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    virtual_poly::{build_eq_x_r_vec, eq_eval},
    virtual_polys::VirtualPolynomialsBuilder,
};
use std::marker::PhantomData;
use sumcheck::{
    structs::{IOPProof, IOPProverState, IOPVerifierState, SumCheckSubClaim},
    util::optimal_sumcheck_threads,
};
use transcript::Transcript;

use crate::error::ZKVMError;

/// Proof produced by [`prove_open_reduction`].
#[derive(Clone, Debug)]
pub struct OpenReductionProof<E: ExtensionField> {
    /// Sumcheck proof for sum_{i,b} g(i,b) * h(i,b) = s.
    pub sumcheck_proof: IOPProof<E>,
    /// Evaluations f_i(alpha_2) for each input polynomial, in input order.
    pub f_evals_at_alpha2: Vec<E>,
}

/// Claim reduced to a single opening point. Returned by both prover and
/// verifier after the reduction runs.
#[derive(Clone, Debug)]
pub struct ReducedClaim<E: ExtensionField> {
    /// The shared point alpha_2 at which every input polynomial is now opened.
    pub alpha2: Vec<E>,
    /// Evaluations f_i(alpha_2) in input order.
    pub evals: Vec<E>,
}

/// Prove the multi-point reduction.
///
/// `polys[i]` is f_i with `num_vars == n_vars` for every i. `points[i]` is
/// z_i, also of length `n_vars`. `evals[i]` is the claimed value y_i =
/// f_i(z_i). The number of polynomials must be a power of two; callers
/// padding shorter batches are responsible for supplying zero polynomials
/// with matching zero claims.
///
/// Returns the sumcheck proof, the single point alpha_2 at which all f_i
/// are now opened, and each f_i(alpha_2) value.
pub fn prove_open_reduction<'a, E: ExtensionField>(
    polys: &[&'a MultilinearExtension<'a, E>],
    points: &[Vec<E>],
    evals: &[E],
    transcript: &mut impl Transcript<E>,
) -> Result<(OpenReductionProof<E>, ReducedClaim<E>), ZKVMError> {
    let n_polys = polys.len();
    assert!(
        n_polys.is_power_of_two(),
        "number of polynomials must be a power of two (pad with zero polys)"
    );
    assert_eq!(points.len(), n_polys, "points length mismatch");
    assert_eq!(evals.len(), n_polys, "evals length mismatch");

    let n_vars = polys[0].num_vars();
    assert!(
        polys.iter().all(|p| p.num_vars() == n_vars),
        "all polynomials must have the same number of variables"
    );
    assert!(
        points.iter().all(|p| p.len() == n_vars),
        "all points must have length num_vars"
    );

    let k = n_polys.trailing_zeros() as usize; // log2(N)
    let total_vars = k + n_vars;

    // Bind all opening claims (points + values) into the transcript before
    // sampling challenges, so that t depends on the statement being proved.
    for z_i in points {
        transcript.append_field_element_exts(z_i);
    }
    transcript.append_field_element_exts(evals);

    // Sample t in E^k.
    let t = transcript.sample_and_append_vec(b"open_reduction_t", k);

    // Build G and H as 2^{k+n}-sized MLEs. Indexing convention: flat index
    // `i * 2^n + b` corresponds to (i, b) with i in B_k, b in B_n.
    let eq_t = build_eq_x_r_vec(&t);
    let n_base = 1usize << n_vars;

    let g_evals: Vec<E> = (0..n_polys)
        .flat_map(|i| {
            let scale = eq_t[i];
            let poly = polys[i];
            (0..n_base)
                .map(move |b| scale * poly_eval_at_index(poly, b))
                .collect::<Vec<_>>()
        })
        .collect();

    let h_evals: Vec<E> = (0..n_polys)
        .flat_map(|i| build_eq_x_r_vec(&points[i]))
        .collect();

    debug_assert_eq!(g_evals.len(), 1 << total_vars);
    debug_assert_eq!(h_evals.len(), 1 << total_vars);

    let mut g_mle: MultilinearExtension<E> = g_evals.into_mle();
    let mut h_mle: MultilinearExtension<E> = h_evals.into_mle();

    let num_threads = optimal_sumcheck_threads(total_vars);
    let mut builder = VirtualPolynomialsBuilder::new(num_threads, total_vars);
    let g_expr = builder.lift(Either::Right(&mut g_mle));
    let h_expr = builder.lift(Either::Right(&mut h_mle));
    let product_expr = g_expr * h_expr;

    let virtual_polys = builder.to_virtual_polys(&[product_expr], &[]);
    let (sumcheck_proof, prover_state) = IOPProverState::prove(virtual_polys, transcript);

    // Extract random challenges from the sumcheck state. In our flat
    // indexing G[i*2^n + b] the low n bits encode b (f_i's variables) and
    // the high k bits encode i (the selector). Sumcheck processes variable
    // 0 first, so challenges[..n] corresponds to b (= alpha_2) and
    // challenges[n..] corresponds to i (= alpha_1).
    let challenges = prover_state.collect_raw_challenges();
    assert_eq!(challenges.len(), total_vars);
    let alpha2 = challenges[..n_vars].to_vec();

    // Compute f_i(alpha_2) for each i. The verifier will use these to
    // reconstruct G(alpha_1, alpha_2); the H side is verifier-local.
    let f_evals_at_alpha2: Vec<E> = polys.iter().map(|poly| poly.evaluate(&alpha2)).collect();

    // Bind the prover-supplied openings into the transcript before any
    // downstream protocol step derives further randomness.
    transcript.append_field_element_exts(&f_evals_at_alpha2);

    Ok((
        OpenReductionProof {
            sumcheck_proof,
            f_evals_at_alpha2: f_evals_at_alpha2.clone(),
        },
        ReducedClaim {
            alpha2,
            evals: f_evals_at_alpha2,
        },
    ))
}

/// Verify the multi-point reduction. Returns the reduced single-point
/// claim that downstream PCS verification must check: every f_i opens to
/// `evals[i]` at `alpha2`.
pub fn verify_open_reduction<E: ExtensionField>(
    points: &[Vec<E>],
    evals: &[E],
    n_vars: usize,
    proof: &OpenReductionProof<E>,
    transcript: &mut impl Transcript<E>,
) -> Result<ReducedClaim<E>, ZKVMError> {
    let n_polys = points.len();
    assert!(
        n_polys.is_power_of_two(),
        "number of polynomials must be a power of two"
    );
    assert_eq!(evals.len(), n_polys, "evals length mismatch");
    assert_eq!(
        proof.f_evals_at_alpha2.len(),
        n_polys,
        "opening count mismatch"
    );
    assert!(
        points.iter().all(|p| p.len() == n_vars),
        "all points must have length num_vars"
    );

    let k = n_polys.trailing_zeros() as usize;
    let total_vars = k + n_vars;

    // Mirror prover: absorb opening claims into the transcript before
    // sampling t.
    for z_i in points {
        transcript.append_field_element_exts(z_i);
    }
    transcript.append_field_element_exts(evals);
    let t = transcript.sample_and_append_vec(b"open_reduction_t", k);

    // Initial sumcheck claim s = sum_i eq(t, i) * y_i.
    let eq_t = build_eq_x_r_vec(&t);
    let initial_claim: E = eq_t
        .iter()
        .zip(evals.iter())
        .map(|(e, y)| *e * *y)
        .sum();

    // Verify the sumcheck. The returned subclaim has the random point
    // (alpha_1, alpha_2) and the expected product evaluation.
    let SumCheckSubClaim {
        point: challenge_point,
        expected_evaluation,
    } = IOPVerifierState::verify(
        initial_claim,
        &proof.sumcheck_proof,
        &multilinear_extensions::virtual_poly::VPAuxInfo {
            max_degree: 2, // G * H is degree-2
            max_num_variables: total_vars,
            phantom: PhantomData,
        },
        transcript,
    );

    let raw_challenges: Vec<E> = challenge_point.into_iter().map(|c| c.elements).collect();
    assert_eq!(raw_challenges.len(), total_vars);
    // See prover for the variable ordering rationale.
    let alpha2 = raw_challenges[..n_vars].to_vec();
    let alpha1 = &raw_challenges[n_vars..];

    // Verifier-computed H(alpha_1, alpha_2) = sum_i eq(alpha_1, i) *
    // eq(alpha_2, z_i).
    let eq_alpha1 = build_eq_x_r_vec(alpha1);
    let h_at_alpha: E = points
        .iter()
        .enumerate()
        .map(|(i, z_i)| eq_alpha1[i] * eq_eval(&alpha2, z_i))
        .sum();

    // Prover-derived G(alpha_1, alpha_2) = sum_i eq(alpha_1, i) *
    // eq(t, i) * f_i(alpha_2).
    let g_at_alpha: E = (0..n_polys)
        .map(|i| eq_alpha1[i] * eq_t[i] * proof.f_evals_at_alpha2[i])
        .sum();

    let reconstructed = g_at_alpha * h_at_alpha;
    if reconstructed != expected_evaluation {
        return Err(ZKVMError::VerifyError(
            format!(
                "open reduction sumcheck mismatch: got {:?} expected {:?}",
                reconstructed, expected_evaluation
            )
            .into(),
        ));
    }

    // Mirror prover's transcript bind of provided openings so downstream
    // randomness derivation stays aligned.
    transcript.append_field_element_exts(&proof.f_evals_at_alpha2);

    Ok(ReducedClaim {
        alpha2,
        evals: proof.f_evals_at_alpha2.clone(),
    })
}

// Access the value of an MLE at a boolean-hypercube index without going
// through `evaluate`. This reaches through the underlying FieldType to pull
// out the b-th coefficient as an extension-field element.
fn poly_eval_at_index<E: ExtensionField>(
    poly: &MultilinearExtension<'_, E>,
    index: usize,
) -> E {
    use multilinear_extensions::mle::FieldType;
    match poly.evaluations() {
        FieldType::Base(v) => E::from(v[index]),
        FieldType::Ext(v) => v[index],
        FieldType::Unreachable => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::mle::IntoMLE;
    use p3::field::FieldAlgebra;
    use transcript::BasicTranscript;

    type E = GoldilocksExt2;

    fn random_poly(num_vars: usize, seed: u64) -> Vec<E> {
        // deterministic pseudo-random coefficients for testing
        (0..(1 << num_vars))
            .map(|i| E::from_canonical_u64((i as u64).wrapping_mul(seed).wrapping_add(seed)))
            .collect()
    }

    #[test]
    fn reduction_round_trip_n1_k0() {
        // Trivial single-polynomial case (k = 0, so just pass-through).
        let n_vars = 3;
        let evals = random_poly(n_vars, 7);
        let mle: MultilinearExtension<E> = evals.clone().into_mle();
        let z = vec![E::from_canonical_u64(5); n_vars];
        let y = mle.evaluate(&z);

        let mut p_tr = BasicTranscript::<E>::new(b"test");
        let (proof, p_claim) =
            prove_open_reduction(&[&mle], &[z.clone()], &[y], &mut p_tr).unwrap();

        let mut v_tr = BasicTranscript::<E>::new(b"test");
        let v_claim =
            verify_open_reduction(&[z.clone()], &[y], n_vars, &proof, &mut v_tr).unwrap();

        assert_eq!(p_claim.alpha2, v_claim.alpha2);
        assert_eq!(p_claim.evals, v_claim.evals);
        // sanity: claimed opening matches actual polynomial evaluation
        assert_eq!(v_claim.evals[0], mle.evaluate(&v_claim.alpha2));
    }

    #[test]
    fn reduction_round_trip_n4_k2() {
        // Four polynomials, three variables each, all distinct points.
        let n_vars = 3;
        let seeds = [11u64, 13, 17, 19];
        let poly_evals: Vec<Vec<E>> = seeds.iter().map(|s| random_poly(n_vars, *s)).collect();
        let mles: Vec<MultilinearExtension<E>> =
            poly_evals.iter().cloned().map(|v| v.into_mle()).collect();

        let points: Vec<Vec<E>> = (0..4)
            .map(|i| {
                (0..n_vars)
                    .map(|j| E::from_canonical_u64((i * 7 + j * 3 + 1) as u64))
                    .collect()
            })
            .collect();
        let claimed_evals: Vec<E> = mles
            .iter()
            .zip(points.iter())
            .map(|(m, p)| m.evaluate(p))
            .collect();

        let mle_refs: Vec<&MultilinearExtension<E>> = mles.iter().collect();

        let mut p_tr = BasicTranscript::<E>::new(b"test");
        let (proof, p_claim) =
            prove_open_reduction(&mle_refs, &points, &claimed_evals, &mut p_tr).unwrap();

        let mut v_tr = BasicTranscript::<E>::new(b"test");
        let v_claim =
            verify_open_reduction(&points, &claimed_evals, n_vars, &proof, &mut v_tr).unwrap();

        assert_eq!(p_claim.alpha2, v_claim.alpha2);
        assert_eq!(p_claim.evals, v_claim.evals);
        for (mle, eval) in mles.iter().zip(&v_claim.evals) {
            assert_eq!(*eval, mle.evaluate(&v_claim.alpha2));
        }
    }

    #[test]
    fn reduction_round_trip_n8_k3() {
        // Eight polynomials of five variables each, distinct points.
        let n_vars = 5;
        let n_polys = 8;
        let poly_evals: Vec<Vec<E>> = (0..n_polys)
            .map(|i| random_poly(n_vars, (i as u64 + 1) * 31))
            .collect();
        let mles: Vec<MultilinearExtension<E>> =
            poly_evals.iter().cloned().map(|v| v.into_mle()).collect();

        let points: Vec<Vec<E>> = (0..n_polys)
            .map(|i| {
                (0..n_vars)
                    .map(|j| E::from_canonical_u64((i as u64 * 13 + j as u64 * 5 + 2) as u64))
                    .collect()
            })
            .collect();
        let claimed_evals: Vec<E> = mles
            .iter()
            .zip(points.iter())
            .map(|(m, p)| m.evaluate(p))
            .collect();

        let mle_refs: Vec<&MultilinearExtension<E>> = mles.iter().collect();

        let mut p_tr = BasicTranscript::<E>::new(b"stress");
        let (proof, _) =
            prove_open_reduction(&mle_refs, &points, &claimed_evals, &mut p_tr).unwrap();

        let mut v_tr = BasicTranscript::<E>::new(b"stress");
        let v_claim =
            verify_open_reduction(&points, &claimed_evals, n_vars, &proof, &mut v_tr).unwrap();

        for (mle, eval) in mles.iter().zip(&v_claim.evals) {
            assert_eq!(*eval, mle.evaluate(&v_claim.alpha2));
        }
    }

    #[test]
    fn reduction_shared_point() {
        // All polys opened at the same point - degenerate multi-point case.
        let n_vars = 4;
        let n_polys = 4;
        let poly_evals: Vec<Vec<E>> = (0..n_polys)
            .map(|i| random_poly(n_vars, (i as u64 + 1) * 41))
            .collect();
        let mles: Vec<MultilinearExtension<E>> =
            poly_evals.iter().cloned().map(|v| v.into_mle()).collect();

        let shared: Vec<E> = (0..n_vars).map(|j| E::from_canonical_u64(j as u64 + 100)).collect();
        let points: Vec<Vec<E>> = vec![shared.clone(); n_polys];
        let claimed_evals: Vec<E> = mles.iter().map(|m| m.evaluate(&shared)).collect();

        let mle_refs: Vec<&MultilinearExtension<E>> = mles.iter().collect();

        let mut p_tr = BasicTranscript::<E>::new(b"shared");
        let (proof, _) =
            prove_open_reduction(&mle_refs, &points, &claimed_evals, &mut p_tr).unwrap();

        let mut v_tr = BasicTranscript::<E>::new(b"shared");
        let v_claim =
            verify_open_reduction(&points, &claimed_evals, n_vars, &proof, &mut v_tr).unwrap();

        for (mle, eval) in mles.iter().zip(&v_claim.evals) {
            assert_eq!(*eval, mle.evaluate(&v_claim.alpha2));
        }
    }

    #[test]
    fn reduction_detects_wrong_claim() {
        // If the prover lies about y_0, verification must fail.
        let n_vars = 2;
        let poly_evals = random_poly(n_vars, 23);
        let mle: MultilinearExtension<E> = poly_evals.into_mle();

        // N = 2 polys: two copies of the same poly but claims differ.
        let z0: Vec<E> = (0..n_vars).map(|i| E::from_canonical_u64(i as u64 + 2)).collect();
        let z1: Vec<E> = (0..n_vars).map(|i| E::from_canonical_u64(i as u64 + 9)).collect();
        let y0 = mle.evaluate(&z0);
        let y1 = mle.evaluate(&z1);

        // Corrupt y0.
        let bad_y0 = y0 + E::ONE;

        let mut p_tr = BasicTranscript::<E>::new(b"test");
        // Prover cooperates (doesn't know y0 is wrong), but will produce
        // inconsistent openings.
        let result = prove_open_reduction(
            &[&mle, &mle],
            &[z0.clone(), z1.clone()],
            &[bad_y0, y1],
            &mut p_tr,
        );
        assert!(result.is_ok(), "prover doesn't check semantics");
        let (proof, _) = result.unwrap();

        let mut v_tr = BasicTranscript::<E>::new(b"test");
        let verify = verify_open_reduction(
            &[z0, z1],
            &[bad_y0, y1],
            n_vars,
            &proof,
            &mut v_tr,
        );
        assert!(verify.is_err(), "lying claim must be rejected");
    }
}
