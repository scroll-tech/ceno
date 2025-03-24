use crate::{
    structs::{IOPProverState, IOPVerifierState},
    util::interpolate_uni_poly,
};
use ark_std::{rand::RngCore, test_rng};
use ff_ext::{ExtensionField, FromUniformBytes, GoldilocksExt2, PoseidonField};
use multilinear_extensions::{
    util::max_usable_threads,
    virtual_poly::{VPAuxInfo, VirtualPolynomial},
    virtual_polys::VirtualPolynomials,
};
use p3::field::PrimeCharacteristicRing;
use transcript::{BasicTranscript, Transcript};

#[test]
fn test_sumcheck_with_different_degree() {
    // test polynomial mixed with different num_var
    let nv = vec![3, 4, 5];
    let num_polys = nv.len();
    for num_threads in 1..num_polys.min(max_usable_threads()) {
        test_sumcheck_with_different_degree_helper::<GoldilocksExt2>(num_threads, &nv);
    }
}

fn test_sumcheck_with_different_degree_helper<E: ExtensionField>(num_threads: usize, nv: &[usize])
where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let mut rng = test_rng();
    let degree = 2;
    let num_multiplicands_range = (degree, degree + 1);
    let num_products = 1;
    let mut transcript = BasicTranscript::<E>::new(b"test");

    let max_num_variables = *nv.iter().max().unwrap();
    let poly = VirtualPolynomials::new(num_threads, max_num_variables);

    let input_polys = nv
        .iter()
        .map(|nv| {
            VirtualPolynomial::<E>::random(*nv, num_multiplicands_range, num_products, &mut rng)
        })
        .collect::<Vec<_>>();

    let (poly, asserted_sum) =
        input_polys
            .iter()
            .fold((poly, E::ZERO), |(mut poly, sum), (new_poly, new_sum)| {
                poly.merge(new_poly);
                (
                    poly,
                    sum + E::from_u64(
                        1 << (max_num_variables - new_poly.aux_info.max_num_variables),
                    ) * *new_sum,
                )
            });

    let batch_poly = poly.get_batched_polys();
    let (proof, _) =
        IOPProverState::<E>::prove_batch_polys(num_threads, batch_poly.clone(), &mut transcript);
    let mut transcript = BasicTranscript::new(b"test");
    let subclaim = IOPVerifierState::<E>::verify(
        asserted_sum,
        &proof,
        &VPAuxInfo {
            max_degree: 2,
            max_num_variables,
            ..Default::default()
        },
        &mut transcript,
    );
    let r = subclaim
        .point
        .iter()
        .map(|c| c.elements)
        .collect::<Vec<_>>();
    assert_eq!(r.len(), max_num_variables);
    // r are right alignment
    assert!(
        input_polys
            .iter()
            .map(|(poly, _)| { poly.evaluate(&r[r.len() - poly.aux_info.max_num_variables..]) })
            .sum::<E>()
            == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_sumcheck<E: ExtensionField>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
) where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let mut rng = test_rng();
    let mut transcript = BasicTranscript::new(b"test");

    let (poly, asserted_sum) =
        VirtualPolynomial::<E>::random(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.aux_info.clone();
    #[allow(deprecated)]
    let (proof, _) = IOPProverState::<E>::prove_parallel(poly.clone(), &mut transcript);

    let mut transcript = BasicTranscript::new(b"test");
    let subclaim = IOPVerifierState::<E>::verify(asserted_sum, &proof, &poly_info, &mut transcript);
    assert!(
        poly.evaluate(
            subclaim
                .point
                .iter()
                .map(|c| c.elements)
                .collect::<Vec<_>>()
                .as_ref()
        ) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_sumcheck_internal<E: ExtensionField>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
) where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let mut rng = test_rng();
    let (poly, asserted_sum) =
        VirtualPolynomial::<E>::random(nv, num_multiplicands_range, num_products, &mut rng);
    let (poly_info, num_variables) = (poly.aux_info.clone(), poly.aux_info.max_num_variables);
    #[allow(deprecated)]
    let mut prover_state = IOPProverState::prover_init_parallel(poly.clone());
    let mut verifier_state = IOPVerifierState::verifier_init(&poly_info);
    let mut challenge = None;

    let mut transcript = BasicTranscript::new(b"test");

    transcript.append_message(b"initializing transcript for testing");

    for _ in 0..num_variables {
        let prover_message =
            IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);

        challenge = Some(IOPVerifierState::verify_round_and_update_state(
            &mut verifier_state,
            &prover_message,
            &mut transcript,
        ));
    }
    // pushing the last challenge point to the state
    if let Some(p) = challenge {
        prover_state.challenges.push(p);
        // fix last challenge to collect final evaluation
        prover_state.fix_var(p.elements);
    };
    let subclaim = IOPVerifierState::check_and_generate_subclaim(&verifier_state, &asserted_sum);
    assert!(
        poly.evaluate(
            subclaim
                .point
                .iter()
                .map(|c| c.elements)
                .collect::<Vec<_>>()
                .as_ref()
        ) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

#[test]
fn test_trivial_polynomial() {
    test_trivial_polynomial_helper::<GoldilocksExt2>();
}

fn test_trivial_polynomial_helper<E: ExtensionField>()
where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let nv = 1;
    let num_multiplicands_range = (3, 5);
    let num_products = 5;

    test_sumcheck::<E>(nv, num_multiplicands_range, num_products);
    test_sumcheck_internal::<E>(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_normal_polynomial() {
    test_normal_polynomial_helper::<GoldilocksExt2>();
}

fn test_normal_polynomial_helper<E: ExtensionField>()
where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let nv = 12;
    let num_multiplicands_range = (3, 5);
    let num_products = 5;

    test_sumcheck::<E>(nv, num_multiplicands_range, num_products);
    test_sumcheck_internal::<E>(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_extract_sum() {
    test_extract_sum_helper::<GoldilocksExt2>();
}

fn test_extract_sum_helper<E: ExtensionField>()
where
    [(); E::BaseField::PERM_WIDTH + E::BaseField::RATE]:,
{
    let mut rng = test_rng();
    let mut transcript = BasicTranscript::new(b"test");
    let (poly, asserted_sum) = VirtualPolynomial::<E>::random(8, (2, 3), 3, &mut rng);
    #[allow(deprecated)]
    let (proof, _) = IOPProverState::<E>::prove_parallel(poly, &mut transcript);
    assert_eq!(proof.extract_sum(), asserted_sum);
}

struct DensePolynomial(Vec<GoldilocksExt2>);

impl DensePolynomial {
    fn rand(degree: usize, mut rng: &mut impl RngCore) -> Self {
        Self(
            (0..degree)
                .map(|_| GoldilocksExt2::random(&mut rng))
                .collect(),
        )
    }

    fn evaluate(&self, p: &GoldilocksExt2) -> GoldilocksExt2 {
        let mut powers_of_p = *p;
        let mut res = self.0[0];
        for &c in self.0.iter().skip(1) {
            res += powers_of_p * c;
            powers_of_p *= *p;
        }
        res
    }
}

#[test]
fn test_interpolation() {
    let mut prng = ark_std::test_rng();

    // test a polynomial with 20 known points, i.e., with degree 19
    let poly = DensePolynomial::rand(20 - 1, &mut prng);
    let evals = (0..20)
        .map(|i| poly.evaluate(&GoldilocksExt2::from_u64(i as u64)))
        .collect::<Vec<GoldilocksExt2>>();
    let query = GoldilocksExt2::random(&mut prng);

    assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));

    // test a polynomial with 33 known points, i.e., with degree 32
    let poly = DensePolynomial::rand(33 - 1, &mut prng);
    let evals = (0..33)
        .map(|i| poly.evaluate(&GoldilocksExt2::from_u64(i as u64)))
        .collect::<Vec<GoldilocksExt2>>();
    let query = GoldilocksExt2::random(&mut prng);

    assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));

    // test a polynomial with 64 known points, i.e., with degree 63
    let poly = DensePolynomial::rand(64 - 1, &mut prng);
    let evals = (0..64)
        .map(|i| poly.evaluate(&GoldilocksExt2::from_u64(i as u64)))
        .collect::<Vec<GoldilocksExt2>>();
    let query = GoldilocksExt2::random(&mut prng);

    assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));
}
