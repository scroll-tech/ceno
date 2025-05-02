use std::array;

use ff_ext::{ExtensionField, FromUniformBytes};
use itertools::{Itertools, izip};
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks as F;
use rand::thread_rng;
use subprotocols::{
    expression::{Constant, Expression, Witness},
    sumcheck::{SumcheckProof, SumcheckProverOutput},
    test_utils::{random_point, random_poly},
    utils::eq_vecs,
    zerocheck::{ZerocheckProverState, ZerocheckVerifierState},
};
use transcript::BasicTranscript;

type E = BinomialExtensionField<F, 2>;

fn run_prover<E: ExtensionField>(
    point: &[E],
    ext_mles: &mut [Vec<E>],
    expr: Expression,
    challenges: Vec<E>,
) -> SumcheckProof<E> {
    let timer = std::time::Instant::now();
    let ext_mle_refs = ext_mles.iter_mut().map(|v| v.as_mut_slice()).collect_vec();

    let mut prover_transcript = BasicTranscript::new(b"test");
    let prover = ZerocheckProverState::new(
        vec![expr],
        &[point],
        ext_mle_refs,
        vec![],
        &challenges,
        &mut prover_transcript,
    );

    let SumcheckProverOutput { proof, .. } = prover.prove();
    println!("Proving time: {:?}", timer.elapsed());
    proof
}

fn run_verifier<E: ExtensionField>(
    proof: SumcheckProof<E>,
    ans: &E,
    point: &[E],
    expr: Expression,
    challenges: Vec<E>,
) {
    let mut verifier_transcript = BasicTranscript::new(b"test");
    let verifier = ZerocheckVerifierState::new(
        vec![*ans],
        vec![expr],
        vec![],
        vec![point],
        proof,
        &challenges,
        &mut verifier_transcript,
    );

    verifier.verify().expect("verification failed");
}

fn main() {
    let num_vars = 20;
    let mut rng = thread_rng();

    // Initialize logup expression.
    let beta = Expression::Const(Constant::Challenge(0));
    let [d0, d1, n0, n1] = array::from_fn(|i| Expression::Wit(Witness::ExtPoly(i)));
    let expr = d0.clone() * d1.clone() + beta * (d0 * n1 + d1 * n0);

    // Randomly generate point and witness.
    let point = random_point(&mut rng, num_vars);

    let d0 = random_poly(&mut rng, num_vars);
    let d1 = random_poly(&mut rng, num_vars);
    let n0 = random_poly(&mut rng, num_vars);
    let n1 = random_poly(&mut rng, num_vars);
    let mut ext_mles = [d0.clone(), d1.clone(), n0.clone(), n1.clone()];

    let challenges = vec![E::random(&mut rng)];

    let proof = run_prover(&point, &mut ext_mles, expr.clone(), challenges.clone());

    let eqs = eq_vecs([point.as_slice()].into_iter(), &[E::ONE]);

    let ans: E = izip!(&eqs[0], &d0, &d1, &n0, &n1)
        .map(|(eq, d0, d1, n0, n1)| *eq * (*d0 * *d1 + challenges[0] * (*d0 * *n1 + *d1 * *n0)))
        .sum();

    run_verifier(proof, &ans, &point, expr, challenges);
}
