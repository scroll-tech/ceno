use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use multilinear_extensions::virtual_poly::VirtualPolynomial;
use rayon::{
    iter::IntoParallelRefMutIterator,
    prelude::{IntoParallelIterator, ParallelIterator},
};
use transcript::{Challenge, Transcript};

use crate::{
    structs::{IOPProof, IOPProverMessage, IOPProverState},
    util::{barycentric_weights, extrapolate},
};

impl<F: SmallField> IOPProverState<F> {
    /// Identical to `prove` function. With the exception that the input poly is
    /// over the base field rather than the extension field
    pub fn prove_base_poly(
        poly: VirtualPolynomial<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> (IOPProof<F>, IOPProverState<F>) {
        let ploy_ext = poly.to_ext_field::<F>();
        Self::prove(ploy_ext, transcript)
    }

    /// Given a virtual polynomial, generate an IOP proof.
    pub fn prove(
        poly: VirtualPolynomial<F>,
        transcript: &mut Transcript<F>,
    ) -> (IOPProof<F>, IOPProverState<F>) {
        let (num_variables, max_degree) = (poly.aux_info.num_variables, poly.aux_info.max_degree);
        if num_variables == 0 {
            return (IOPProof::default(), IOPProverState::default());
        }
        let start = start_timer!(|| "sum check prove");

        transcript.append_message(&num_variables.to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());

        let mut prover_state = Self::prover_init(poly);
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(num_variables);
        for _ in 0..num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);

            prover_msg
                .evaluations
                .iter()
                .for_each(|e| transcript.append_field_element(e));

            prover_msgs.push(prover_msg);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round"));
        }
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p);
            // fix last challenge to collect final evaluation
            prover_state
                .poly
                .flattened_ml_extensions
                .par_iter_mut()
                .for_each(|mle| {
                    Arc::get_mut(mle).unwrap().fix_variables(&[p.elements]);
                });
        };

        end_timer!(start);
        (
            IOPProof {
                // the point consists of the first elements in the challenge
                point: prover_state
                    .challenges
                    .iter()
                    .map(|challenge| challenge.elements)
                    .collect(),
                proofs: prover_msgs,
            },
            prover_state.into(),
        )
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub(crate) fn prover_init(polynomial: VirtualPolynomial<F>) -> Self {
        let start = start_timer!(|| "sum check prover init");
        assert_ne!(
            polynomial.aux_info.num_variables, 0,
            "Attempt to prove a constant."
        );
        end_timer!(start);

        let max_degree = polynomial.aux_info.max_degree;
        Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            poly: polynomial,
            extrapolation_aux: (1..max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect(),
        }
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    pub(crate) fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<Challenge<F>>,
    ) -> IOPProverMessage<F> {
        let start =
            start_timer!(|| format!("sum check prove {}-th round and update state", self.round));

        assert!(
            self.round < self.poly.aux_info.num_variables,
            "Prover is not active"
        );

        // let fix_argument = start_timer!(|| "fix argument");

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)
        let mut flattened_ml_extensions = self
            .poly
            .flattened_ml_extensions
            .par_iter_mut()
            .map(Arc::make_mut)
            .collect::<Vec<_>>();

        if let Some(chal) = challenge {
            assert!(self.round != 0, "first round should be prover first.");

            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            flattened_ml_extensions.par_iter_mut().for_each(|mle| {
                mle.fix_variables(&[r.elements]);
            });
        } else if self.round > 0 {
            panic!("verifier message is empty");
        }
        // end_timer!(fix_argument);

        self.round += 1;

        let mut products_sum = vec![F::ZERO; self.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        self.poly
            .products
            .iter()
            .for_each(|(coefficient, products)| {
                let mut sum = (0..1 << (self.poly.aux_info.num_variables - self.round))
                    .into_par_iter()
                    .fold(
                        || {
                            (
                                vec![(F::ZERO, F::ZERO); products.len()],
                                vec![F::ZERO; products.len() + 1],
                            )
                        },
                        |(mut buf, mut acc), b| {
                            buf.iter_mut()
                                .zip(products.iter())
                                .for_each(|((eval, step), f)| {
                                    let table = &flattened_ml_extensions[*f].evaluations;
                                    *eval = table[b << 1];
                                    *step = table[(b << 1) + 1] - table[b << 1];
                                });
                            acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                                *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| partial)
                    .reduce(
                        || vec![F::ZERO; products.len() + 1],
                        |mut sum, partial| {
                            sum.iter_mut()
                                .zip(partial.iter())
                                .for_each(|(sum, partial)| *sum += partial);
                            sum
                        },
                    );
                sum.iter_mut().for_each(|sum| *sum *= coefficient);
                let extrapolation = (0..self.poly.aux_info.max_degree - products.len())
                    .into_par_iter()
                    .map(|i| {
                        let (points, weights) = &self.extrapolation_aux[products.len() - 1];
                        let at = F::from((products.len() + 1 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
                products_sum
                    .iter_mut()
                    .zip(sum.iter().chain(extrapolation.iter()))
                    .for_each(|(products_sum, sum)| *products_sum += sum);
            });

        end_timer!(start);

        IOPProverMessage {
            evaluations: products_sum,
        }
    }

    /// collect all mle evaluation (claim) after sumcheck
    pub fn get_mle_final_evaluations(&self) -> Vec<F> {
        self.poly
            .flattened_ml_extensions
            .iter()
            .map(|mle| {
                assert!(
                    mle.evaluations.len() == 1,
                    "mle.evaluations.len() {} != 1, must be called after prove_round_and_update_state",
                    mle.evaluations.len(),
                );
                mle.evaluations[0]
            })
            .collect()
    }
}
