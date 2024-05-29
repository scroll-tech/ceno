use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use multilinear_extensions::{commutative_op_mle_pair, op_mle, virtual_poly::VirtualPolynomial};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelIterator, ParallelIterator},
};
use transcript::{Challenge, Transcript};

use crate::{
    entered_span, exit_span,
    structs::{IOPProof, IOPProverMessage, IOPProverState},
    util::{barycentric_weights, extrapolate, AdditiveArray, AdditiveVec},
};

impl<E: ExtensionField> IOPProverState<E> {
    /// Given a virtual polynomial, generate an IOP proof.
    #[tracing::instrument(skip_all, name = "sumcheck::prove")]
    pub fn prove(
        poly: VirtualPolynomial<E>,
        transcript: &mut Transcript<E>,
    ) -> (IOPProof<E>, IOPProverState<E>) {
        let (num_variables, max_degree) = (poly.aux_info.num_variables, poly.aux_info.max_degree);

        // return empty proof when target polymonial is constant
        if num_variables == 0 {
            return (
                IOPProof::default(),
                IOPProverState {
                    poly: poly,
                    ..Default::default()
                },
            );
        }
        let start = start_timer!(|| "sum check prove");

        transcript.append_message(&num_variables.to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());

        let mut prover_state = Self::prover_init(poly);
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(num_variables);
        let span = entered_span!("prove_rounds");
        for _ in 0..num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);

            prover_msg
                .evaluations
                .iter()
                .for_each(|e| transcript.append_field_element_ext(e));

            prover_msgs.push(prover_msg);
            let span = entered_span!("get_challenge");
            challenge = Some(transcript.get_and_append_challenge(b"Internal round"));
            exit_span!(span);
        }
        exit_span!(span);

        let span = entered_span!("after_rounds_prover_state");
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p);
            // fix last challenge to collect final evaluation
            prover_state
                .poly
                .flattened_ml_extensions
                .par_iter_mut()
                .for_each(|mle| {
                    Arc::make_mut(mle).fix_variables_in_place(&[p.elements]);
                });
        };
        exit_span!(span);

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
                ..Default::default()
            },
            prover_state.into(),
        )
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub(crate) fn prover_init(polynomial: VirtualPolynomial<E>) -> Self {
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
                    let points = (0..1 + degree as u64).map(E::from).collect::<Vec<_>>();
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
    #[tracing::instrument(skip_all, name = "sumcheck::prove_round_and_update_state")]
    pub(crate) fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<Challenge<E>>,
    ) -> IOPProverMessage<E> {
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
        let span = entered_span!("fix_variables");
        if self.round == 0 {
            assert!(challenge.is_none(), "first round should be prover first.");
        } else {
            assert!(challenge.is_some(), "verifier message is empty");
            let chal = challenge.unwrap();
            self.challenges.push(chal);
            let r = self.challenges[self.round - 1];

            if self.challenges.len() == 1 {
                self.poly
                    .flattened_ml_extensions
                    .par_iter_mut()
                    .for_each(|f| *f = f.fix_variables(&[r.elements]).into());
            } else {
                self.poly
                    .flattened_ml_extensions
                    .par_iter_mut()
                    // benchmark result indicate make_mut achieve better performange than get_mut, which can be +5% overhead
                    // rust docs doen't explain the reason
                    .map(Arc::make_mut)
                    .for_each(|f| {
                        f.fix_variables_in_place(&[r.elements]);
                    });
            }
        }
        exit_span!(span);
        // end_timer!(fix_argument);

        self.round += 1;

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        let span = entered_span!("products_sum");
        let AdditiveVec(products_sum) = self
            .poly
            .products
            .par_iter()
            .fold_with(
                AdditiveVec::new(self.poly.aux_info.max_degree + 1),
                |mut products_sum, (coefficient, products)| {
                    let span = entered_span!("sum");

                    let mut sum = match products.len() {
                        1 => {
                            let f = &self.poly.flattened_ml_extensions[products[0]];
                            op_mle! {
                                |f| (0..f.len())
                                .into_par_iter()
                                .step_by(2)
                                .with_min_len(64)
                                .map(|b| {
                                    AdditiveArray([
                                        f[b],
                                        f[b + 1]
                                    ])
                                })
                                .sum::<AdditiveArray<_, 2>>(),
                                |sum| AdditiveArray(sum.0.map(E::from))
                            }
                            .to_vec()
                        }
                        2 => {
                            let (f, g) = (
                                &self.poly.flattened_ml_extensions[products[0]],
                                &self.poly.flattened_ml_extensions[products[1]],
                            );
                            commutative_op_mle_pair!(
                                |f, g| (0..f.len())
                                    .into_par_iter()
                                    .step_by(2)
                                    .with_min_len(64)
                                    .map(|b| {
                                        AdditiveArray([
                                            f[b] * g[b],
                                            f[b + 1] * g[b + 1],
                                            (f[b + 1] + f[b + 1] - f[b])
                                                * (g[b + 1] + g[b + 1] - g[b]),
                                        ])
                                    })
                                    .sum::<AdditiveArray<_, 3>>(),
                                |sum| AdditiveArray(sum.0.map(E::from))
                            )
                            .to_vec()
                        }
                        _ => unimplemented!("do not support degree > 2"),
                    };
                    exit_span!(span);
                    sum.iter_mut().for_each(|sum| *sum *= coefficient);

                    let span = entered_span!("extrapolation");
                    let extrapolation = (0..self.poly.aux_info.max_degree - products.len())
                        .into_par_iter()
                        .map(|i| {
                            let (points, weights) = &self.extrapolation_aux[products.len() - 1];
                            let at = E::from((products.len() + 1 + i) as u64);
                            extrapolate(points, weights, &sum, &at)
                        })
                        .collect::<Vec<_>>();
                    sum.extend(extrapolation);
                    exit_span!(span);
                    let span = entered_span!("extend_extrapolate");
                    products_sum += AdditiveVec(sum);
                    exit_span!(span);
                    products_sum
                },
            )
            .reduce_with(|acc, item| acc + item)
            .unwrap();
        exit_span!(span);

        end_timer!(start);

        IOPProverMessage {
            evaluations: products_sum,
            ..Default::default()
        }
    }

    /// collect all mle evaluation (claim) after sumcheck
    pub fn get_mle_final_evaluations(&self) -> Vec<E> {
        self.poly
            .flattened_ml_extensions
            .iter()
            .map(|mle| {
                assert!(
                    mle.evaluations.len() == 1,
                    "mle.evaluations.len() {} != 1, must be called after prove_round_and_update_state",
                    mle.evaluations.len(),
                );
                op_mle! {
                    |mle| mle[0],
                    |eval| E::from(eval)
                }
            })
            .collect()
    }
}
