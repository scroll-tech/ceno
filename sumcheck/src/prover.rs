use std::{array, mem, sync::Arc};

use ark_std::{end_timer, start_timer};
use crossbeam_channel::bounded;
use ff_ext::ExtensionField;
use multilinear_extensions::{
    commutative_op_mle_pair, mle::MultilinearExtension, op_mle, virtual_poly::VirtualPolynomial,
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelIterator, ParallelIterator},
};
use transcript::{Challenge, Transcript, TranscriptSyncronized};

#[cfg(feature = "non_pow2_rayon_thread")]
use crate::local_thread_pool::{LOCAL_THREAD_POOL, create_local_pool_once};

use crate::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverMessage, IOPProverState},
    util::{
        AdditiveArray, AdditiveVec, barycentric_weights, ceil_log2, extrapolate,
        merge_sumcheck_polys,
    },
};

impl<E: ExtensionField> IOPProverState<E> {
    /// Given a virtual polynomial, generate an IOP proof.
    /// multi-threads model follow https://arxiv.org/pdf/2210.00264#page=8 "distributed sumcheck"
    /// This is experiment features. It's preferable that we move parallel level up more to
    /// "bould_poly" so it can be more isolation
    #[tracing::instrument(skip_all, name = "sumcheck::prove_batch_polys")]
    pub fn prove_batch_polys(
        max_thread_id: usize,
        mut polys: Vec<VirtualPolynomial<E>>,
        transcript: &mut impl Transcript<E>,
    ) -> (IOPProof<E>, IOPProverState<E>) {
        assert!(!polys.is_empty());
        assert_eq!(polys.len(), max_thread_id);

        let log2_max_thread_id = ceil_log2(max_thread_id); // do not support SIZE not power of 2
        let (num_variables, max_degree) = (
            polys[0].aux_info.num_variables,
            polys[0].aux_info.max_degree,
        );
        for poly in polys[1..].iter() {
            assert!(poly.aux_info.num_variables == num_variables);
            assert!(poly.aux_info.max_degree == max_degree);
        }

        // return empty proof when target polymonial is constant
        if num_variables == 0 {
            return (IOPProof::default(), IOPProverState {
                poly: polys[0].clone(),
                ..Default::default()
            });
        }
        let start = start_timer!(|| "sum check prove");

        transcript.append_message(&(num_variables + log2_max_thread_id).to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());
        let thread_based_transcript = TranscriptSyncronized::new(max_thread_id);
        let (tx_prover_state, rx_prover_state) = bounded(max_thread_id);

        // extrapolation_aux only need to init once
        let extrapolation_aux = (1..max_degree)
            .map(|degree| {
                let points = (0..1 + degree as u64).map(E::from).collect::<Vec<_>>();
                let weights = barycentric_weights(&points);
                (points, weights)
            })
            .collect::<Vec<_>>();

        // spawn extra #(max_thread_id - 1) work threads, whereas the main-thread be the last work
        // thread
        for thread_id in 0..(max_thread_id - 1) {
            let mut prover_state = Self::prover_init_with_extrapolation_aux(
                mem::take(&mut polys[thread_id]),
                extrapolation_aux.clone(),
            );
            let tx_prover_state = tx_prover_state.clone();
            let mut thread_based_transcript = thread_based_transcript.clone();

            let spawn_task = move || {
                let mut challenge = None;
                let span = entered_span!("prove_rounds");
                for _ in 0..num_variables {
                    let prover_msg =
                        IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);
                    thread_based_transcript.append_field_element_exts(&prover_msg.evaluations);

                    challenge =
                        Some(thread_based_transcript.get_and_append_challenge(b"Internal round"));
                    thread_based_transcript.commit_rolling();
                }
                exit_span!(span);
                // pushing the last challenge point to the state
                if let Some(p) = challenge {
                    prover_state.challenges.push(p);
                    // fix last challenge to collect final evaluation
                    prover_state
                        .poly
                        .flattened_ml_extensions
                        .iter_mut()
                        .for_each(|mle| {
                            let mle = Arc::make_mut(mle);
                            mle.fix_variables_in_place(&[p.elements]);
                        });
                    tx_prover_state
                        .send(Some((thread_id, prover_state)))
                        .unwrap();
                } else {
                    tx_prover_state.send(None).unwrap();
                }
            };

            // create local thread pool if global rayon pool size < max_thread_id
            // this usually cause by global pool size not power of 2.
            if rayon::current_num_threads() >= max_thread_id {
                rayon::spawn(spawn_task);
            } else {
                #[cfg(not(feature = "non_pow2_rayon_thread"))]
                {
                    panic!(
                        "rayon global thread pool size {} mismatch with desired poly size {}, add --features non_pow2_rayon_thread",
                        rayon::current_num_threads(),
                        polys.len()
                    );
                }

                #[cfg(feature = "non_pow2_rayon_thread")]
                unsafe {
                    create_local_pool_once(max_thread_id, true);

                    if let Some(pool) = LOCAL_THREAD_POOL.as_ref() {
                        pool.spawn(spawn_task)
                    } else {
                        panic!("empty local pool")
                    }
                }
            }
        }

        let mut prover_msgs = Vec::with_capacity(num_variables);
        let thread_id = max_thread_id - 1;
        let mut prover_state = Self::prover_init_with_extrapolation_aux(
            mem::take(&mut polys[thread_id]),
            extrapolation_aux.clone(),
        );
        let tx_prover_state = tx_prover_state.clone();
        let mut thread_based_transcript = thread_based_transcript.clone();

        let span = entered_span!("main_thread_prove_rounds");
        // main thread also be one worker thread
        // NOTE inline main thread flow with worker thread to improve efficiency
        // refactor to shared closure cause to 5% throuput drop
        let mut challenge = None;
        for _ in 0..num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);
            thread_based_transcript.append_field_element_exts(&prover_msg.evaluations);

            // for each round, we must collect #SIZE prover message
            let mut evaluations = AdditiveVec::new(max_degree + 1);

            // sum for all round poly evaluations vector
            for _ in 0..max_thread_id {
                let round_poly_coeffs = thread_based_transcript.read_field_element_exts();
                evaluations += AdditiveVec(round_poly_coeffs);
            }

            let span = entered_span!("main_thread_get_challenge");
            transcript.append_field_element_exts(&evaluations.0);

            let next_challenge = transcript.get_and_append_challenge(b"Internal round");
            (0..max_thread_id).for_each(|_| {
                thread_based_transcript.send_challenge(next_challenge.elements);
            });

            exit_span!(span);

            prover_msgs.push(IOPProverMessage {
                evaluations: evaluations.0,
            });

            challenge = Some(thread_based_transcript.get_and_append_challenge(b"Internal round"));
            thread_based_transcript.commit_rolling();
        }
        exit_span!(span);
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p);
            // fix last challenge to collect final evaluation
            prover_state
                .poly
                .flattened_ml_extensions
                .iter_mut()
                .for_each(|mle| {
                    let mle = Arc::make_mut(mle);
                    mle.fix_variables_in_place(&[p.elements]);
                });
            tx_prover_state
                .send(Some((thread_id, prover_state)))
                .unwrap();
        } else {
            tx_prover_state.send(None).unwrap();
        }

        let mut prover_states = (0..max_thread_id)
            .map(|_| IOPProverState::default())
            .collect::<Vec<_>>();
        for _ in 0..max_thread_id {
            if let Some((index, prover_msg)) = rx_prover_state.recv().unwrap() {
                prover_states[index] = prover_msg
            } else {
                println!("got empty msg, which is normal if virtual poly is constant function")
            }
        }

        if log2_max_thread_id == 0 {
            let prover_state = mem::take(&mut prover_states[0]);
            return (
                IOPProof {
                    point: prover_state
                        .challenges
                        .iter()
                        .map(|challenge| challenge.elements)
                        .collect(),
                    proofs: prover_msgs,
                },
                prover_state,
            );
        }

        // second stage sumcheck
        let poly = merge_sumcheck_polys(&prover_states, max_thread_id);
        let mut prover_state =
            Self::prover_init_with_extrapolation_aux(poly, extrapolation_aux.clone());

        let mut challenge = None;
        let span = entered_span!("prove_rounds_stage2");
        for _ in 0..log2_max_thread_id {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);

            prover_msg
                .evaluations
                .iter()
                .for_each(|e| transcript.append_field_element_ext(e));
            prover_msgs.push(prover_msg);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round"));
        }
        exit_span!(span);

        let span = entered_span!("after_rounds_prover_state_stage2");
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
                point: [
                    mem::take(&mut prover_states[0]).challenges,
                    prover_state.challenges.clone(),
                ]
                .concat()
                .iter()
                .map(|challenge| challenge.elements)
                .collect(),
                proofs: prover_msgs,
            },
            prover_state,
        )
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub fn prover_init_with_extrapolation_aux(
        polynomial: VirtualPolynomial<E>,
        extrapolation_aux: Vec<(Vec<E>, Vec<E>)>,
    ) -> Self {
        let start = start_timer!(|| "sum check prover init");
        assert_ne!(
            polynomial.aux_info.num_variables, 0,
            "Attempt to prove a constant."
        );
        end_timer!(start);

        let max_degree = polynomial.aux_info.max_degree;
        assert!(extrapolation_aux.len() == max_degree - 1);
        Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            poly: polynomial,
            extrapolation_aux,
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
            assert!(
                challenge.is_some(),
                "verifier message is empty in round {}",
                self.round
            );
            let chal = challenge.unwrap();
            self.challenges.push(chal);
            let r = self.challenges[self.round - 1];

            if self.challenges.len() == 1 {
                self.poly
                    .flattened_ml_extensions
                    .iter_mut()
                    .for_each(|f| *f = Arc::new(f.fix_variables(&[r.elements])));
            } else {
                self.poly
                    .flattened_ml_extensions
                    .iter_mut()
                    // benchmark result indicate make_mut achieve better performange than get_mut,
                    // which can be +5% overhead rust docs doen't explain the
                    // reason
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
        let AdditiveVec(products_sum) = self.poly.products.iter().fold(
            AdditiveVec::new(self.poly.aux_info.max_degree + 1),
            |mut products_sum, (coefficient, products)| {
                let span = entered_span!("sum");

                let mut sum = match products.len() {
                    1 => {
                        let f = &self.poly.flattened_ml_extensions[products[0]];
                        op_mle! {
                            |f| {
                                (0..f.len())
                                    .step_by(2)
                                    .fold(AdditiveArray::<E, 2>(array::from_fn(|_| 0.into())), |mut acc, b| {
                                            acc.0[0] += f[b];
                                            acc.0[1] += f[b+1];
                                            acc
                                    })
                            },
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
                            |f, g| (0..f.len()).step_by(2).fold(
                                AdditiveArray::<E, 3>(array::from_fn(|_| 0.into())),
                                |mut acc, b| {
                                    acc.0[0] += f[b] * g[b];
                                    acc.0[1] += f[b + 1] * g[b + 1];
                                    acc.0[2] +=
                                        (f[b + 1] + f[b + 1] - f[b]) * (g[b + 1] + g[b + 1] - g[b]);
                                    acc
                                }
                            ),
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
        );
        exit_span!(span);

        end_timer!(start);

        IOPProverMessage {
            evaluations: products_sum,
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

/// parallel version
#[deprecated(note = "deprecated parallel version due to syncronizaion overhead")]
impl<E: ExtensionField> IOPProverState<E> {
    /// Given a virtual polynomial, generate an IOP proof.
    #[tracing::instrument(skip_all, name = "sumcheck::prove_parallel")]
    pub fn prove_parallel(
        poly: VirtualPolynomial<E>,
        transcript: &mut impl Transcript<E>,
    ) -> (IOPProof<E>, IOPProverState<E>) {
        let (num_variables, max_degree) = (poly.aux_info.num_variables, poly.aux_info.max_degree);

        // return empty proof when target polymonial is constant
        if num_variables == 0 {
            return (IOPProof::default(), IOPProverState {
                poly,
                ..Default::default()
            });
        }
        let start = start_timer!(|| "sum check prove");

        transcript.append_message(&num_variables.to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());

        let mut prover_state = Self::prover_init_parallel(poly);
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(num_variables);
        let span = entered_span!("prove_rounds");
        for _ in 0..num_variables {
            let prover_msg = IOPProverState::prove_round_and_update_state_parallel(
                &mut prover_state,
                &challenge,
            );

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
                    Arc::make_mut(mle).fix_variables_in_place_parallel(&[p.elements]);
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
            },
            prover_state,
        )
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub(crate) fn prover_init_parallel(polynomial: VirtualPolynomial<E>) -> Self {
        let start = start_timer!(|| "sum check prover init");
        assert_ne!(
            polynomial.aux_info.num_variables, 0,
            "Attempt to prove a constant."
        );

        let max_degree = polynomial.aux_info.max_degree;
        let prover_state = Self {
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
        };

        end_timer!(start);
        prover_state
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    #[tracing::instrument(skip_all, name = "sumcheck::prove_round_and_update_state_parallel")]
    pub(crate) fn prove_round_and_update_state_parallel(
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
                    .for_each(|f| *f = f.fix_variables_parallel(&[r.elements]).into());
            } else {
                self.poly
                    .flattened_ml_extensions
                    .par_iter_mut()
                    // benchmark result indicate make_mut achieve better performange than get_mut,
                    // which can be +5% overhead rust docs doen't explain the
                    // reason
                    .map(Arc::make_mut)
                    .for_each(|f| {
                        f.fix_variables_in_place_parallel(&[r.elements]);
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
        }
    }
}
