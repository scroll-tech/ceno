use std::{mem, sync::Arc};

use ark_std::{end_timer, start_timer};
use crossbeam_channel::bounded;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::FieldType,
    op_mle,
    util::largest_even_below,
    virtual_poly::VirtualPolynomial,
    virtual_polys::{PolyMeta, VirtualPolynomials},
};
use rayon::{
    Scope,
    iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelIterator, ParallelIterator},
};
use sumcheck_macro::sumcheck_code_gen;
use transcript::{Challenge, Transcript, TranscriptSyncronized};

use crate::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverMessage, IOPProverState},
    util::{
        AdditiveArray, AdditiveVec, barycentric_weights, ceil_log2, extrapolate,
        merge_sumcheck_polys, merge_sumcheck_prover_state, serial_extrapolate,
    },
};
use p3::field::PrimeCharacteristicRing;

impl<'a, E: ExtensionField> IOPProverState<'a, E> {
    /// Given a virtual polynomial, generate an IOP proof.
    /// multi-threads model follow https://arxiv.org/pdf/2210.00264#page=8 "distributed sumcheck"
    /// This is experiment features. It's preferable that we move parallel level up more to
    /// "bould_poly" so it can be more isolation
    #[tracing::instrument(skip_all, name = "sumcheck::prove", level = "trace")]
    pub fn prove(
        virtual_poly: VirtualPolynomials<'a, E>,
        transcript: &mut impl Transcript<E>,
    ) -> (IOPProof<E>, IOPProverState<'a, E>) {
        let max_thread_id = virtual_poly.num_threads;
        let (polys, poly_meta) = virtual_poly.get_batched_polys();

        assert!(!polys.is_empty());
        assert_eq!(polys.len(), max_thread_id);
        assert!(max_thread_id.is_power_of_two());

        let log2_max_thread_id = ceil_log2(max_thread_id); // do not support SIZE not power of 2
        assert!(
            polys
                .iter()
                .map(|poly| (poly.aux_info.max_num_variables, poly.aux_info.max_degree))
                .all_equal()
        );
        let (num_variables, max_degree) = (
            polys[0].aux_info.max_num_variables,
            polys[0].aux_info.max_degree,
        );

        // extrapolation_aux only need to init once
        let extrapolation_aux: Vec<(Vec<E>, Vec<E>)> = (1..max_degree)
            .map(|degree| {
                let points = (0..1 + degree as u64).map(E::from_u64).collect::<Vec<_>>();
                let weights = barycentric_weights(&points);
                (points, weights)
            })
            .collect::<Vec<_>>();

        transcript.append_message(&(num_variables + log2_max_thread_id).to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());
        let (phase1_point, mut prover_state, mut prover_msgs) = if num_variables > 0 {
            let (mut prover_states, prover_msgs) = Self::phase1_sumcheck(
                max_thread_id,
                num_variables,
                extrapolation_aux.clone(),
                poly_meta,
                polys,
                max_degree,
                transcript,
            );
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
            let point = prover_states[0]
                .challenges
                .iter()
                .map(|c| c.elements)
                .collect_vec();
            let poly = merge_sumcheck_prover_state(&prover_states);

            (
                point,
                Self::prover_init_with_extrapolation_aux(
                    true,
                    poly,
                    extrapolation_aux.clone(),
                    None,
                    None,
                ),
                prover_msgs,
            )
        } else {
            (
                vec![],
                Self::prover_init_with_extrapolation_aux(
                    true,
                    merge_sumcheck_polys(polys.iter().collect_vec(), Some(poly_meta)),
                    extrapolation_aux.clone(),
                    None,
                    None,
                ),
                vec![],
            )
        };

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
            challenge = Some(transcript.sample_and_append_challenge(b"Internal round"));
        }
        exit_span!(span);

        let span = entered_span!("after_rounds_prover_state_stage2");
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p);
            // fix last challenge to collect final evaluation
            prover_state.fix_var(p.elements);
        };
        exit_span!(span);
        (
            IOPProof {
                point: phase1_point
                    .into_iter()
                    .chain(prover_state.challenges.iter().map(|c| c.elements))
                    .collect(),
                proofs: prover_msgs,
            },
            prover_state,
        )
    }

    fn phase1_sumcheck(
        max_thread_id: usize,
        num_variables: usize,
        extrapolation_aux: Vec<(Vec<E>, Vec<E>)>,
        poly_meta: Vec<PolyMeta>,
        mut polys: Vec<VirtualPolynomial<'a, E>>,
        max_degree: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Vec<IOPProverState<'a, E>>, Vec<IOPProverMessage<E>>) {
        let log2_max_thread_id = ceil_log2(max_thread_id); // do not support SIZE not power of 2
        let thread_based_transcript = TranscriptSyncronized::new(max_thread_id);
        let (tx_prover_state, rx_prover_state) = bounded(max_thread_id);

        // spawn extra #(max_thread_id - 1) work threads
        let num_worker_threads = max_thread_id - 1;
        // whereas the main-thread be the last work thread
        let main_thread_id = num_worker_threads;
        let span = entered_span!("spawn loop", profiling_4 = true);
        let scoped_fn = |s: &Scope<'a>| {
            for (thread_id, poly) in polys.iter_mut().enumerate().take(num_worker_threads) {
                let mut prover_state = Self::prover_init_with_extrapolation_aux(
                    false,
                    mem::take(poly),
                    extrapolation_aux.clone(),
                    Some(log2_max_thread_id),
                    Some(poly_meta.clone()),
                );
                let tx_prover_state = tx_prover_state.clone();
                let mut thread_based_transcript = thread_based_transcript.clone();
                s.spawn(move |_| {
                    let mut challenge = None;
                    // Note: This span is not nested into the "spawn loop" span, although lexically it looks so.
                    // Nesting is possible, but then `tracing-forest` does the wrong thing when measuring duration.
                    // TODO: investigate possibility of nesting with correct duration of parent span
                    let span = entered_span!("prove_rounds", profiling_5 = true);
                    for _ in 0..num_variables {
                        let prover_msg = IOPProverState::prove_round_and_update_state(
                            &mut prover_state,
                            &challenge,
                        );
                        thread_based_transcript.append_field_element_exts(&prover_msg.evaluations);

                        challenge = Some(
                            thread_based_transcript.sample_and_append_challenge(b"Internal round"),
                        );
                        thread_based_transcript.commit_rolling();
                    }
                    exit_span!(span);
                    // pushing the last challenge point to the state
                    if let Some(p) = challenge {
                        prover_state.challenges.push(p);
                        // fix last challenge to collect final evaluation
                        prover_state.fix_var(p.elements);

                        tx_prover_state
                            .send(Some((thread_id, prover_state)))
                            .unwrap();
                    } else {
                        tx_prover_state.send(None).unwrap();
                    }
                })
            }
            exit_span!(span);

            let mut prover_msgs = Vec::with_capacity(num_variables);
            let mut prover_state = Self::prover_init_with_extrapolation_aux(
                true,
                mem::take(&mut polys[main_thread_id]),
                extrapolation_aux.clone(),
                Some(log2_max_thread_id),
                Some(poly_meta.clone()),
            );
            let tx_prover_state = tx_prover_state.clone();
            let mut thread_based_transcript = thread_based_transcript.clone();

            let main_thread_span = entered_span!("main_thread_prove_rounds");
            // main thread also be one worker thread
            // NOTE inline main thread flow with worker thread to improve efficiency
            // refactor to shared closure cause to 5% throuput drop
            let mut challenge = None;
            for _ in 0..num_variables {
                let prover_msg =
                    IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge);

                // for each round, we must collect #SIZE prover message
                let mut evaluations = AdditiveVec::new(max_degree + 1);

                // sum for all round poly evaluations vector
                evaluations += AdditiveVec(prover_msg.evaluations);
                for _ in 0..num_worker_threads {
                    let round_poly_coeffs = thread_based_transcript.read_field_element_exts();
                    evaluations += AdditiveVec(round_poly_coeffs);
                }

                let get_challenge_span = entered_span!("main_thread_get_challenge");
                transcript.append_field_element_exts(&evaluations.0);

                let next_challenge = transcript.sample_and_append_challenge(b"Internal round");
                (0..num_worker_threads).for_each(|_| {
                    thread_based_transcript.send_challenge(next_challenge.elements);
                });

                exit_span!(get_challenge_span);

                prover_msgs.push(IOPProverMessage {
                    evaluations: evaluations.0,
                });

                challenge = Some(next_challenge);
                thread_based_transcript.commit_rolling();
            }
            exit_span!(main_thread_span);
            // pushing the last challenge point to the state
            if let Some(p) = challenge {
                prover_state.challenges.push(p);
                // fix last challenge to collect final evaluation
                prover_state.fix_var(p.elements);
                tx_prover_state
                    .send(Some((main_thread_id, prover_state)))
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

            (prover_states, prover_msgs)
        };

        // create local thread pool if global rayon pool size < max_thread_id
        // this usually cause by global pool size not power of 2.
        if rayon::current_num_threads() >= max_thread_id {
            rayon::in_place_scope(scoped_fn)
        } else {
            panic!(
                "rayon global thread pool size {} mismatch with desired poly size {}.",
                rayon::current_num_threads(),
                polys.len()
            );
        }
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub fn prover_init_with_extrapolation_aux(
        is_main_worker: bool,
        polynomial: VirtualPolynomial<'a, E>,
        extrapolation_aux: Vec<(Vec<E>, Vec<E>)>,
        phase2_numvar: Option<usize>,
        poly_meta: Option<Vec<PolyMeta>>,
    ) -> Self {
        let start = start_timer!(|| "sum check prover init");
        assert_ne!(
            polynomial.aux_info.max_num_variables, 0,
            "Attempt to prove a constant."
        );
        if let Some(poly_meta) = poly_meta.as_ref() {
            assert_eq!(
                poly_meta.len(),
                polynomial.flattened_ml_extensions.len(),
                "num_vars too small for concurrency"
            );
        }
        end_timer!(start);

        let max_degree = polynomial.aux_info.max_degree;
        assert!(extrapolation_aux.len() == max_degree - 1);
        let num_polys = polynomial.flattened_ml_extensions.len();

        Self {
            is_main_worker,
            max_num_variables: polynomial.aux_info.max_num_variables,
            challenges: Vec::with_capacity(polynomial.aux_info.max_num_variables),
            round: 0,
            poly: polynomial,
            extrapolation_aux,
            poly_meta: poly_meta.unwrap_or_else(|| vec![PolyMeta::Normal; num_polys]),
            phase2_numvar,
            poly_index_fixvar_in_place: vec![false; num_polys],
        }
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    #[tracing::instrument(skip_all, name = "sumcheck::prove_round_and_update_state")]
    pub fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<Challenge<E>>,
    ) -> IOPProverMessage<E> {
        let start =
            start_timer!(|| format!("sum check prove {}-th round and update state", self.round));

        assert!(
            self.round < self.poly.aux_info.max_num_variables,
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
            self.fix_var(r.elements);
        }
        exit_span!(span);
        // end_timer!(fix_argument);

        self.round += 1;

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        let span = entered_span!("products_sum");
        let AdditiveVec(products_sum) = self.poly.products.iter().fold(
            AdditiveVec::new(self.poly.aux_info.max_degree + 1),
            |mut products_sum, (coefficient, prod)| {
                let span = entered_span!("sum");
                let f = &self.poly.flattened_ml_extensions;
                let f_type = &self.poly_meta;
                let get_poly_meta = || f_type[prod[0]];
                let mut sum: Vec<E> = match prod.len() {
                    1 => sumcheck_code_gen!(1, false, |i| &f[prod[i]], || get_poly_meta()).to_vec(),
                    2 => sumcheck_code_gen!(2, false, |i| &f[prod[i]], || get_poly_meta()).to_vec(),
                    3 => sumcheck_code_gen!(3, false, |i| &f[prod[i]], || get_poly_meta()).to_vec(),
                    4 => sumcheck_code_gen!(4, false, |i| &f[prod[i]], || get_poly_meta()).to_vec(),
                    5 => sumcheck_code_gen!(5, false, |i| &f[prod[i]], || get_poly_meta()).to_vec(),
                    _ => unimplemented!("do not support degree {} > 5", prod.len()),
                };
                exit_span!(span);

                sum.iter_mut().for_each(|sum| *sum *= *coefficient);

                let span = entered_span!("extrapolation");
                let extrapolation = (0..self.poly.aux_info.max_degree - prod.len())
                    .map(|i| {
                        let (points, weights) = &self.extrapolation_aux[prod.len() - 1];
                        let at = E::from_u64((prod.len() + 1 + i) as u64);
                        serial_extrapolate(points, weights, &sum, &at)
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
    pub fn get_mle_final_evaluations(&self) -> Vec<Vec<E>> {
        self.poly
            .flattened_ml_extensions
            .iter()
            .map(|mle| {
                op_mle! {
                    |mle| mle.to_vec(),
                    |mle| mle.into_iter().map(E::from).collect_vec()
                }
            })
            .collect()
    }

    /// collect all mle evaluation (claim) after sumcheck
    /// NOTE final evaluation size of each mle could be >= 1
    pub fn get_mle_flatten_final_evaluations(&self) -> Vec<E> {
        self.get_mle_final_evaluations()
            .into_iter()
            .flatten()
            .collect_vec()
    }

    pub fn expected_numvars_at_round(&self) -> usize {
        // first round start from 1
        let num_vars = self.max_num_variables + 1 - self.round;
        debug_assert!(num_vars > 0, "make sumcheck work on constant");
        num_vars
    }

    /// fix_var
    pub fn fix_var(&mut self, r: E) {
        let expected_numvars_at_round = self.expected_numvars_at_round();
        self.poly_index_fixvar_in_place
            .iter_mut()
            .zip_eq(self.poly.flattened_ml_extensions.iter_mut())
            .zip_eq(&self.poly_meta)
            .for_each(|((can_fixvar_in_place, poly), poly_type)| {
                debug_assert!(poly.num_vars() > 0);
                if *can_fixvar_in_place {
                    // in place
                    let poly = Arc::get_mut(poly);
                    if let Some(f) = poly {
                        debug_assert!(f.num_vars() <= expected_numvars_at_round);
                        if f.num_vars() > 0 {
                            f.fix_variables_in_place(&[r])
                        }
                    };
                } else if poly.num_vars() > 0 {
                    if expected_numvars_at_round == poly.num_vars()
                        && matches!(poly_type, PolyMeta::Normal)
                    {
                        *poly = Arc::new(poly.fix_variables(&[r]));
                        *can_fixvar_in_place = true;
                    }
                } else {
                    panic!("calling sumcheck on constant")
                }
            });
    }
}

/// parallel version
#[deprecated(note = "deprecated parallel version due to syncronizaion overhead")]
impl<'a, E: ExtensionField> IOPProverState<'a, E> {
    /// Given a virtual polynomial, generate an IOP proof.
    #[tracing::instrument(skip_all, name = "sumcheck::prove_parallel")]
    pub fn prove_parallel(
        poly: VirtualPolynomial<'a, E>,
        transcript: &mut impl Transcript<E>,
    ) -> (IOPProof<E>, IOPProverState<'a, E>) {
        let (num_variables, max_degree) =
            (poly.aux_info.max_num_variables, poly.aux_info.max_degree);

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
            challenge = Some(transcript.sample_and_append_challenge(b"Internal round"));
            exit_span!(span);
        }
        exit_span!(span);

        let span = entered_span!("after_rounds_prover_state");
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p);
            // fix last challenge to collect final evaluation
            prover_state.fix_var_parallel(p.elements);
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
    pub(crate) fn prover_init_parallel(polynomial: VirtualPolynomial<'a, E>) -> Self {
        let start = start_timer!(|| "sum check prover init");
        assert_ne!(
            polynomial.aux_info.max_num_variables, 0,
            "Attempt to prove a constant."
        );

        let max_degree = polynomial.aux_info.max_degree;
        let num_polys = polynomial.flattened_ml_extensions.len();
        let poly_meta = vec![PolyMeta::Normal; num_polys];
        let prover_state = Self {
            is_main_worker: true,
            max_num_variables: polynomial.aux_info.max_num_variables,
            challenges: Vec::with_capacity(polynomial.aux_info.max_num_variables),
            round: 0,
            poly: polynomial,
            extrapolation_aux: (1..max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(E::from_u64).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect(),
            poly_meta,
            phase2_numvar: None,
            poly_index_fixvar_in_place: vec![false; num_polys],
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
            self.round < self.poly.aux_info.max_num_variables,
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
            self.fix_var(r.elements);
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
                |mut products_sum, (coefficient, prod)| {
                    let span = entered_span!("sum");

                    let f = &self.poly.flattened_ml_extensions;
                    let f_type = &self.poly_meta;
                    let get_poly_meta = || f_type[prod[0]];
                    let mut sum: Vec<E> = match prod.len() {
                        1 => sumcheck_code_gen!(1, true, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        2 => sumcheck_code_gen!(2, true, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        3 => sumcheck_code_gen!(3, true, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        4 => sumcheck_code_gen!(4, true, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        5 => sumcheck_code_gen!(5, true, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        _ => unimplemented!("do not support degree {} > 5", prod.len()),
                    };
                    exit_span!(span);
                    sum.iter_mut().for_each(|sum| *sum *= *coefficient);

                    let span = entered_span!("extrapolation");
                    let extrapolation = (0..self.poly.aux_info.max_degree - prod.len())
                        .into_par_iter()
                        .map(|i| {
                            let (points, weights) = &self.extrapolation_aux[prod.len() - 1];
                            let at = E::from_u64((prod.len() + 1 + i) as u64);
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

    /// fix_var
    pub fn fix_var_parallel(&mut self, r: E) {
        let expected_numvars_at_round = self.expected_numvars_at_round();
        self.poly_index_fixvar_in_place
            .par_iter_mut()
            .zip_eq(self.poly.flattened_ml_extensions.par_iter_mut())
            .for_each(|(can_fixvar_in_place, poly)| {
                if *can_fixvar_in_place {
                    // in place
                    let poly = Arc::get_mut(poly);
                    if let Some(f) = poly {
                        if f.num_vars() > 0 {
                            f.fix_variables_in_place_parallel(&[r])
                        }
                    };
                } else if poly.num_vars() > 0 {
                    if expected_numvars_at_round == poly.num_vars() {
                        *poly = Arc::new(poly.fix_variables_parallel(&[r]));
                        *can_fixvar_in_place = true;
                    }
                } else {
                    panic!("calling sumcheck on constant")
                }
            });
    }
}
