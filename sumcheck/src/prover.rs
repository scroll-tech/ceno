use std::{mem, sync::Arc};

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::FieldType,
    monomial::Term,
    op_mle,
    util::{ceil_log2, largest_even_below},
    virtual_poly::{MonomialTerms, VirtualPolynomial},
    virtual_polys::{PolyMeta, VirtualPolynomials},
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelIterator, ParallelIterator},
};
use sumcheck_macro::sumcheck_code_gen;
use transcript::{Challenge, Transcript};

use crate::{
    extrapolate::ExtrapolationCache,
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverMessage, IOPProverState},
    util::{
        AdditiveArray, AdditiveVec, extrapolate_from_table, merge_sumcheck_polys,
        merge_sumcheck_prover_state,
    },
};
use p3::field::FieldAlgebra;

struct Phase1Workers<'a, E: ExtensionField> {
    workers_states: Vec<Phase1WorkerState<'a, E>>,
}

impl<'a, E: ExtensionField> Phase1Workers<'a, E> {
    fn run(
        mut self,
        num_variables: usize,
        max_degree: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Vec<IOPProverState<'a, E>>, Vec<IOPProverMessage<E>>) {
        let mut prover_msgs = Vec::with_capacity(num_variables);
        for _ in 0..num_variables {
            let evaluations = self
                .workers_states
                .par_iter_mut()
                .map(|state| state.run_round())
                .reduce(|| AdditiveVec::new(max_degree + 1), |a, b| a + b);

            transcript.append_field_element_exts(&evaluations.0);

            let challenge = transcript.sample_and_append_challenge(b"Internal round");
            for worker_state in self.workers_states.iter_mut() {
                worker_state.challenge = Some(challenge);
            }

            prover_msgs.push(IOPProverMessage {
                evaluations: evaluations.0,
            });
        }

        let Self { workers_states, .. } = self;

        (
            workers_states
                .into_iter()
                .map(|mut s| {
                    if let Some(challenge) = s.challenge.take() {
                        s.prover_state.push_challenges(vec![challenge]);
                        // fix last challenge to collect final evaluation
                        s.prover_state.fix_var(challenge.elements);
                    }
                    s.prover_state
                })
                .collect(),
            prover_msgs,
        )
    }
}

struct Phase1WorkerState<'a, E: ExtensionField> {
    prover_state: IOPProverState<'a, E>,
    challenge: Option<Challenge<E>>,
}

impl<'a, E: ExtensionField> Phase1WorkerState<'a, E> {
    fn new(
        is_main_worker: bool,
        poly: VirtualPolynomial<'a, E>,
        phase2_numvar: usize,
        poly_meta: Option<Vec<PolyMeta>>,
    ) -> Self {
        Self {
            prover_state: IOPProverState::prover_init_with_extrapolation_aux(
                is_main_worker,
                poly,
                Some(phase2_numvar),
                poly_meta,
            ),
            challenge: None,
        }
    }

    fn run_round(&mut self) -> AdditiveVec<E> {
        let prover_msg =
            IOPProverState::prove_round_and_update_state(&mut self.prover_state, &self.challenge);
        AdditiveVec(prover_msg.evaluations)
    }
}

impl<'a, E: ExtensionField> IOPProverState<'a, E> {
    /// Given a virtual polynomial, generate an IOP proof.
    /// multi-threads model follow https://arxiv.org/pdf/2210.00264#page=8 "distributed sumcheck"
    /// This is experiment features. It's preferable that we move parallel level up more to
    /// "bould_poly" so it can be more isolation
    #[tracing::instrument(
        skip_all,
        name = "sumcheck::prove",
        level = "trace",
        fields(profiling_5)
    )]
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

        let min_degree = polys[0]
            .products
            .iter()
            .flat_map(|monomial_terms| {
                monomial_terms
                    .terms
                    .iter()
                    .map(|Term { product, .. }| product.len())
            })
            .min()
            .unwrap();
        if min_degree < max_degree {
            // warm up cache giving min/max_degree
            let _ = ExtrapolationCache::<E>::get(min_degree, max_degree);
        }

        transcript.append_message(&(num_variables + log2_max_thread_id).to_le_bytes());
        transcript.append_message(&max_degree.to_le_bytes());
        let (mut prover_state, mut prover_msgs) = if num_variables > 0 {
            let span = entered_span!("phase1_sumcheck", profiling_6 = true);
            let (mut prover_states, prover_msgs) = Self::phase1_sumcheck(
                max_thread_id,
                num_variables,
                poly_meta,
                polys,
                max_degree,
                transcript,
            );
            exit_span!(span);
            if log2_max_thread_id == 0 {
                let prover_state = mem::take(&mut prover_states[0]);
                return (
                    IOPProof {
                        proofs: prover_msgs,
                    },
                    prover_state,
                );
            }
            let span = entered_span!("merged_poly", profiling_6 = true);
            let poly = merge_sumcheck_prover_state(&prover_states);
            let mut phase2_sumcheck_state =
                Self::prover_init_with_extrapolation_aux(true, poly, None, None);
            phase2_sumcheck_state.push_challenges(prover_states[0].challenges.clone());
            exit_span!(span);
            (phase2_sumcheck_state, prover_msgs)
        } else {
            (
                Self::prover_init_with_extrapolation_aux(
                    true,
                    merge_sumcheck_polys(polys.iter().collect_vec(), Some(poly_meta)),
                    None,
                    None,
                ),
                vec![],
            )
        };

        let mut challenge = None;
        let span = entered_span!("prove_rounds_stage2", profiling_6 = true);
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
            prover_state.push_challenges(vec![p]);
            // fix last challenge to collect final evaluation
            prover_state.fix_var(p.elements);
        };
        exit_span!(span);
        (
            IOPProof {
                proofs: prover_msgs,
            },
            prover_state,
        )
    }

    fn phase1_sumcheck(
        max_thread_id: usize,
        num_variables: usize,
        poly_meta: Vec<PolyMeta>,
        mut polys: Vec<VirtualPolynomial<'a, E>>,
        max_degree: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Vec<IOPProverState<'a, E>>, Vec<IOPProverMessage<E>>) {
        let log2_max_thread_id = ceil_log2(max_thread_id); // do not support SIZE not power of 2

        let span = entered_span!("spawn loop", profiling_4 = true);
        let workers_states: Vec<_> = polys
            .iter_mut()
            .enumerate()
            .map(|(thread_id, poly)| {
                // Only the first one of the workers is the "main" worker
                Phase1WorkerState::new(
                    thread_id == 0,
                    mem::take(poly),
                    log2_max_thread_id,
                    Some(poly_meta.clone()),
                )
            })
            .collect();

        exit_span!(span);

        let workers = Phase1Workers { workers_states };

        workers.run(num_variables, max_degree, transcript)
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub fn prover_init_with_extrapolation_aux(
        is_main_worker: bool,
        polynomial: VirtualPolynomial<'a, E>,
        phase2_numvar: Option<usize>,
        poly_meta: Option<Vec<PolyMeta>>,
    ) -> Self {
        let start = entered_span!("sum check prover init");
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
        exit_span!(start);

        let num_polys = polynomial.flattened_ml_extensions.len();

        Self {
            is_main_worker,
            max_num_variables: polynomial.aux_info.max_num_variables,
            // preallocate space with 2x redundancy for challenges used in sumcheck.
            // This accounts for multiple phases and potential continuation challenges,
            // ensuring we avoid reallocations when the protocol spans multiple rounds
            challenges: Vec::with_capacity(2 * polynomial.aux_info.max_num_variables),
            round: 0,
            poly: polynomial,
            poly_meta: poly_meta.unwrap_or_else(|| vec![PolyMeta::Normal; num_polys]),
            phase2_numvar,
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
        let start = entered_span!("sum check prove {}-th round and update state", self.round);

        assert!(
            self.round < self.poly.aux_info.max_num_variables,
            "Prover is not active"
        );

        // let fix_argument = entered_span!("fix argument");

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
        if self.round > 0 {
            assert!(
                challenge.is_some(),
                "verifier message is empty in round {}",
                self.round
            );
            let chal = challenge.unwrap();
            self.challenges.push(chal);
            let r = self.challenges.last().unwrap();
            self.fix_var(r.elements);
        }
        exit_span!(span);
        // exit_span!fix_argument);

        self.round += 1;

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        let span = entered_span!("build_uni_poly");
        let AdditiveVec(uni_polys) = self.poly.products.iter().fold(
            AdditiveVec::new(self.poly.aux_info.max_degree + 1),
            |mut uni_polys, MonomialTerms { terms }| {
                for Term {
                    scalar,
                    product: prod,
                } in terms
                {
                    let f = &self.poly.flattened_ml_extensions;
                    let f_type = &self.poly_meta;
                    let get_poly_meta = || f_type[prod[0]];
                    let mut uni_variate: Vec<E> = vec![E::ZERO; self.poly.aux_info.max_degree + 1];
                    let uni_variate_monomial: Vec<E> = match prod.len() {
                        1 => sumcheck_code_gen!(1, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        2 => sumcheck_code_gen!(2, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        3 => sumcheck_code_gen!(3, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        4 => sumcheck_code_gen!(4, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        5 => sumcheck_code_gen!(5, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        6 => sumcheck_code_gen!(6, false, |i| &f[prod[i]], || get_poly_meta())
                            .to_vec(),
                        _ => unimplemented!("do not support degree {} > 6", prod.len()),
                    };

                    uni_variate
                        .iter_mut()
                        .zip(uni_variate_monomial)
                        .take(prod.len() + 1)
                        .for_each(|(eval, monimial_eval,)| either::for_both!(scalar, scalar => *eval = monimial_eval**scalar));


                    if prod.len() < self.poly.aux_info.max_degree {
                        // Perform extrapolation using the precomputed extrapolation table
                        extrapolate_from_table(
                            &mut uni_variate,
                            prod.len() + 1,
                        );
                    }

                    uni_polys += AdditiveVec(uni_variate);
                }
                uni_polys
            },
        );
        exit_span!(span);

        exit_span!(start);

        IOPProverMessage {
            evaluations: uni_polys,
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
        self.poly
            .flattened_ml_extensions
            .iter_mut()
            .zip_eq(&self.poly_meta)
            .for_each(|(poly, poly_type)| {
                debug_assert!(poly.num_vars() > 0);
                if expected_numvars_at_round == poly.num_vars()
                    && matches!(poly_type, PolyMeta::Normal)
                {
                    if !poly.is_mut() {
                        *poly = Arc::new(poly.fix_variables(&[r]));
                    } else {
                        let poly = Arc::get_mut(poly).unwrap();
                        poly.fix_variables_in_place(&[r])
                    }
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
            return (
                IOPProof::default(),
                IOPProverState {
                    poly,
                    ..Default::default()
                },
            );
        }
        let start = entered_span!("sum check prove");

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
            prover_state.push_challenges(vec![p]);
            // fix last challenge to collect final evaluation
            prover_state.fix_var_parallel(p.elements);
        };
        exit_span!(span);

        exit_span!(start);
        (
            IOPProof {
                proofs: prover_msgs,
            },
            prover_state,
        )
    }

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    pub(crate) fn prover_init_parallel(polynomial: VirtualPolynomial<'a, E>) -> Self {
        let start = entered_span!("sum check prover init");
        assert_ne!(
            polynomial.aux_info.max_num_variables, 0,
            "Attempt to prove a constant."
        );

        let num_polys = polynomial.flattened_ml_extensions.len();
        let poly_meta = vec![PolyMeta::Normal; num_polys];
        let prover_state = Self {
            is_main_worker: true,
            max_num_variables: polynomial.aux_info.max_num_variables,
            challenges: Vec::with_capacity(polynomial.aux_info.max_num_variables),
            round: 0,
            poly: polynomial,
            poly_meta,
            phase2_numvar: None,
        };

        exit_span!(start);
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
        let start = entered_span!("sum check prove {}-th round and update state", self.round);

        assert!(
            self.round < self.poly.aux_info.max_num_variables,
            "Prover is not active"
        );

        // let fix_argument = entered_span!("fix argument");

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
        if self.round > 0 {
            assert!(challenge.is_some(), "verifier message is empty");
            let chal = challenge.unwrap();
            self.challenges.push(chal);
            let r = self.challenges.last().unwrap();
            self.fix_var_parallel(r.elements);
        }
        exit_span!(span);

        self.round += 1;

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        let span = entered_span!("build_uni_poly");
        let AdditiveVec(uni_polys) = self
            .poly
            .products
            .par_iter()
            .fold_with(
                AdditiveVec::new(self.poly.aux_info.max_degree + 1),
                |mut uni_polys, MonomialTerms { terms }| {
                    for Term {
                        scalar,
                        product: prod,
                    } in terms
                    {
                        let f = &self.poly.flattened_ml_extensions;
                        let f_type = &self.poly_meta;
                        let get_poly_meta = || f_type[prod[0]];
                        let mut uni_variate: Vec<E> =
                            vec![E::ZERO; self.poly.aux_info.max_degree + 1];
                        let uni_variate_monomial: Vec<E> = match prod.len() {
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
                            6 => sumcheck_code_gen!(6, true, |i| &f[prod[i]], || get_poly_meta())
                                .to_vec(),
                            _ => unimplemented!("do not support degree {} > 6", prod.len()),
                        };
                        uni_variate
                            .iter_mut()
                            .zip(uni_variate_monomial)
                            .take(prod.len() + 1)
                            .for_each(|(eval, monimial_eval,)| either::for_both!(scalar, scalar => *eval = monimial_eval**scalar));


                        if prod.len() < self.poly.aux_info.max_degree {
                            // Perform extrapolation using the precomputed extrapolation table
                            extrapolate_from_table(&mut uni_variate, prod.len() + 1);
                        }
                        uni_polys += AdditiveVec(uni_variate);
                    }
                    uni_polys
                },
            )
            .reduce_with(|acc, item| acc + item)
            .unwrap();
        exit_span!(span);

        exit_span!(start);

        IOPProverMessage {
            evaluations: uni_polys,
        }
    }

    /// fix_var
    pub fn fix_var_parallel(&mut self, r: E) {
        let expected_numvars_at_round = self.expected_numvars_at_round();
        self.poly
            .flattened_ml_extensions
            .par_iter_mut()
            .for_each(|poly| {
                assert!(poly.num_vars() > 0);
                if expected_numvars_at_round == poly.num_vars() {
                    if !poly.is_mut() {
                        *poly = Arc::new(poly.fix_variables_parallel(&[r]));
                    } else {
                        let poly = Arc::get_mut(poly).unwrap();
                        poly.fix_variables_in_place_parallel(&[r])
                    }
                }
            });
    }
}

impl<E: ExtensionField> IOPProverState<'_, E> {
    pub fn push_challenges(&mut self, challenge: Vec<Challenge<E>>) {
        self.challenges.extend(challenge)
    }

    pub fn collect_raw_challenges(&self) -> Vec<E> {
        self.challenges
            .iter()
            .map(|challenge| challenge.elements)
            .collect()
    }
}
