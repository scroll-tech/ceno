use crate::{
    basefold_verifier::query_phase::{QueryPhaseVerifierInputVariable, batch_verifier_query_phase},
    transcript::{transcript_check_pow_witness, transcript_observe_label},
};

use super::{basefold::*, rs::*, utils::*};
use ff_ext::BabyBearExt4;
use openvm_native_compiler::{asm::AsmConfig, ir::FromConstant, prelude::*};
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::challenger::{
    CanObserveDigest, CanObserveVariable, CanSampleBitsVariable, FeltChallenger,
    duplex::DuplexChallengerVariable,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::FieldAlgebra;

pub type F = BabyBear;
pub type E = BabyBearExt4;
pub type InnerConfig = AsmConfig<F, E>;

pub fn batch_verify<C: Config>(
    builder: &mut Builder<C>,
    max_num_var: Var<C::N>,
    max_width: Var<C::N>,
    rounds: Array<C, RoundVariable<C>>,
    proof: BasefoldProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) {
    builder.cycle_tracker_start("prior query phase");

    builder.assert_nonzero(&proof.final_message.len());
    builder.assert_nonzero(&proof.sumcheck_proof.len());

    // we don't support early stopping for now
    iter_zip!(builder, proof.final_message).for_each(|ptr_vec, builder| {
        let final_message_len = builder.iter_ptr_get(&proof.final_message, ptr_vec[0]).len();
        builder.assert_eq::<Usize<C::N>>(
            final_message_len,
            Usize::from(1 << get_basecode_msg_size_log()),
        );
    });

    builder.assert_eq::<Usize<C::N>>(
        proof.query_opening_proof.len(),
        Usize::from(get_num_queries()),
    );

    // Compute the total number of polynomials across all rounds
    let total_num_polys: Var<C::N> = builder.constant(C::N::ZERO);
    iter_zip!(builder, rounds).for_each(|ptr_vec, builder| {
        let openings = builder.iter_ptr_get(&rounds, ptr_vec[0]).openings;
        iter_zip!(builder, openings).for_each(|ptr_vec_openings, builder| {
            let evals_num = builder
                .iter_ptr_get(&openings, ptr_vec_openings[0])
                .point_and_evals
                .evals
                .len();
            builder.assign(&total_num_polys, total_num_polys + evals_num);
        });
    });

    // get batch coeffs
    transcript_observe_label(builder, challenger, b"batch coeffs");
    let batch_coeff = challenger.sample_ext(builder);
    let running_coeff =
        <Ext<C::F, C::EF> as FromConstant<C>>::constant(C::EF::from_canonical_usize(1), builder);
    let batch_coeffs: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(total_num_polys);

    iter_zip!(builder, batch_coeffs).for_each(|ptr_vec_batch_coeffs, builder| {
        builder.iter_ptr_set(&batch_coeffs, ptr_vec_batch_coeffs[0], running_coeff);
        builder.assign(&running_coeff, running_coeff * batch_coeff);
    });

    // The max num var and max width are provided by the prover and not guaranteed to be correct.
    // Check that
    //  1. max_num_var is greater than or equal to every num var (same for width);
    //  2. it is equal to at least one of the num vars by multiplying all the differences
    //      together and assert the product is zero (same for width).
    let diff_product_num_var: Var<C::N> = builder.eval(Usize::from(1));
    let diff_product_width: Var<C::N> = builder.eval(Usize::from(1));
    iter_zip!(builder, rounds).for_each(|ptr_vec, builder| {
        let round = builder.iter_ptr_get(&rounds, ptr_vec[0]);

        iter_zip!(builder, round.openings).for_each(|ptr_vec_opening, builder| {
            let opening = builder.iter_ptr_get(&round.openings, ptr_vec_opening[0]);
            let diff: Var<C::N> = builder.eval(max_num_var - opening.num_var);
            // num_var is always smaller than 32.
            builder.range_check_var(diff, 5);
            builder.assign(&diff_product_num_var, diff_product_num_var * diff);

            let diff: Var<C::N> = builder.eval(max_width - opening.point_and_evals.evals.len());
            // width is always smaller than 2^14.
            builder.range_check_var(diff, 14);
            builder.assign(&diff_product_width, diff_product_width * diff);
        });
    });
    // Check that at least one num_var is equal to max_num_var
    let zero: Var<C::N> = builder.eval(C::N::ZERO);
    builder.assert_eq::<Var<C::N>>(diff_product_num_var, zero);
    builder.assert_eq::<Var<C::N>>(diff_product_width, zero);

    let num_rounds: Var<C::N> =
        builder.eval(max_num_var - Usize::from(get_basecode_msg_size_log()));

    let fold_challenges: Array<C, Ext<_, _>> = builder.dyn_array(max_num_var);
    builder.range(0, num_rounds).for_each(|index_vec, builder| {
        let sumcheck_message = builder.get(&proof.sumcheck_proof, index_vec[0]).evaluations;
        iter_zip!(builder, sumcheck_message).for_each(|ptr_vec_sumcheck_message, builder| {
            let elem = builder.iter_ptr_get(&sumcheck_message, ptr_vec_sumcheck_message[0]);
            let elem_felts = builder.ext2felt(elem);
            challenger.observe_slice(builder, elem_felts);
        });

        transcript_observe_label(builder, challenger, b"commit round");
        let challenge = challenger.sample_ext(builder);
        builder.set(&fold_challenges, index_vec[0], challenge);
        builder
            .if_ne(index_vec[0], num_rounds - Usize::from(1))
            .then(|builder| {
                let commit = builder.get(&proof.commits, index_vec[0]);
                challenger.observe_digest(builder, commit.value.into());
            });
    });

    iter_zip!(builder, proof.final_message).for_each(|ptr_vec_sumcheck_message, builder| {
        // Each final message should contain a single element, since the final
        // message size log is assumed to be zero
        let elems = builder.iter_ptr_get(&proof.final_message, ptr_vec_sumcheck_message[0]);
        let elem = builder.get(&elems, 0);
        let elem_felts = builder.ext2felt(elem);
        challenger.observe_slice(builder, elem_felts);
    });

    transcript_check_pow_witness(builder, challenger, 16, proof.pow_witness); // TODO: avoid hardcoding pow bits
    transcript_observe_label(builder, challenger, b"query indices");
    let queries: Array<C, Var<C::N>> = builder.dyn_array(get_num_queries());
    builder
        .range(0, get_num_queries())
        .for_each(|index_vec, builder| {
            let number_of_bits = builder.eval_expr(max_num_var + Usize::from(get_rate_log()));
            let query = challenger.sample_bits(builder, number_of_bits);
            // TODO: the index will need to be split back to bits in query phase, so it's
            // probably better to avoid converting bits to integer altogether
            let number_of_bits = builder.eval(max_num_var + Usize::from(get_rate_log()));
            let query = bin_to_dec_le(builder, &query, zero, number_of_bits);
            builder.set(&queries, index_vec[0], query);
        });

    let input = QueryPhaseVerifierInputVariable {
        max_num_var: builder.eval(max_num_var),
        max_width: builder.eval(max_width),
        batch_coeffs,
        fold_challenges,
        indices: queries,
        proof,
        rounds,
    };
    builder.cycle_tracker_end("prior query phase");
    builder.cycle_tracker_start("query phase");
    batch_verifier_query_phase(builder, input);
    builder.cycle_tracker_end("query phase");
}

#[cfg(test)]
pub mod tests {
    use std::{cmp::Reverse, collections::BTreeMap, iter::once};

    use ff_ext::{BabyBearExt4, FromUniformBytes};
    use itertools::Itertools;
    use mpcs::{
        BasefoldDefault, BasefoldRSParams, BasefoldSpec, PCSFriParam, PolynomialCommitmentScheme,
        pcs_batch_commit, pcs_setup, pcs_trim, util::hash::write_digest_to_transcript,
    };
    use multilinear_extensions::mle::MultilinearExtension;
    use openvm_circuit::arch::{SystemConfig, VmExecutor, instructions::program::Program};
    use openvm_native_circuit::{Native, NativeConfig};
    use openvm_native_compiler::{asm::AsmBuilder, conversion::CompilerOptions};
    use openvm_native_recursion::{challenger::duplex::DuplexChallengerVariable, hints::Hintable};
    use openvm_stark_backend::p3_challenger::GrindingChallenger;
    use openvm_stark_sdk::{config::baby_bear_poseidon2::Challenger, p3_baby_bear::BabyBear};
    use p3::field::{Field, FieldAlgebra};
    use rand::thread_rng;
    use serde::Deserialize;
    use transcript::{BasicTranscript, Transcript};

    type F = BabyBear;
    type E = BabyBearExt4;
    type PCS = BasefoldDefault<E>;

    use super::{BasefoldProof, BasefoldProofVariable, InnerConfig, RoundVariable, batch_verify};
    use crate::{
        basefold_verifier::{
            basefold::{BasefoldCommitment, Round, RoundOpening},
            query_phase::{BatchOpening, CommitPhaseProofStep, PointAndEvals, QueryOpeningProof},
        },
        tower_verifier::binding::{Point, PointAndEval},
    };
    use openvm_native_compiler::{asm::AsmConfig, prelude::*};

    #[derive(Deserialize)]
    pub struct VerifierInput {
        pub max_num_var: usize,
        pub max_width: usize,
        pub proof: BasefoldProof,
        pub rounds: Vec<Round>,
    }

    impl Hintable<InnerConfig> for VerifierInput {
        type HintVariable = VerifierInputVariable<InnerConfig>;

        fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
            let max_num_var = usize::read(builder);
            let max_width = usize::read(builder);
            let proof = BasefoldProof::read(builder);
            let rounds = Vec::<Round>::read(builder);

            VerifierInputVariable {
                max_num_var,
                max_width,
                proof,
                rounds,
            }
        }

        fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
            let mut stream = Vec::new();
            stream.extend(<usize as Hintable<InnerConfig>>::write(&self.max_num_var));
            stream.extend(<usize as Hintable<InnerConfig>>::write(&self.max_width));
            stream.extend(self.proof.write());
            stream.extend(self.rounds.write());
            stream
        }
    }

    #[derive(DslVariable, Clone)]
    pub struct VerifierInputVariable<C: Config> {
        pub max_num_var: Var<C::N>,
        pub max_width: Var<C::N>,
        pub proof: BasefoldProofVariable<C>,
        pub rounds: Array<C, RoundVariable<C>>,
    }

    #[allow(dead_code)]
    pub fn build_batch_verifier(input: VerifierInput) -> (Program<BabyBear>, Vec<Vec<BabyBear>>) {
        // build test program
        let mut builder = AsmBuilder::<F, E>::default();
        builder.cycle_tracker_start("Prepare data");
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let verifier_input = VerifierInput::read(&mut builder);
        builder.cycle_tracker_end("Prepare data");
        batch_verify(
            &mut builder,
            verifier_input.max_num_var,
            verifier_input.max_width,
            verifier_input.rounds,
            verifier_input.proof,
            &mut challenger,
        );
        builder.halt();
        let program = builder.compile_isa_with_options(CompilerOptions {
            enable_cycle_tracker: true,
            ..Default::default()
        });

        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(input.write());

        (program, witness_stream)
    }

    fn construct_test(dimensions: Vec<Vec<(usize, usize)>>) {
        let mut rng = thread_rng();

        // setup PCS
        let pp = PCS::setup(1 << 22, mpcs::SecurityLevel::Conjecture100bits).unwrap();
        let (pp, vp) = pcs_trim::<E, PCS>(pp, 1 << 22).unwrap();

        let rounds = dimensions
            .iter()
            .map(|dimensions| {
                let mut num_total_polys = 0;
                let (matrices, mles): (Vec<_>, Vec<_>) = dimensions
                    .into_iter()
                    .map(|(num_vars, width)| {
                        let m = witness::RowMajorMatrix::<F>::rand(&mut rng, 1 << num_vars, *width);
                        let mles = m.to_mles();
                        num_total_polys += width;

                        (m, mles)
                    })
                    .unzip();

                // commit to matrices
                let pcs_data = pcs_batch_commit::<E, PCS>(&pp, matrices).unwrap();

                let point_and_evals = mles
                    .iter()
                    .map(|mles| {
                        let point = E::random_vec(mles[0].num_vars(), &mut rng);
                        let evals = mles.iter().map(|mle| mle.evaluate(&point)).collect_vec();

                        (point, evals)
                    })
                    .collect_vec();
                (pcs_data, point_and_evals.clone())
            })
            .collect_vec();

        let prover_rounds = rounds
            .iter()
            .map(|(comm, other)| (comm, other.clone()))
            .collect_vec();

        let max_num_var = rounds
            .iter()
            .map(|round| round.1.iter().map(|(point, _)| point.len()).max().unwrap())
            .max()
            .unwrap();
        let max_width = rounds
            .iter()
            .map(|round| round.1.iter().map(|(_, evals)| evals.len()).max().unwrap())
            .max()
            .unwrap();

        let verifier_rounds = rounds
            .iter()
            .map(|round| {
                (
                    PCS::get_pure_commitment(&round.0),
                    round
                        .1
                        .iter()
                        .map(|(point, evals)| (point.len(), (point.clone(), evals.clone())))
                        .collect_vec(),
                )
            })
            .collect_vec();

        // batch open
        let mut transcript = BasicTranscript::<E>::new(&[]);
        let opening_proof = PCS::batch_open(&pp, prover_rounds, &mut transcript).unwrap();

        // batch verify
        let mut transcript = BasicTranscript::<E>::new(&[]);
        PCS::batch_verify(
            &vp,
            verifier_rounds.clone(),
            &opening_proof,
            &mut transcript,
        )
        .expect("Native verification failed");

        let verifier_input = VerifierInput {
            max_num_var,
            max_width,
            rounds: verifier_rounds
                .into_iter()
                .map(|(commit, openings)| Round {
                    commit: commit.into(),
                    openings: openings
                        .into_iter()
                        .map(|(num_var, (point, evals))| RoundOpening {
                            num_var,
                            point_and_evals: PointAndEvals {
                                point: Point { fs: point },
                                evals,
                            },
                        })
                        .collect(),
                })
                .collect(),
            proof: opening_proof.into(),
        };

        let (program, witness) = build_batch_verifier(verifier_input);

        let system_config = SystemConfig::default()
            .with_public_values(4)
            .with_max_segment_len((1 << 25) - 100)
            .with_profiling();
        let config = NativeConfig::new(system_config, Native);

        let executor = VmExecutor::<BabyBear, NativeConfig>::new(config);
        executor.execute(program.clone(), witness.clone()).unwrap();

        let results = executor.execute_segments(program, witness).unwrap();
        for seg in results {
            println!("=> cycle count: {:?}", seg.metrics.cycle_count);
        }
    }

    #[test]
    fn test_simple_batch() {
        for num_var in 5..20 {
            construct_test(vec![vec![(num_var, 20)]]);
        }
    }

    #[test]
    fn test_decreasing_batch() {
        construct_test(vec![vec![
            (14, 20),
            (14, 40),
            (13, 30),
            (12, 30),
            (11, 10),
            (10, 15),
        ]]);
    }

    #[test]
    fn test_random_batch() {
        construct_test(vec![vec![(10, 20), (12, 30), (11, 10), (12, 15)]]);
    }

    #[test]
    fn test_e2e_fibonacci_batch() {
        construct_test(vec![
            vec![
                (22, 22),
                (22, 18),
                (1, 28),
                (2, 24),
                (3, 18),
                (1, 21),
                (4, 19),
                (21, 18),
                (1, 8),
                (1, 11),
                (4, 22),
                (3, 27),
                (5, 22),
                (16, 1),
                (16, 1),
                (16, 1),
                (5, 1),
                (16, 1),
                (1, 28),
                (9, 1),
                (3, 2),
                (3, 1),
                (5, 2),
                (10, 2),
                (6, 3),
                (14, 1),
                (16, 1),
                (5, 1),
                (8, 1),
                (4, 29),
                (1, 29),
                (1, 18),
                (1, 23),
                (21, 20),
                (21, 22),
                (5, 22),
            ],
            vec![
                (16, 3),
                (16, 3),
                (16, 3),
                (5, 3),
                (16, 3),
                (9, 6),
                (3, 1),
                (10, 2),
                (6, 3),
            ],
        ]);
    }
}
