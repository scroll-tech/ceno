use crate::{
    crypto::{Digest, MerkleTreeExt, write_digest_to_transcript},
    error::Error,
    ntt::expand_from_coeff,
    utils::{self, interpolate_over_boolean_hypercube},
    whir::{
        committer::Committer,
        fold::{expand_from_univariate, restructure_evaluations},
        verifier::WhirCommitmentInTranscript,
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType, MultilinearExtension};
use p3::{commit::Mmcs, matrix::dense::RowMajorMatrix};
use sumcheck::macros::{entered_span, exit_span};
use transcript::{BasicTranscript, Transcript};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug)]
pub struct Witnesses<E: ExtensionField> {
    pub(crate) polys: Vec<DenseMultilinearExtension<E>>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTreeExt<E>,
    pub(crate) merkle_leaves: Vec<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

impl<E: ExtensionField> Witnesses<E> {
    pub fn merkle_tree(&self) -> &MerkleTreeExt<E> {
        &self.merkle_tree
    }

    pub fn root(&self) -> Digest<E> {
        self.merkle_tree.root()
    }

    pub fn to_commitment_in_transcript(&self) -> WhirCommitmentInTranscript<E> {
        WhirCommitmentInTranscript {
            root: self.root(),
            ood_points: self.ood_points.clone(),
            ood_answers: self.ood_answers.clone(),
        }
    }

    pub fn num_vars(&self) -> usize {
        self.polys[0].num_vars()
    }
}

impl<E: ExtensionField> Committer<E> {
    pub fn batch_commit(
        &self,
        polys: witness::RowMajorMatrix<E::BaseField>,
    ) -> Result<(Witnesses<E>, WhirCommitmentInTranscript<E>), Error> {
        let mut transcript = BasicTranscript::<E>::new(b"commitment");
        let polys = polys.to_mles();
        let timer = entered_span!("Batch Commit");
        let expansion = self.0.starting_domain.size() / polys[0].evaluations().len();
        let expand_timer = entered_span!("Batch Expand");
        let evals = polys
            .par_iter()
            .map(|poly| {
                expand_from_coeff(
                    &match poly.evaluations() {
                        #[cfg(feature = "parallel")]
                        FieldType::Base(evals) => {
                            let mut evals = evals
                                .par_iter()
                                .map(|e| E::from_base(e))
                                .collect::<Vec<_>>();
                            interpolate_over_boolean_hypercube(&mut evals);
                            evals
                        }
                        #[cfg(not(feature = "parallel"))]
                        FieldType::Base(evals) => {
                            let mut evals =
                                evals.iter().map(|e| E::from_base(e)).collect::<Vec<_>>();
                            interpolate_over_boolean_hypercube(&mut evals);
                            evals
                        }
                        FieldType::Ext(evals) => {
                            let mut evals = evals.clone();
                            interpolate_over_boolean_hypercube(&mut evals);
                            evals
                        }
                        _ => panic!("Invalid field type"),
                    },
                    expansion,
                )
            })
            .collect::<Vec<Vec<_>>>();
        exit_span!(expand_timer);

        assert_eq!(self.0.starting_domain.size(), evals[0].len());

        // These stacking operations are bottleneck of the commitment process.
        // Try to finish the tasks with as few allocations as possible.
        let stack_evaluations_timer = entered_span!("Stack Evaluations");
        let domain_gen_inverse = self.0.starting_domain.backing_domain_group_gen().inverse();
        let domain_gen = self.0.starting_domain.backing_domain_group_gen();
        let folded_evals = evals
            .into_par_iter()
            .map(|evals| {
                let ret = utils::stack_evaluations(evals, self.0.folding_factor.at_round(0));
                ret
            })
            .flat_map(|evals| {
                let ret = restructure_evaluations(
                    evals,
                    self.0.fold_optimisation,
                    domain_gen,
                    domain_gen_inverse,
                    self.0.folding_factor.at_round(0),
                );
                ret
            })
            .collect::<Vec<_>>();
        exit_span!(stack_evaluations_timer);

        let mut buffer = Vec::with_capacity(folded_evals.len());
        #[allow(clippy::uninit_vec)]
        unsafe {
            buffer.set_len(folded_evals.len());
        }
        let horizontal_stacking_timer = entered_span!("Horizontal Stacking");
        let folded_evals = super::utils::horizontal_stacking(
            folded_evals,
            self.0.starting_domain.size(),
            self.0.folding_factor.at_round(0),
            buffer.as_mut_slice(),
        );
        exit_span!(horizontal_stacking_timer);

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        let merkle_build_timer = entered_span!("Build Merkle Tree");

        let (root, merkle_tree) = {
            let clone_timer = entered_span!("Clone into rmm");
            let rmm = RowMajorMatrix::new(folded_evals.clone(), fold_size * polys.len());
            exit_span!(clone_timer);
            self.0.hash_params.commit_matrix(rmm)
        };
        exit_span!(merkle_build_timer);

        write_digest_to_transcript(&root, &mut transcript);

        let ood_timer = entered_span!("Compute OOD answers");
        let (ood_points, ood_answers) = if self.0.committment_ood_samples > 0 {
            let ood_points =
                transcript.sample_and_append_vec(b"ood_points", self.0.committment_ood_samples);
            #[cfg(feature = "parallel")]
            let ood_answers = ood_points
                .par_iter()
                .flat_map(|ood_point| {
                    polys.par_iter().map(|poly| {
                        poly.evaluate(&expand_from_univariate(
                            *ood_point,
                            self.0.mv_parameters.num_variables,
                        ))
                    })
                })
                .collect::<Vec<_>>();
            #[cfg(not(feature = "parallel"))]
            let ood_answers = ood_points
                .iter()
                .flat_map(|ood_point| {
                    polys.iter().map(|poly| {
                        poly.evaluate(&expand_from_univariate(
                            *ood_point,
                            self.0.mv_parameters.num_variables,
                        ))
                    })
                })
                .collect::<Vec<_>>();
            transcript.append_field_element_exts(&ood_answers);
            (ood_points, ood_answers)
        } else {
            (
                vec![E::ZERO; self.0.committment_ood_samples],
                vec![E::ZERO; self.0.committment_ood_samples],
            )
        };
        exit_span!(ood_timer);

        let into_polys_timer = entered_span!("Into polys");
        #[cfg(feature = "parallel")]
        let polys = polys
            .into_par_iter()
            .map(|poly| {
                DenseMultilinearExtension::from_evaluations_ext_vec(
                    poly.num_vars(),
                    match poly.evaluations() {
                        FieldType::Base(evals) => evals
                            .par_iter()
                            .map(|e| E::from_base(e))
                            .collect::<Vec<_>>(),
                        FieldType::Ext(evals) => evals.clone(),
                        _ => panic!("Invalid field type"),
                    },
                )
            })
            .collect::<Vec<_>>();

        #[cfg(not(feature = "parallel"))]
        let polys = polys
            .into_iter()
            .map(|poly| {
                DenseMultilinearExtension::from_evaluations_ext_vec(
                    poly.num_vars(),
                    match poly.evaluations() {
                        FieldType::Base(evals) => {
                            evals.iter().map(|e| E::from_base(e)).collect::<Vec<_>>()
                        }
                        FieldType::Ext(evals) => evals.clone(),
                        _ => panic!("Invalid field type"),
                    },
                )
            })
            .collect::<Vec<_>>();

        exit_span!(into_polys_timer);
        exit_span!(timer);

        let commitment = WhirCommitmentInTranscript {
            root,
            ood_points: ood_points.clone(),
            ood_answers: ood_answers.clone(),
        };
        Ok((
            Witnesses {
                polys,
                merkle_tree,
                merkle_leaves: folded_evals,
                ood_points,
                ood_answers,
            },
            commitment,
        ))
    }
}
