use crate::{
    crypto::{Digest, MerkleTreeExt, write_digest_to_transcript},
    error::Error,
    ntt::expand_from_coeff_rmm,
    utils::{self, evaluate_as_multilinear_evals, interpolate_over_boolean_hypercube_rmm},
    whir::{
        committer::Committer,
        fold::{expand_from_univariate, restructure_evaluations},
        verifier::WhirCommitmentInTranscript,
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use p3::{commit::Mmcs, matrix::dense::RowMajorMatrix, util::log2_strict_usize};
use sumcheck::macros::{entered_span, exit_span};
use transcript::{BasicTranscript, Transcript};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug)]
pub struct Witnesses<E: ExtensionField> {
    pub(crate) polys: Vec<Vec<E>>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTreeExt<E>,
    pub(crate) root: Digest<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

impl<E: ExtensionField> Witnesses<E> {
    pub fn merkle_tree(&self) -> &MerkleTreeExt<E> {
        &self.merkle_tree
    }

    pub fn root(&self) -> Digest<E> {
        self.root.clone()
    }

    pub fn to_commitment_in_transcript(&self) -> WhirCommitmentInTranscript<E> {
        WhirCommitmentInTranscript {
            root: self.root(),
            ood_points: self.ood_points.clone(),
            ood_answers: self.ood_answers.clone(),
        }
    }

    pub fn num_vars(&self) -> usize {
        log2_strict_usize(self.polys[0].len())
    }
}

impl<E: ExtensionField> Committer<E>
where
    Digest<E>: IntoIterator<Item = E::BaseField> + PartialEq,
{
    pub fn batch_commit(
        &self,
        mut rmm: witness::RowMajorMatrix<E::BaseField>,
    ) -> Result<(Witnesses<E>, WhirCommitmentInTranscript<E>), Error> {
        let mut transcript = BasicTranscript::<E>::new(b"commitment");
        let timer = entered_span!("Batch Commit");
        let prepare_timer = entered_span!("Prepare");
        let polys = rmm.to_cols_ext();
        let num_polys = polys.len();
        exit_span!(prepare_timer);
        let expansion = self.0.starting_domain.size() / polys[0].len();
        let expand_timer = entered_span!("Batch Expand");
        interpolate_over_boolean_hypercube_rmm(&mut rmm);
        let rmm = expand_from_coeff_rmm(rmm, expansion);
        let polys_for_commit = rmm.to_cols_ext();
        let domain_gen_inverse = self.0.starting_domain.backing_domain_group_gen().inverse();
        let evals = polys_for_commit
            .into_par_iter()
            .flat_map(|evals| {
                let ret = utils::stack_evaluations(evals, self.0.folding_factor.at_round(0));
                let ret = restructure_evaluations(
                    ret,
                    self.0.fold_optimisation,
                    domain_gen_inverse,
                    self.0.folding_factor.at_round(0),
                );
                ret
            })
            .collect::<Vec<_>>();
        exit_span!(expand_timer);

        // These stacking operations are bottleneck of the commitment process.
        // Try to finish the tasks with as few allocations as possible.
        let mut buffer = Vec::with_capacity(evals.len());
        #[allow(clippy::uninit_vec)]
        unsafe {
            buffer.set_len(evals.len());
        }
        let horizontal_stacking_timer = entered_span!("Stacking again");
        let folded_evals = super::utils::stack_evaluations(evals, num_polys, buffer.as_mut_slice());
        exit_span!(horizontal_stacking_timer);

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        let merkle_build_timer = entered_span!("Build Merkle Tree");

        let (root, merkle_tree) = {
            let rmm = RowMajorMatrix::new(folded_evals, fold_size * num_polys);
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
                        evaluate_as_multilinear_evals(
                            poly,
                            &expand_from_univariate(*ood_point, self.0.mv_parameters.num_variables),
                        )
                    })
                })
                .collect::<Vec<_>>();
            #[cfg(not(feature = "parallel"))]
            let ood_answers = ood_points
                .iter()
                .flat_map(|ood_point| {
                    mles.iter().map(|poly| {
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

        exit_span!(timer);

        let commitment = WhirCommitmentInTranscript {
            root: root.clone(),
            ood_points: ood_points.clone(),
            ood_answers: ood_answers.clone(),
        };
        Ok((
            Witnesses {
                polys,
                root,
                merkle_tree,
                ood_points,
                ood_answers,
            },
            commitment,
        ))
    }
}
