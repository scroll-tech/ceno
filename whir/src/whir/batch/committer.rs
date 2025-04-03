use crate::{
    crypto::{Digest, MerkleTreeExt, write_digest_to_transcript},
    error::Error,
    ntt::expand_from_coeff_rmm,
    utils::{self, evaluate_as_multilinear_evals, interpolate_over_boolean_hypercube_rmm},
    whir::{
        committer::Committer,
        fold::{expand_from_univariate, restructure_evaluations_mut},
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
        let interpolate_timer = entered_span!("Interpolate over hypercube rmm");
        interpolate_over_boolean_hypercube_rmm(&mut rmm);
        exit_span!(interpolate_timer);
        let expand_timer = entered_span!("Batch Expand");
        let rmm = expand_from_coeff_rmm(rmm, expansion);
        exit_span!(expand_timer);
        let transpose_timer = entered_span!("Transpose rmm");
        let mut rmm = rmm.transpose();
        exit_span!(transpose_timer);
        let domain_gen_inverse = self.0.starting_domain.base_domain_group_gen_inv();
        let restructure_timer = entered_span!("Restructure rmm");
        rmm.par_rows_mut().for_each(|row| {
            utils::stack_evaluations_mut(row, self.0.folding_factor.at_round(0));
            restructure_evaluations_mut(
                row,
                self.0.fold_optimisation,
                domain_gen_inverse,
                self.0.folding_factor.at_round(0),
            );
        });
        exit_span!(restructure_timer);
        let transpose_timer = entered_span!("Transpose rmm");
        let rmm = rmm.transpose();
        exit_span!(transpose_timer);

        let to_ext_timer = entered_span!("Transform rmm to extension field");
        let rmm = rmm
            .values
            .par_iter()
            .map(|x| E::from_base(x))
            .collect::<Vec<_>>();
        exit_span!(to_ext_timer);

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);

        let merkle_build_timer = entered_span!("Build Merkle Tree");

        let rmm = RowMajorMatrix::new(rmm, num_polys * fold_size);

        let (root, merkle_tree) = self.0.hash_params.commit_matrix(rmm);
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
