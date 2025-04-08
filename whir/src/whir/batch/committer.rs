use crate::{
    crypto::{Digest, DigestExt, MerkleTree, write_digest_to_transcript},
    error::Error,
    ntt::expand_from_coeff_rmm,
    utils::{self, evaluate_as_multilinear_evals, interpolate_over_boolean_hypercube_rmm},
    whir::{
        committer::Committer,
        fold::{expand_from_univariate, restructure_evaluations_mut_rmm},
        verifier::WhirCommitmentInTranscript,
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use p3::{
    matrix::{Matrix, dense::RowMajorMatrix},
    util::log2_strict_usize,
};
use sumcheck::macros::{entered_span, exit_span};
use transcript::{BasicTranscript, Transcript};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug)]
pub struct Witnesses<E: ExtensionField> {
    pub(crate) polys: Vec<Vec<E::BaseField>>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTree<E>,
    pub(crate) root: Digest<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

impl<E: ExtensionField> Witnesses<E> {
    pub fn merkle_tree(&self) -> &MerkleTree<E> {
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
    DigestExt<E>: IntoIterator<Item = E::BaseField> + PartialEq,
{
    pub fn batch_commit(
        &self,
        mut rmm: witness::RowMajorMatrix<E::BaseField>,
    ) -> Result<(Witnesses<E>, WhirCommitmentInTranscript<E>), Error> {
        let num_polys = rmm.width();
        let mut transcript = BasicTranscript::<E>::new(b"commitment");
        let timer = entered_span!("Batch Commit");
        let prepare_timer = entered_span!("Prepare");
        let polys: Vec<Vec<E::BaseField>> = rmm.to_cols_base::<E>();
        exit_span!(prepare_timer);
        let expansion = self.0.starting_domain.size() / polys[0].len();
        let interpolate_timer = entered_span!("Interpolate over hypercube rmm");
        interpolate_over_boolean_hypercube_rmm(&mut rmm);
        exit_span!(interpolate_timer);
        let expand_timer = entered_span!("Batch Expand");
        let mut rmm: witness::RowMajorMatrix<E::BaseField> =
            expand_from_coeff_rmm::<E::BaseField>(rmm, expansion);
        exit_span!(expand_timer);
        let stack_timer = entered_span!("Stack evaluations");
        utils::stack_evaluations_mut_rmm(&mut rmm, self.0.folding_factor.at_round(0));
        exit_span!(stack_timer);
        let restructure_timer = entered_span!("Restructure evaluations");
        let domain_gen_inverse = self.0.starting_domain.base_domain_group_gen_inv();
        restructure_evaluations_mut_rmm(
            &mut rmm,
            self.0.fold_optimisation,
            domain_gen_inverse,
            self.0.folding_factor.at_round(0),
        );
        exit_span!(restructure_timer);

        let merkle_build_timer = entered_span!("Build Merkle Tree");

        let fold_size = 1 << self.0.folding_factor.at_round(0);
        let (root, merkle_tree) = self.0.hash_params.commit_matrix_base(RowMajorMatrix::new(
            rmm.into_inner().values,
            fold_size * num_polys,
        ));
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
