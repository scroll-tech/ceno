use super::{batch::Witnesses, parameters::WhirConfig};
use crate::{
    crypto::{MerkleTree, MerkleTreeExt, write_digest_to_transcript},
    end_timer,
    error::Error,
    ntt::expand_from_coeff,
    start_timer,
    utils::{self, interpolate_over_boolean_hypercube},
    whir::{
        fold::{expand_from_univariate, restructure_evaluations},
        fs_utils::MmcsCommitmentWriter,
        verifier::WhirCommitmentInTranscript,
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType, MultilinearExtension};
use p3_matrix::dense::RowMajorMatrix;
use transcript::Transcript;

use p3_commit::Mmcs;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct Committer<E: ExtensionField>(pub(crate) WhirConfig<E>);

impl<E: ExtensionField> Committer<E> {
    pub fn new(config: WhirConfig<E>) -> Self {
        Self(config)
    }

    pub fn commit<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        mut polynomial: DenseMultilinearExtension<E>,
    ) -> Result<(Witnesses<E>, WhirCommitmentInTranscript<E>), Error> {
        let timer = start_timer!(|| "Single Commit");
        // If size of polynomial < folding factor, keep doubling polynomial size by cloning itself
        let mut evaluations = match polynomial.evaluations() {
            FieldType::Base(evals) => evals.iter().map(|x| E::from_base(x)).collect(),
            FieldType::Ext(evals) => evals.clone(),
            _ => panic!("Unsupported field type"),
        };

        let mut coeffs = evaluations.clone();
        interpolate_over_boolean_hypercube(&mut coeffs);
        // Resize the polynomial to at least the first folding factor number of
        // variables. This is equivalent to repeating the evaluations over the
        // hypercube, and extending zero to the coefficients.
        if evaluations.len() < (1 << self.0.folding_factor.at_round(0)) {
            let original_size = evaluations.len();
            evaluations.resize(1 << self.0.folding_factor.at_round(0), E::ZERO);
            for i in original_size..evaluations.len() {
                evaluations[i] = evaluations[i - original_size];
            }
            coeffs.extend(itertools::repeat_n(
                E::ZERO,
                (1 << self.0.folding_factor.at_round(0)) - original_size,
            ));
        }

        let expansion = self.0.starting_domain.size() / evaluations.len();
        let evals = expand_from_coeff(&coeffs, expansion);
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals = utils::stack_evaluations(evals, self.0.folding_factor.at_round(0));
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            self.0.starting_domain.backing_domain_group_gen(),
            self.0.starting_domain.backing_domain_group_gen().inverse(),
            self.0.folding_factor.at_round(0),
        );

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        let merkle_build_timer = start_timer!(|| "Single Merkle Tree Build");
        let (root, merkle_tree) = self
            .0
            .hash_params
            .commit_matrix(RowMajorMatrix::new(folded_evals.clone(), fold_size));
        end_timer!(merkle_build_timer);
        write_digest_to_transcript(&root, transcript);

        let (ood_points, ood_answers) = if self.0.committment_ood_samples > 0 {
            let ood_points =
                transcript.sample_and_append_vec(b"ood_points", self.0.committment_ood_samples);
            let ood_answers = ood_points
                .iter()
                .map(|ood_point| {
                    polynomial.evaluate(&expand_from_univariate(*ood_point, polynomial.num_vars()))
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

        end_timer!(timer);

        let commitment = WhirCommitmentInTranscript {
            root,
            ood_points: ood_points.clone(),
            ood_answers: ood_answers.clone(),
        };

        let polynomial = DenseMultilinearExtension::from_evaluations_ext_vec(
            p3_util::log2_strict_usize(evaluations.len()),
            evaluations,
        );
        Ok((
            Witnesses {
                polys: vec![polynomial],
                merkle_tree,
                merkle_leaves: folded_evals,
                ood_points,
                ood_answers,
            },
            commitment,
        ))
    }
}
