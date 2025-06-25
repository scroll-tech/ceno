use super::{batch::Witnesses, parameters::WhirConfig};
use crate::{
    crypto::{DigestExt, write_digest_to_transcript},
    error::Error,
    ntt::expand_from_coeff,
    utils::{self, interpolate_over_boolean_hypercube},
    whir::{
        fold::{expand_from_univariate, restructure_evaluations},
        verifier::WhirCommitmentInTranscript,
    },
};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::{FieldType, MultilinearExtension};
use p3::{
    field::{Field, FieldAlgebra},
    matrix::dense::RowMajorMatrix,
};
use sumcheck::macros::{entered_span, exit_span};
use transcript::{BasicTranscript, Transcript};

pub struct Committer<E: ExtensionField>(pub(crate) WhirConfig<E>);

impl<E: ExtensionField> Committer<E>
where
    DigestExt<E>: IntoIterator<Item = E::BaseField> + PartialEq,
{
    pub fn new(config: WhirConfig<E>) -> Self {
        Self(config)
    }

    pub fn commit(
        &self,
        polynomial: MultilinearExtension<E>,
    ) -> Result<(Witnesses<E>, WhirCommitmentInTranscript<E>), Error> {
        let timer = entered_span!("Single Commit");
        let mut transcript = BasicTranscript::new(b"commitment");
        // If size of polynomial < folding factor, keep doubling polynomial size by cloning itself
        let mut evaluations: Vec<E::BaseField> = match polynomial.evaluations() {
            #[cfg(feature = "parallel")]
            FieldType::Base(evals) => evals.to_vec(),
            #[cfg(not(feature = "parallel"))]
            FieldType::Base(evals) => evals.iter().map(|x| E::from_ref_base(x)).collect(),
            FieldType::Ext(_) => panic!("Not supporting committing to ext polys"),
            _ => panic!("Unsupported field type"),
        };

        let mut coeffs = evaluations.clone();
        interpolate_over_boolean_hypercube(&mut coeffs);
        // Resize the polynomial to at least the first folding factor number of
        // variables. This is equivalent to repeating the evaluations over the
        // hypercube, and extending zero to the coefficients.
        if evaluations.len() < (1 << self.0.folding_factor.at_round(0)) {
            let original_size = evaluations.len();
            evaluations.resize(1 << self.0.folding_factor.at_round(0), E::BaseField::ZERO);
            for i in original_size..evaluations.len() {
                evaluations[i] = evaluations[i - original_size];
            }
            coeffs.extend(itertools::repeat_n(
                E::BaseField::ZERO,
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
            self.0.starting_domain.base_domain_group_gen().inverse(),
            self.0.folding_factor.at_round(0),
        );

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        let merkle_build_timer = entered_span!("Single Merkle Tree Build");
        let (root, merkle_tree) = self
            .0
            .hash_params
            .commit_matrix_base(RowMajorMatrix::new(folded_evals, fold_size));
        exit_span!(merkle_build_timer);
        write_digest_to_transcript(&root, &mut transcript);

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

        exit_span!(timer);

        let commitment = WhirCommitmentInTranscript {
            root: root.clone(),
            ood_points: ood_points.clone(),
            ood_answers: ood_answers.clone(),
        };

        Ok((
            Witnesses {
                polys: vec![evaluations],
                root,
                merkle_tree,
                ood_points,
                ood_answers,
            },
            commitment,
        ))
    }

    pub fn write_commitment_to_transcript<T: Transcript<E>>(
        &self,
        commitment: &WhirCommitmentInTranscript<E>,
        transcript: &mut T,
    ) {
        write_digest_to_transcript(&commitment.root, transcript);
        // No need to write the ood points and ood answers to transcript, because
        // they are deterministic functions of the Merkle root.
    }
}
