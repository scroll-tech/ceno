use super::parameters::WhirConfig;
use crate::{
    crypto::{MerkleConfig as Config, MerkleTree},
    end_timer,
    error::Error,
    ntt::expand_from_coeff,
    start_timer, utils,
    whir::{
        fold::{expand_from_univariate, restructure_evaluations},
        fs_utils::MmcsCommitmentWriter,
        verifier::WhirCommitmentInTranscript,
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::{DenseMultilinearExtension, MultilinearExtension};
use transcript::Transcript;

use p3_commit::Mmcs;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct Witness<E: ExtensionField, MerkleConfig>
where
    MerkleConfig: Config<E>,
{
    pub(crate) polynomial: DenseMultilinearExtension<E>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTree<E, MerkleConfig>,
    pub(crate) merkle_leaves: Vec<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

pub struct Committer<E, MerkleConfig>(pub(crate) WhirConfig<E, MerkleConfig>)
where
    E: ExtensionField,
    MerkleConfig: Config<E>;

impl<E, MerkleConfig> Committer<E, MerkleConfig>
where
    E: ExtensionField,
    MerkleConfig: Config<E>,
{
    pub fn new(config: WhirConfig<E, MerkleConfig>) -> Self {
        Self(config)
    }

    pub fn commit<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        mut polynomial: DenseMultilinearExtension<E>,
    ) -> Result<
        (
            Witness<E, MerkleConfig>,
            WhirCommitmentInTranscript<E, MerkleConfig>,
        ),
        Error,
    > {
        let timer = start_timer!(|| "Single Commit");
        // If size of polynomial < folding factor, keep doubling polynomial size by cloning itself
        polynomial.pad_to_num_vars(self.0.folding_factor.at_round(0));

        let base_domain = self.0.starting_domain.base_domain.unwrap();
        let expansion = self.0.starting_domain.size() / polynomial.evaluations().len();
        let evals = expand_from_coeff(polynomial.evaluations(), expansion);
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals = utils::stack_evaluations(evals, self.0.folding_factor.at_round(0));
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            self.0.starting_domain.base_domain_group_gen(),
            self.0.starting_domain.base_domain_group_gen().inverse(),
            self.0.folding_factor.at_round(0),
        );

        // Convert to extension field.
        // This is not necessary for the commit, but in further rounds
        // we will need the extension field. For symplicity we do it here too.
        // TODO: Commit to base field directly.
        let folded_evals = folded_evals
            .into_iter()
            .map(E::from_base_prime_field)
            .collect::<Vec<_>>();

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        #[cfg(not(feature = "parallel"))]
        let leafs_iter = folded_evals.chunks_exact(fold_size);
        #[cfg(feature = "parallel")]
        let leafs_iter = folded_evals.par_chunks_exact(fold_size);

        let merkle_build_timer = start_timer!(|| "Single Merkle Tree Build");
        let merkle_tree = MerkleTree::<MerkleConfig>::new(
            &self.0.leaf_hash_params,
            &self.0.two_to_one_params,
            leafs_iter,
        )
        .unwrap();
        end_timer!(merkle_build_timer);

        let root = merkle_tree.root();

        transcript.add_digest(root)?;

        let mut ood_points = vec![E::ZERO; self.0.committment_ood_samples];
        let mut ood_answers = Vec::with_capacity(self.0.committment_ood_samples);
        if self.0.committment_ood_samples > 0 {
            transcript.fill_challenge_scalars(&mut ood_points)?;
            ood_answers.extend(ood_points.iter().map(|ood_point| {
                polynomial.evaluate_at_extension(&expand_from_univariate(
                    *ood_point,
                    self.0.mv_parameters.num_variables,
                ))
            }));
            transcript.add_scalars(&ood_answers)?;
        }

        end_timer!(timer);

        let commitment = WhirCommitmentInTranscript {
            root,
            ood_points,
            ood_answers,
        };

        Ok((
            Witness {
                polynomial: polynomial.to_extension(),
                merkle_tree,
                merkle_leaves: folded_evals,
                ood_points,
                ood_answers,
            },
            commitment,
        ))
    }
}
