use crate::{
    crypto::{MerkleConfig as Config, MerkleTree},
    end_timer,
    error::Error,
    ntt::expand_from_coeff,
    start_timer, utils,
    whir::{
        committer::{Committer, Witness},
        fold::{expand_from_univariate, restructure_evaluations},
    },
};
use derive_more::Debug;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use transcript::Transcript;

use crate::whir::fs_utils::MmcsCommitmentWriter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct Witnesses<E: ExtensionField, MerkleConfig>
where
    MerkleConfig: Config<E>,
{
    pub(crate) polys: Vec<DenseMultilinearExtension<E>>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTree<E, MerkleConfig>,
    pub(crate) merkle_leaves: Vec<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

impl<E: ExtensionField, MerkleConfig: Config<E>> From<Witness<E, MerkleConfig>>
    for Witnesses<E, MerkleConfig>
{
    fn from(witness: Witness<E, MerkleConfig>) -> Self {
        Self {
            polys: vec![witness.polynomial],
            merkle_tree: witness.merkle_tree,
            merkle_leaves: witness.merkle_leaves,
            ood_points: witness.ood_points,
            ood_answers: witness.ood_answers,
        }
    }
}

impl<E: ExtensionField, MerkleConfig: Config<E>> From<Witnesses<E, MerkleConfig>>
    for Witness<E, MerkleConfig>
{
    fn from(witness: Witnesses<E, MerkleConfig>) -> Self {
        Self {
            polynomial: witness.polys[0].clone(),
            merkle_tree: witness.merkle_tree,
            merkle_leaves: witness.merkle_leaves,
            ood_points: witness.ood_points,
            ood_answers: witness.ood_answers,
        }
    }
}

impl<E, MerkleConfig> Committer<E, MerkleConfig>
where
    E: ExtensionField,
    MerkleConfig: Config<E>,
{
    pub fn batch_commit<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Witnesses<E, MerkleConfig>, Error> {
        let timer = start_timer!(|| "Batch Commit");
        let base_domain = self.0.starting_domain.base_domain.unwrap();
        let expansion = base_domain.size() / polys[0].num_coeffs();
        let expand_timer = start_timer!(|| "Batch Expand");
        let evals = polys
            .par_iter()
            .map(|poly| expand_from_coeff(poly.coeffs(), expansion))
            .collect::<Vec<Vec<_>>>();
        end_timer!(expand_timer);

        assert_eq!(base_domain.size(), evals[0].len());

        // These stacking operations are bottleneck of the commitment process.
        // Try to finish the tasks with as few allocations as possible.
        let stack_evaluations_timer = start_timer!(|| "Stack Evaluations");
        let folded_evals = evals
            .into_par_iter()
            .map(|evals| {
                let sub_stack_evaluations_timer = start_timer!(|| "Sub Stack Evaluations");
                let ret = utils::stack_evaluations(evals, self.0.folding_factor.at_round(0));
                end_timer!(sub_stack_evaluations_timer);
                ret
            })
            .map(|evals| {
                let restructure_evaluations_timer = start_timer!(|| "Restructure Evaluations");
                let ret = restructure_evaluations(
                    evals,
                    self.0.fold_optimisation,
                    base_domain.group_gen(),
                    base_domain.group_gen_inv(),
                    self.0.folding_factor.at_round(0),
                );
                end_timer!(restructure_evaluations_timer);
                ret
            })
            .flat_map(|evals| evals.into_par_iter().map(E::from_base_prime_field))
            .collect::<Vec<_>>();
        end_timer!(stack_evaluations_timer);

        let allocate_timer = start_timer!(|| "Allocate buffer.");

        let mut buffer = Vec::with_capacity(folded_evals.len());
        #[allow(clippy::uninit_vec)]
        unsafe {
            buffer.set_len(folded_evals.len());
        }
        end_timer!(allocate_timer);
        let horizontal_stacking_timer = start_timer!(|| "Horizontal Stacking");
        let folded_evals = super::utils::horizontal_stacking(
            folded_evals,
            base_domain.size(),
            self.0.folding_factor.at_round(0),
            buffer.as_mut_slice(),
        );
        end_timer!(horizontal_stacking_timer);

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor.at_round(0);
        #[cfg(not(feature = "parallel"))]
        let leafs_iter = folded_evals.chunks_exact(fold_size * polys.len());
        #[cfg(feature = "parallel")]
        let leafs_iter = folded_evals.par_chunks_exact(fold_size * polys.len());

        let merkle_build_timer = start_timer!(|| "Build Merkle Tree");
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
        let mut ood_answers = vec![E::ZERO; polys.len() * self.0.committment_ood_samples];
        if self.0.committment_ood_samples > 0 {
            transcript.fill_challenge_scalars(&mut ood_points)?;
            ood_points
                .par_iter()
                .zip(ood_answers.par_chunks_mut(polys.len()))
                .for_each(|(ood_point, ood_answers)| {
                    for j in 0..polys.len() {
                        let eval = polys[j].evaluate_at_extension(&expand_from_univariate(
                            *ood_point,
                            self.0.mv_parameters.num_variables,
                        ));
                        ood_answers[j] = eval;
                    }
                });
            transcript.add_scalars(&ood_answers)?;
        }

        let polys = polys
            .into_par_iter()
            .map(|poly| poly.clone().to_extension())
            .collect::<Vec<_>>();

        end_timer!(timer);

        Ok(Witnesses {
            polys,
            merkle_tree,
            merkle_leaves: folded_evals,
            ood_points,
            ood_answers,
        })
    }
}
