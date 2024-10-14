use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use multilinear_extensions::{mle::FieldType, virtual_poly_v2::ArcMultilinearExtension};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Serialize};

use crate::{util::merkle_tree::MerkleTree, Error};

use super::{
    Basefold, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec, PolyEvalsCodeword,
};

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn batch_commit_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[ArcMultilinearExtension<E>],
    ) -> Result<BasefoldCommitmentWithData<E>, Error> {
        // assumptions
        // 1. there must be at least one polynomial
        // 2. all polynomials must exist in the same field type
        //    (TODO: eliminate this assumption by supporting commiting
        //     and opening mixed-type polys)
        // 3. all polynomials must have the same number of variables

        if polys.is_empty() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to zero polynomials".to_string(),
            ));
        }

        let is_base = match polys[0].evaluations() {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        for i in 1..polys.len() {
            if polys[i].num_vars() != polys[0].num_vars() {
                return Err(Error::InvalidPcsParam(
                    "cannot batch commit to polynomials with different number of variables"
                        .to_string(),
                ));
            }
        }
        let timer = start_timer!(|| "Basefold::batch commit");

        let encode_timer = start_timer!(|| "Basefold::batch commit::encoding and interpolations");
        // convert each polynomial to a code word
        let evals_codewords = polys
            .par_iter()
            .map(|poly| Self::get_poly_bh_evals_and_codeword(pp, poly))
            .collect::<Vec<PolyEvalsCodeword<E>>>();
        end_timer!(encode_timer);

        // build merkle tree from leaves
        let ret = match evals_codewords[0] {
            PolyEvalsCodeword::Normal(_) => {
                let (bh_evals, codewords) = evals_codewords
                    .into_iter()
                    .map(|evals_codeword| match evals_codeword {
                        PolyEvalsCodeword::Normal((bh_evals, codeword)) => (bh_evals, codeword),
                        PolyEvalsCodeword::TooSmall(_) => {
                            unreachable!();
                        }
                        PolyEvalsCodeword::TooBig(_) => {
                            unreachable!();
                        }
                    })
                    .collect::<(Vec<_>, Vec<_>)>();
                let codeword_tree = MerkleTree::<E>::from_batch_leaves(codewords, 2);
                BasefoldCommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: bh_evals,
                    num_vars: polys[0].num_vars(),
                    is_base,
                    num_polys: polys.len(),
                }
            }
            PolyEvalsCodeword::TooSmall(_) => {
                let bh_evals = evals_codewords
                    .into_iter()
                    .map(|bh_evals| match bh_evals {
                        PolyEvalsCodeword::Normal(_) => unreachable!(),
                        PolyEvalsCodeword::TooSmall(evals) => evals,
                        PolyEvalsCodeword::TooBig(_) => {
                            unreachable!();
                        }
                    })
                    .collect::<Vec<_>>();
                let codeword_tree = MerkleTree::<E>::from_batch_leaves(bh_evals.clone(), 2);
                BasefoldCommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: bh_evals,
                    num_vars: polys[0].num_vars(),
                    is_base,
                    num_polys: polys.len(),
                }
            }
            PolyEvalsCodeword::TooBig(num_vars) => return Err(Error::PolynomialTooLarge(num_vars)),
        };

        end_timer!(timer);

        Ok(ret)
    }
}
