use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::TwoAdicField;
use nimue::plugins::ark::*;

use crate::{
    fs_utils::{OODIOPattern, WhirPoWIOPattern},
    sumcheck::prover_not_skipping::SumcheckNotSkippingIOPattern,
    whir::iopattern::DigestIOPattern,
};

use crate::whir::parameters::WhirConfig;

pub trait WhirBatchIOPattern<F: TwoAdicField, MerkleConfig: Config> {
    fn commit_batch_statement<PowStrategy>(
        self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self;
    fn add_whir_unify_proof<PowStrategy>(
        self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self;
    fn add_whir_batch_proof<PowStrategy>(
        self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self;
}

impl<F, MerkleConfig, IOPattern> WhirBatchIOPattern<F, MerkleConfig> for IOPattern
where
    F: TwoAdicField,
    MerkleConfig: Config,
    IOPattern: ByteIOPattern
        + FieldIOPattern<F>
        + SumcheckNotSkippingIOPattern<F>
        + WhirPoWIOPattern
        + OODIOPattern<F>
        + DigestIOPattern<MerkleConfig>,
{
    fn commit_batch_statement<PowStrategy>(
        self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self {
        // TODO: Add params
        let mut this = self.add_digest("merkle_digest");
        if params.committment_ood_samples > 0 {
            assert!(params.initial_statement);
            this = this
                .challenge_scalars(params.committment_ood_samples, "ood_query")
                .add_scalars(params.committment_ood_samples * batch_size, "ood_ans");
        }
        this
    }

    fn add_whir_unify_proof<PowStrategy>(
        mut self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self {
        if batch_size > 1 {
            self = self.challenge_scalars(1, "batch_poly_combination_randomness");
        }
        self = self
            // .challenge_scalars(1, "initial_combination_randomness")
            .add_sumcheck(params.mv_parameters.num_variables, 0.);
        self.add_scalars(batch_size, "unified_folded_evals")
    }

    fn add_whir_batch_proof<PowStrategy>(
        mut self,
        params: &WhirConfig<F, MerkleConfig, PowStrategy>,
        batch_size: usize,
    ) -> Self {
        if batch_size > 1 {
            self = self.challenge_scalars(1, "batch_poly_combination_randomness");
        }

        // TODO: Add statement
        if params.initial_statement {
            self = self
                .challenge_scalars(1, "initial_combination_randomness")
                .add_sumcheck(
                    params.folding_factor.at_round(0),
                    params.starting_folding_pow_bits,
                );
        } else {
            self = self
                .challenge_scalars(params.folding_factor.at_round(0), "folding_randomness")
                .pow(params.starting_folding_pow_bits);
        }

        let mut domain_size = params.starting_domain.size();

        for (round, r) in params.round_parameters.iter().enumerate() {
            let folded_domain_size = domain_size >> params.folding_factor.at_round(round);
            let domain_size_bytes = ((folded_domain_size * 2 - 1).ilog2() as usize + 7) / 8;
            self = self
                .add_digest("merkle_digest")
                .add_ood(r.ood_samples)
                .challenge_bytes(r.num_queries * domain_size_bytes, "stir_queries")
                .pow(r.pow_bits)
                .challenge_scalars(1, "combination_randomness")
                .add_sumcheck(
                    params.folding_factor.at_round(round + 1),
                    r.folding_pow_bits,
                );
            domain_size >>= 1;
        }

        let folded_domain_size = domain_size
            >> params
                .folding_factor
                .at_round(params.round_parameters.len());
        let domain_size_bytes = ((folded_domain_size * 2 - 1).ilog2() as usize + 7) / 8;

        self.add_scalars(1 << params.final_sumcheck_rounds, "final_coeffs")
            .challenge_bytes(domain_size_bytes * params.final_queries, "final_queries")
            .pow(params.final_pow_bits)
            .add_sumcheck(params.final_sumcheck_rounds, params.final_folding_pow_bits)
    }
}
