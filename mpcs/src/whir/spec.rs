use ff_ext::ExtensionField;
use serde::Serialize;
use whir::{
    crypto::poseidon2_merkle_tree,
    parameters::{FoldType, FoldingFactor, SoundnessType, WhirParameters},
};

pub trait WhirSpec<E: ExtensionField>: Default + std::fmt::Debug + Clone {
    fn get_whir_parameters(is_batch: bool) -> WhirParameters<E>;
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WhirDefaultSpec;

impl<E: ExtensionField> WhirSpec<E> for WhirDefaultSpec {
    fn get_whir_parameters(is_batch: bool) -> WhirParameters<E> {
        WhirParameters::<E> {
            initial_statement: true,
            starting_log_inv_rate: 1,
            folding_factor: if is_batch {
                FoldingFactor::ConstantFromSecondRound(1, 4)
            } else {
                FoldingFactor::Constant(4)
            },
            soundness_type: SoundnessType::ConjectureList,
            security_level: 100,
            pow_bits: 0,
            fold_optimisation: FoldType::ProverHelps,
            // Merkle tree parameters
            hash_params: poseidon2_merkle_tree(),
        }
    }
}
