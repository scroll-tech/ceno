use ff_ext::{ExtensionField, PoseidonField};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use poseidon::DIGEST_WIDTH;

pub(crate) type Poseidon2Sponge<P> = PaddingFreeSponge<P, 8, 4, 4>;
// TODO investigate compression setting legibility
pub(crate) type Poseidon2Compression<P> = TruncatedPermutation<P, 2, 4, 8>;
pub(crate) type Poseidon2MerkleMmcs<F, P> =
    MerkleTreeMmcs<F, F, Poseidon2Sponge<P>, Poseidon2Compression<P>, DIGEST_WIDTH>;

pub fn poseidon2_merkle_tree<E: ExtensionField>()
-> Poseidon2MerkleMmcs<E::BaseField, <E::BaseField as PoseidonField>::T> {
    MerkleTreeMmcs::new(
        Poseidon2Sponge::new(<E::BaseField as PoseidonField>::get_perm()),
        Poseidon2Compression::new(<E::BaseField as PoseidonField>::get_perm()),
    )
}
