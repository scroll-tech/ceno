use ff_ext::{ExtensionField, PoseidonField};
use p3::{self, commit::ExtensionMmcs};

pub type Poseidon2ExtMerkleMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;

pub fn poseidon2_merkle_tree<E: ExtensionField>()
-> <<E as ExtensionField>::BaseField as PoseidonField>::MMCS {
    <E::BaseField as PoseidonField>::get_default_mmcs()
}
