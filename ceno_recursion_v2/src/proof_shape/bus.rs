use p3_field::PrimeCharacteristicRing;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::define_typed_per_proof_permutation_bus;

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct ProofShapePermutationMessage<T> {
    pub idx: T,
}

define_typed_per_proof_permutation_bus!(ProofShapePermutationBus, ProofShapePermutationMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct StartingTidxMessage<T> {
    pub air_idx: T,
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(StartingTidxBus, StartingTidxMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct NumPublicValuesMessage<T> {
    pub air_idx: T,
    pub tidx: T,
    pub num_pvs: T,
}

define_typed_per_proof_permutation_bus!(NumPublicValuesBus, NumPublicValuesMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct CommitmentsBusMessage<T> {
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(CommitmentsBus, CommitmentsBusMessage);

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum AirShapeProperty {
    AirId,
    NumInteractions,
    NeedRot,
    NumRead,
    NumWrite,
    NumLk,
}

impl AirShapeProperty {
    pub fn to_field<T: PrimeCharacteristicRing>(self) -> T {
        T::from_u8(self as u8)
    }
}
