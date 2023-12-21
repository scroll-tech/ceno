use goldilocks::SmallField;
use transcript::Transcript;

use crate::structs::ZKVMProof;

use super::structs::{VMBasic, VMBasicWitness};

pub fn prove<F: SmallField>(
    vm: &VMBasic<F>,
    vm_witness: &VMBasicWitness<F>,
    public_input: &[F],
    transcript: &mut Transcript<F>,
) -> ZKVMProof<F> {
    todo!()
}
