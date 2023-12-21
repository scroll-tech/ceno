use goldilocks::SmallField;
use transcript::Transcript;

use crate::structs::{VMError, ZKVMProof};

use super::structs::VMBasic;

pub fn verify<F: SmallField>(
    circuit: &VMBasic<F>,
    proof: &ZKVMProof<F>,
    public_input: &[F],
    transcript: &mut Transcript<F>,
) -> Result<(), VMError> {
    todo!()
}
