use ff_ext::ExtensionField;
use gkr::structs::PointAndEval;

pub mod prover;
pub mod verifier;

#[derive(Clone)]
pub struct ZKVMProof<E: ExtensionField> {
    pub input_point_and_evals: Vec<PointAndEval<E>>,
}
