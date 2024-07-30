use ff_ext::ExtensionField;
use sumcheck::structs::IOPProverMessage;

mod constants;
pub mod prover;
pub mod verifier;

#[derive(Clone)]
pub struct ZKVMProof<E: ExtensionField> {
    // TODO support >1 opcodes
    pub num_instances: usize,

    // main constraint and select sumcheck proof
    pub out_record_r_eval: E,
    pub out_record_w_eval: E,
    pub main_sel_sumcheck_proofs: Vec<IOPProverMessage<E>>,
    pub r_records_in_evals: Vec<E>,
    pub w_records_in_evals: Vec<E>,

    pub wits_in_evals: Vec<E>,
}
