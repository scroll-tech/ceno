use ff_ext::ExtensionField;
use std::collections::HashMap;
use sumcheck::structs::IOPProverMessage;

use crate::structs::TowerProofs;

pub mod constants;
pub mod prover;
pub mod utils;
pub mod verifier;

#[cfg(test)]
pub mod mock_prover;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ZKVMOpcodeProof<E: ExtensionField> {
    // TODO support >1 opcodes
    pub num_instances: usize,

    // product constraints
    pub record_r_out_evals: Vec<E>,
    pub record_w_out_evals: Vec<E>,

    // logup constraint
    pub lk_p1_out_eval: E,
    pub lk_p2_out_eval: E,
    pub lk_q1_out_eval: E,
    pub lk_q2_out_eval: E,

    pub tower_proof: TowerProofs<E>,

    // main constraint and select sumcheck proof
    pub main_sel_sumcheck_proofs: Vec<IOPProverMessage<E>>,
    pub r_records_in_evals: Vec<E>,
    pub w_records_in_evals: Vec<E>,
    pub lk_records_in_evals: Vec<E>,

    pub wits_in_evals: Vec<E>,
}

#[derive(Clone)]
pub struct ZKVMTableProof<E: ExtensionField> {
    pub num_instances: usize,
    // logup sum at layer 1
    pub lk_p1_out_eval: E,
    pub lk_p2_out_eval: E,
    pub lk_q1_out_eval: E,
    pub lk_q2_out_eval: E,

    pub tower_proof: TowerProofs<E>,

    // select layer sumcheck proof
    pub sel_sumcheck_proofs: Vec<IOPProverMessage<E>>,
    pub lk_d_in_evals: Vec<E>,
    pub lk_n_in_evals: Vec<E>,

    pub fixed_in_evals: Vec<E>,
    pub wits_in_evals: Vec<E>,
}

/// Map circuit names to
/// - an opcode or table proof,
/// - an index unique across both types.
#[derive(Default, Clone)]
pub struct ZKVMProof<E: ExtensionField> {
    opcode_proofs: HashMap<String, (usize, ZKVMOpcodeProof<E>)>,
    table_proofs: HashMap<String, (usize, ZKVMTableProof<E>)>,
}

impl<E: ExtensionField> ZKVMProof<E> {
    pub fn num_circuits(&self) -> usize {
        self.opcode_proofs.len() + self.table_proofs.len()
    }
}
