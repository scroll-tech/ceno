use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use sumcheck::structs::IOPProverMessage;

use crate::structs::TowerProofs;

pub mod constants;
pub mod prover;
pub mod utils;
pub mod verifier;

pub mod mock_prover;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ZKVMOpcodeProof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    // TODO support >1 opcodes
    pub num_instances: usize,

    // product constraints
    pub record_r_out_evals: Vec<E>,
    pub record_w_out_evals: Vec<E>,

    // logup sum at layer 1
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

    pub wits_commit: PCS::Commitment,
    pub wits_opening_proof: PCS::Proof,
    pub wits_in_evals: Vec<E>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ZKVMTableProof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    // tower evaluation at layer 1
    pub r_out_evals: Vec<[E; 2]>,
    pub w_out_evals: Vec<[E; 2]>,
    pub lk_out_evals: Vec<[E; 4]>,

    pub same_r_sumcheck_proofs: Option<Vec<IOPProverMessage<E>>>,
    pub rw_in_evals: Vec<E>,
    pub lk_in_evals: Vec<E>,

    pub tower_proof: TowerProofs<E>,

    // num_vars hint for rw dynamic address to work
    pub rw_hints_num_vars: Vec<usize>,

    pub fixed_in_evals: Vec<E>,
    pub fixed_opening_proof: Option<PCS::Proof>,
    pub wits_commit: PCS::Commitment,
    pub wits_in_evals: Vec<E>,
    pub wits_opening_proof: PCS::Proof,
}

/// each field will be interpret to (constant) polynomial
#[derive(Default, Clone, Debug)]
pub struct PublicValues<T: Default + Clone + Debug> {
    exit_code: T,
    init_pc: T,
    init_cycle: T,
    end_pc: T,
    end_cycle: T,
    public_io: Vec<T>,
}

impl PublicValues<u32> {
    pub fn new(
        exit_code: u32,
        init_pc: u32,
        init_cycle: u32,
        end_pc: u32,
        end_cycle: u32,
        public_io: Vec<u32>,
    ) -> Self {
        Self {
            exit_code,
            init_pc,
            init_cycle,
            end_pc,
            end_cycle,
            public_io,
        }
    }
    pub fn to_vec<E: ExtensionField>(&self) -> Vec<Vec<E::BaseField>> {
        vec![
            vec![E::BaseField::from((self.exit_code & 0xffff) as u64)],
            vec![E::BaseField::from(((self.exit_code >> 16) & 0xffff) as u64)],
            vec![E::BaseField::from(self.init_pc as u64)],
            vec![E::BaseField::from(self.init_cycle as u64)],
            vec![E::BaseField::from(self.end_pc as u64)],
            vec![E::BaseField::from(self.end_cycle as u64)],
            self.public_io
                .iter()
                .map(|e| E::BaseField::from(*e as u64))
                .collect(),
        ]
    }
}

/// Map circuit names to
/// - an opcode or table proof,
/// - an index unique across both types.
#[derive(Clone)]
pub struct ZKVMProof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    // TODO preserve in serde only for auxiliary public input
    // other raw value can be construct by verifier directly.
    pub raw_pi: Vec<Vec<E::BaseField>>,
    // the evaluation of raw_pi.
    pub pi_evals: Vec<E>,
    opcode_proofs: BTreeMap<String, (usize, ZKVMOpcodeProof<E, PCS>)>,
    table_proofs: BTreeMap<String, (usize, ZKVMTableProof<E, PCS>)>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProof<E, PCS> {
    pub fn empty(pv: PublicValues<u32>) -> Self {
        let raw_pi = pv.to_vec::<E>();
        let pi_evals = raw_pi
            .iter()
            .map(|pv| {
                assert!(!pv.is_empty());
                if pv.len() == 1 {
                    // this is constant poly, and always evaluate to same constant value
                    E::from(pv[0])
                } else {
                    // set 0 as placeholder. will be evaluate lazily
                    E::ZERO
                }
            })
            .collect_vec();
        Self {
            raw_pi,
            pi_evals,
            opcode_proofs: BTreeMap::new(),
            table_proofs: BTreeMap::new(),
        }
    }

    pub fn update_pi_eval(&mut self, idx: usize, v: E) {
        self.pi_evals[idx] = v;
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProof<E, PCS> {
    pub fn num_circuits(&self) -> usize {
        self.opcode_proofs.len() + self.table_proofs.len()
    }
}
