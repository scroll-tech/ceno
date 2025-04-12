use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
use p3::field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::{self, Debug},
    ops::Div,
};
use sumcheck::structs::IOPProverMessage;

use crate::{
    instructions::{Instruction, riscv::ecall::HaltInstruction},
    structs::{TowerProofs, ZKVMVerifyingKey},
};

pub mod constants;
pub mod prover;
pub mod utils;
pub mod verifier;

pub mod mock_prover;
#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct ZKVMOpcodeProof<E: ExtensionField> {
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

    pub wits_in_evals: Vec<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct ZKVMTableProof<E: ExtensionField> {
    // tower evaluation at layer 1
    pub r_out_evals: Vec<[E; 2]>,
    pub w_out_evals: Vec<[E; 2]>,
    pub lk_out_evals: Vec<[E; 4]>,

    pub same_r_sumcheck_proofs: Option<Vec<IOPProverMessage<E>>>,
    pub rw_in_evals: Vec<E>,
    pub lk_in_evals: Vec<E>,

    pub tower_proof: TowerProofs<E>,

    pub fixed_in_evals: Vec<E>,
    pub wits_in_evals: Vec<E>,
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
            vec![E::BaseField::from_u64((self.exit_code & 0xffff) as u64)],
            vec![E::BaseField::from_u64(
                ((self.exit_code >> 16) & 0xffff) as u64,
            )],
            vec![E::BaseField::from_u64(self.init_pc as u64)],
            vec![E::BaseField::from_u64(self.init_cycle as u64)],
            vec![E::BaseField::from_u64(self.end_pc as u64)],
            vec![E::BaseField::from_u64(self.end_cycle as u64)],
            self.public_io
                .iter()
                .map(|e| E::BaseField::from_u64(*e as u64))
                .collect(),
        ]
    }
}

/// Map circuit names to
/// - an opcode or table proof,
/// - an index unique across both types.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct ZKVMProof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    // TODO preserve in serde only for auxiliary public input
    // other raw value can be construct by verifier directly.
    pub raw_pi: Vec<Vec<E::BaseField>>,
    // the evaluation of raw_pi.
    pub pi_evals: Vec<E>,
    // circuit size -> instance mapping
    pub num_instances: Vec<(usize, usize)>,
    opcode_proofs: BTreeMap<usize, ZKVMOpcodeProof<E>>,
    table_proofs: BTreeMap<usize, ZKVMTableProof<E>>,
    witin_commit: <PCS as PolynomialCommitmentScheme<E>>::Commitment,
    pub fixed_witin_opening_proof: PCS::Proof,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProof<E, PCS> {
    pub fn new(
        raw_pi: Vec<Vec<E::BaseField>>,
        pi_evals: Vec<E>,
        opcode_proofs: BTreeMap<usize, ZKVMOpcodeProof<E>>,
        table_proofs: BTreeMap<usize, ZKVMTableProof<E>>,
        witin_commit: <PCS as PolynomialCommitmentScheme<E>>::Commitment,
        fixed_witin_opening_proof: PCS::Proof,
        num_instances: Vec<(usize, usize)>,
    ) -> Self {
        Self {
            raw_pi,
            pi_evals,
            opcode_proofs,
            table_proofs,
            witin_commit,
            fixed_witin_opening_proof,
            num_instances,
        }
    }

    pub fn pi_evals(raw_pi: &[Vec<E::BaseField>]) -> Vec<E> {
        raw_pi
            .iter()
            .map(|pv| {
                if pv.len() == 1 {
                    // this is constant poly, and always evaluate to same constant value
                    E::from(pv[0])
                } else {
                    // set 0 as placeholder. will be evaluate lazily
                    // Or the vector is empty, i.e. the constant 0 polynomial.
                    E::ZERO
                }
            })
            .collect_vec()
    }

    pub fn update_pi_eval(&mut self, idx: usize, v: E) {
        self.pi_evals[idx] = v;
    }

    pub fn num_circuits(&self) -> usize {
        self.opcode_proofs.len() + self.table_proofs.len()
    }

    pub fn has_halt(&self, vk: &ZKVMVerifyingKey<E, PCS>) -> bool {
        let halt_instance_count = self
            .num_instances
            .iter()
            .find_map(|(circuit_index, num_instances)| {
                (*circuit_index
                    == vk
                        .circuit_vks
                        .keys()
                        .position(|circuit_name| *circuit_name == HaltInstruction::<E>::name())
                        .expect("halt circuit not exist"))
                .then_some(*num_instances)
            })
            .unwrap_or(0);
        if halt_instance_count > 0 {
            assert_eq!(
                halt_instance_count, 1,
                "abnormal halt instance count {halt_instance_count} != 1"
            );
        }
        halt_instance_count == 1
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + Serialize> fmt::Display
    for ZKVMProof<E, PCS>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // break down zkvm proof size

        // also provide by-circuit stats
        let mut by_circuitname_stats = HashMap::new();
        // opcode circuit mpcs size
        let mpcs_opcode_commitment =
            bincode::serialized_size(&self.witin_commit).expect("serialization error");
        let mpcs_opcode_opening =
            bincode::serialized_size(&self.fixed_witin_opening_proof).expect("serialization error");

        // opcode circuit for tower proof size
        let tower_proof_opcode = self
            .opcode_proofs
            .iter()
            .map(|(circuit_index, proof)| {
                let size = bincode::serialized_size(&proof.tower_proof);
                size.inspect(|size| {
                    *by_circuitname_stats.entry(circuit_index).or_insert(0) += size;
                })
            })
            .collect::<Result<Vec<u64>, _>>()
            .expect("serialization error")
            .iter()
            .sum::<u64>();
        // opcode circuit main sumcheck
        let main_sumcheck_opcode = self
            .opcode_proofs
            .iter()
            .map(|(circuit_index, proof)| {
                let size = bincode::serialized_size(&proof.main_sel_sumcheck_proofs);
                size.inspect(|size| {
                    *by_circuitname_stats.entry(circuit_index).or_insert(0) += size;
                })
            })
            .collect::<Result<Vec<u64>, _>>()
            .expect("serialization error")
            .iter()
            .sum::<u64>();
        // table circuit for tower proof size
        let tower_proof_table = self
            .table_proofs
            .iter()
            .map(|(circuit_index, proof)| {
                let size = bincode::serialized_size(&proof.tower_proof);
                size.inspect(|size| {
                    *by_circuitname_stats.entry(circuit_index).or_insert(0) += size;
                })
            })
            .collect::<Result<Vec<u64>, _>>()
            .expect("serialization error")
            .iter()
            .sum::<u64>();
        // table circuit same r sumcheck
        let same_r_sumcheck_table = self
            .table_proofs
            .iter()
            .map(|(circuit_index, proof)| {
                let size = bincode::serialized_size(&proof.same_r_sumcheck_proofs);
                size.inspect(|size| {
                    *by_circuitname_stats.entry(circuit_index).or_insert(0) += size;
                })
            })
            .collect::<Result<Vec<u64>, _>>()
            .expect("serialization error")
            .iter()
            .sum::<u64>();

        // overall size
        let overall_size = bincode::serialized_size(&self).expect("serialization error");

        // break down by circuit name
        let by_circuitname_stats = by_circuitname_stats
            .iter()
            .sorted_by(|(_, size1), (_, size2)| size1.cmp(size2).reverse())
            .map(|(key, size)| {
                format!(
                    "{}: {:.2}mb({}%)",
                    key,
                    byte_to_mb(*size),
                    (size * 100).div(overall_size)
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        // let mpcs_size = bincode::serialized_size(&proof.).unwrap().len();
        write!(
            f,
            "overall_size {:.2}mb. \n\
            mpcs commitment {:?}% \n\
            mpcs opening {:?}% \n\
            opcode tower proof {:?}% \n\
            opcode main sumcheck proof {:?}% \n\
            table tower proof {:?}% \n\
            table same r sumcheck proof {:?}% \n\n\
            by circuit_name break down: \n\
            {}
            ",
            byte_to_mb(overall_size),
            (mpcs_opcode_commitment * 100).div(overall_size),
            (mpcs_opcode_opening * 100).div(overall_size),
            (tower_proof_opcode * 100).div(overall_size),
            (main_sumcheck_opcode * 100).div(overall_size),
            (tower_proof_table * 100).div(overall_size),
            (same_r_sumcheck_table * 100).div(overall_size),
            by_circuitname_stats,
        )
    }
}

fn byte_to_mb(byte_size: u64) -> f64 {
    byte_size as f64 / (1024.0 * 1024.0)
}
