use crate::structs::EccQuarkProof;
use ff_ext::ExtensionField;
use gkr_iop::gkr::GKRProof;
use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
use p3::field::FieldAlgebra;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::{self, Debug},
    iter,
    ops::Div,
    rc::Rc,
};
use sumcheck::structs::IOPProverMessage;

use crate::{
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, UINT_LIMBS},
            ecall::HaltInstruction,
        },
    },
    structs::{TowerProofs, ZKVMVerifyingKey},
};

pub mod constants;
pub mod cpu;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod hal;
pub mod prover;
pub mod septic_curve;
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
pub struct GKROpcodeProof<E: ExtensionField>(pub GKRProof<E>);

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct ZKVMChipProof<E: ExtensionField> {
    // tower evaluation at layer 1
    pub r_out_evals: Vec<Vec<E>>,
    pub w_out_evals: Vec<Vec<E>>,
    pub lk_out_evals: Vec<Vec<E>>,

    pub main_sumcheck_proofs: Option<Vec<IOPProverMessage<E>>>,
    pub gkr_iop_proof: Option<GKRProof<E>>,

    pub tower_proof: TowerProofs<E>,
    pub ecc_proof: Option<EccQuarkProof<E>>,

    pub num_instances: Vec<usize>,

    pub fixed_in_evals: Vec<E>,
    pub wits_in_evals: Vec<E>,
}

/// each field will be interpret to (constant) polynomial
#[derive(Default, Clone, Debug)]
pub struct PublicValues {
    pub exit_code: u32,
    pub init_pc: u32,
    pub init_cycle: u64,
    pub end_pc: u32,
    pub end_cycle: u64,
    pub shard_id: u32,
    pub heap_start_addr: u32,
    pub heap_shard_len: u32,
    pub hint_start_addr: u32,
    pub hint_shard_len: u32,
    pub num_instances: u32,
    pub public_io: Vec<u32>,
    pub shard_rw_sum: Vec<u32>,
}

impl PublicValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_code: u32,
        init_pc: u32,
        init_cycle: u64,
        end_pc: u32,
        end_cycle: u64,
        shard_id: u32,
        heap_start_addr: u32,
        heap_shard_len: u32,
        hint_start_addr: u32,
        hint_shard_len: u32,
        public_io: Vec<u32>,
        shard_rw_sum: Vec<u32>,
    ) -> Self {
        Self {
            exit_code,
            init_pc,
            init_cycle,
            end_pc,
            end_cycle,
            shard_id,
            heap_start_addr,
            heap_shard_len,
            hint_start_addr,
            hint_shard_len,
            // it will be set per chip proving
            num_instances: 0,
            public_io,
            shard_rw_sum,
        }
    }
    pub fn to_vec<E: ExtensionField>(&self) -> Vec<Vec<E::BaseField>> {
        vec![
            vec![E::BaseField::from_canonical_u32(self.exit_code & 0xffff)],
            vec![E::BaseField::from_canonical_u32(
                (self.exit_code >> 16) & 0xffff,
            )],
            vec![E::BaseField::from_canonical_u32(self.init_pc)],
            vec![E::BaseField::from_canonical_u64(self.init_cycle)],
            vec![E::BaseField::from_canonical_u32(self.end_pc)],
            vec![E::BaseField::from_canonical_u64(self.end_cycle)],
            vec![E::BaseField::from_canonical_u32(self.shard_id)],
            vec![E::BaseField::from_canonical_u32(self.heap_start_addr)],
            vec![E::BaseField::from_canonical_u32(self.heap_shard_len)],
            vec![E::BaseField::from_canonical_u32(self.hint_start_addr)],
            vec![E::BaseField::from_canonical_u32(self.hint_shard_len)],
            vec![E::BaseField::ZERO],
        ]
        .into_iter()
        .chain(
            // public io processed into UINT_LIMBS column
            (0..UINT_LIMBS)
                .map(|limb_index| {
                    self.public_io
                        .iter()
                        .map(|value| {
                            E::BaseField::from_canonical_u16(
                                ((value >> (limb_index * LIMB_BITS)) & LIMB_MASK) as u16,
                            )
                        })
                        .collect_vec()
                })
                .collect_vec(),
        )
        .chain(
            self.shard_rw_sum
                .iter()
                .map(|value| vec![E::BaseField::from_canonical_u32(*value)])
                .collect_vec(),
        )
        .collect::<Vec<_>>()
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
    // each circuit may have multiple proof instances
    pub chip_proofs: BTreeMap<usize, Vec<ZKVMChipProof<E>>>,
    pub witin_commit: <PCS as PolynomialCommitmentScheme<E>>::Commitment,
    pub opening_proof: PCS::Proof,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProof<E, PCS> {
    pub fn new(
        raw_pi: Vec<Vec<E::BaseField>>,
        pi_evals: Vec<E>,
        chip_proofs: BTreeMap<usize, Vec<ZKVMChipProof<E>>>,
        witin_commit: <PCS as PolynomialCommitmentScheme<E>>::Commitment,
        opening_proof: PCS::Proof,
    ) -> Self {
        Self {
            raw_pi,
            pi_evals,
            chip_proofs,
            witin_commit,
            opening_proof,
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
        self.chip_proofs.len()
    }

    pub fn has_halt(&self, vk: &ZKVMVerifyingKey<E, PCS>) -> bool {
        let halt_circuit_index = vk
            .circuit_vks
            .keys()
            .position(|circuit_name| *circuit_name == HaltInstruction::<E>::name())
            .expect("halt circuit not exist");
        let halt_instance_count = self
            .chip_proofs
            .get(&halt_circuit_index)
            .map_or(0, |proofs| {
                proofs
                    .iter()
                    .flat_map(|proof| &proof.num_instances)
                    .copied()
                    .sum()
            });
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
            bincode::serialized_size(&self.opening_proof).expect("serialization error");

        // tower proof size
        let tower_proof = self
            .chip_proofs
            .iter()
            .flat_map(|(circuit_index, proofs)| {
                iter::repeat_n(circuit_index, proofs.len()).zip(proofs)
            })
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
        // main sumcheck
        let main_sumcheck = self
            .chip_proofs
            .iter()
            .flat_map(|(circuit_index, proofs)| {
                iter::repeat_n(circuit_index, proofs.len()).zip(proofs)
            })
            .map(|(circuit_index, proof)| {
                let size = bincode::serialized_size(&proof.main_sumcheck_proofs);
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
            tower proof {:?}% \n\
            main sumcheck proof {:?}% \n\
            by circuit_name break down: \n\
            {}
            ",
            byte_to_mb(overall_size),
            (mpcs_opcode_commitment * 100).div(overall_size),
            (mpcs_opcode_opening * 100).div(overall_size),
            (tower_proof * 100).div(overall_size),
            (main_sumcheck * 100).div(overall_size),
            by_circuitname_stats,
        )
    }
}

fn byte_to_mb(byte_size: u64) -> f64 {
    byte_size as f64 / (1024.0 * 1024.0)
}

#[cfg(not(feature = "gpu"))]
pub fn create_backend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    max_num_variables: usize,
    security_level: mpcs::SecurityLevel,
) -> Rc<gkr_iop::cpu::CpuBackend<E, PCS>> {
    gkr_iop::cpu::CpuBackend::<E, PCS>::new(max_num_variables, security_level).into()
}

#[cfg(not(feature = "gpu"))]
pub fn create_prover<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    backend: Rc<gkr_iop::cpu::CpuBackend<E, PCS>>,
) -> gkr_iop::cpu::CpuProver<gkr_iop::cpu::CpuBackend<E, PCS>> {
    gkr_iop::cpu::CpuProver::new(backend)
}

#[cfg(feature = "gpu")]
pub fn create_backend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    max_num_variables: usize,
    security_level: mpcs::SecurityLevel,
) -> Rc<gkr_iop::gpu::GpuBackend<E, PCS>> {
    gkr_iop::gpu::GpuBackend::<E, PCS>::new(max_num_variables, security_level).into()
}

#[cfg(feature = "gpu")]
pub fn create_prover<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    backend: Rc<gkr_iop::gpu::GpuBackend<E, PCS>>,
) -> gkr_iop::gpu::GpuProver<gkr_iop::gpu::GpuBackend<E, PCS>> {
    gkr_iop::gpu::GpuProver::new(backend)
}
