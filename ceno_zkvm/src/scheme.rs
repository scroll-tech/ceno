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
    pub public_io: Vec<u32>,
    pub global_sum: Vec<u32>,
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
        public_io: Vec<u32>,
        global_sum: Vec<u32>,
    ) -> Self {
        Self {
            exit_code,
            init_pc,
            init_cycle,
            end_pc,
            end_cycle,
            shard_id,
            public_io,
            global_sum,
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
            self.global_sum
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
    pub chip_proofs: BTreeMap<usize, ZKVMChipProof<E>>,
    pub witin_commit: <PCS as PolynomialCommitmentScheme<E>>::Commitment,
    pub opening_proof: PCS::Proof,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProof<E, PCS> {
    pub fn new(
        raw_pi: Vec<Vec<E::BaseField>>,
        pi_evals: Vec<E>,
        chip_proofs: BTreeMap<usize, ZKVMChipProof<E>>,
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
            .map_or(0, |proof| proof.num_instances.iter().sum());
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

// _debug: hintable
// pub struct ZKVMChipProofInput {
//     pub idx: usize,
//     // this is the number of instructions before padding
//     // it's possible that an instruction has multiple rows.
//     pub num_instances: usize,
//     // this is the number of variables of each polynomial in the witness matrix
//     pub num_vars: usize,

//     // product constraints
//     pub record_r_out_evals_len: usize,
//     pub record_w_out_evals_len: usize,
//     pub record_lk_out_evals_len: usize,
//     pub record_r_out_evals: Vec<Vec<E>>,
//     pub record_w_out_evals: Vec<Vec<E>>,
//     pub record_lk_out_evals: Vec<Vec<E>>,

//     pub tower_proof: TowerProofInput,

//     // main constraint and select sumcheck proof
//     pub main_sumcheck_proofs: IOPProverMessageVec,
//     pub wits_in_evals: Vec<E>,
//     pub fixed_in_evals: Vec<E>,

//     // gkr proof
//     pub has_gkr_proof: bool,
//     pub gkr_iop_proof: GKRProofInput,
// }

// impl VecAutoHintable for ZKVMChipProofInput {}

#[derive(DslVariable, Clone)]
pub struct ZKVMChipProofInputVariable<C: Config> {
    pub idx: Usize<C::N>,
    pub idx_felt: Felt<C::F>,
    pub num_instances: Usize<C::N>,
    pub num_instances_minus_one_bit_decomposition: Array<C, Felt<C::F>>,
    pub log2_num_instances: Usize<C::N>,

    pub record_r_out_evals_len: Usize<C::N>,
    pub record_w_out_evals_len: Usize<C::N>,
    pub record_lk_out_evals_len: Usize<C::N>,

    pub record_r_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub record_w_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub record_lk_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,

    pub tower_proof: TowerProofInputVariable<C>,

    pub main_sel_sumcheck_proofs: IOPProverMessageVecVariable<C>,
    pub wits_in_evals: Array<C, Ext<C::F, C::EF>>,
    pub fixed_in_evals: Array<C, Ext<C::F, C::EF>>,

    pub has_gkr_proof: Usize<C::N>,
    pub gkr_iop_proof: GKRProofVariable<C>,
}

impl Hintable<InnerConfig> for ZKVMChipProofInput {
    type HintVariable = ZKVMChipProofInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let idx = Usize::Var(usize::read(builder));
        let idx_felt = F::read(builder);
        let num_instances = Usize::Var(usize::read(builder));
        let num_instances_minus_one_bit_decomposition = Vec::<F>::read(builder);
        let log2_num_instances = Usize::Var(usize::read(builder));

        let record_r_out_evals_len = Usize::Var(usize::read(builder));
        let record_w_out_evals_len = Usize::Var(usize::read(builder));
        let record_lk_out_evals_len = Usize::Var(usize::read(builder));

        let record_r_out_evals = Vec::<Vec<E>>::read(builder);
        let record_w_out_evals = Vec::<Vec<E>>::read(builder);
        let record_lk_out_evals = Vec::<Vec<E>>::read(builder);

        let tower_proof = TowerProofInput::read(builder);
        let main_sel_sumcheck_proofs = IOPProverMessageVec::read(builder);
        let wits_in_evals = Vec::<E>::read(builder);
        let fixed_in_evals = Vec::<E>::read(builder);

        let has_gkr_proof = Usize::Var(usize::read(builder));
        let gkr_iop_proof = GKRProofInput::read(builder);

        ZKVMChipProofInputVariable {
            idx,
            idx_felt,
            num_instances,
            num_instances_minus_one_bit_decomposition,
            log2_num_instances,
            record_r_out_evals_len,
            record_w_out_evals_len,
            record_lk_out_evals_len,
            record_r_out_evals,
            record_w_out_evals,
            record_lk_out_evals,
            tower_proof,
            main_sel_sumcheck_proofs,
            wits_in_evals,
            fixed_in_evals,
            has_gkr_proof,
            gkr_iop_proof,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.idx));

        let idx_u32: F = F::from_canonical_u32(self.idx as u32);
        stream.extend(idx_u32.write());

        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.num_instances));

        let eq_instance = self.num_instances - 1;
        let mut bit_decomp: Vec<F> = vec![];
        for i in 0..32usize {
            bit_decomp.push(F::from_canonical_usize((eq_instance >> i) & 1));
        }
        stream.extend(bit_decomp.write());

        let next_pow2_instance = next_pow2_instance_padding(self.num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instance);
        stream.extend(<usize as Hintable<InnerConfig>>::write(&log2_num_instances));

        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.record_r_out_evals_len,
        ));
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.record_w_out_evals_len,
        ));
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.record_lk_out_evals_len,
        ));

        stream.extend(self.record_r_out_evals.write());
        stream.extend(self.record_w_out_evals.write());
        stream.extend(self.record_lk_out_evals.write());

        stream.extend(self.tower_proof.write());
        stream.extend(self.main_sumcheck_proofs.write());
        stream.extend(self.wits_in_evals.write());
        stream.extend(self.fixed_in_evals.write());
        if self.has_gkr_proof {
            stream.extend(<usize as Hintable<InnerConfig>>::write(&1));
        } else {
            stream.extend(<usize as Hintable<InnerConfig>>::write(&0));
        }
        stream.extend(self.gkr_iop_proof.write());

        stream
    }
}

// _debug: hintable
// pub(crate) struct ZKVMProofInput {
//     pub raw_pi: Vec<Vec<F>>,
//     // Evaluation of raw_pi.
//     pub pi_evals: Vec<E>,
//     pub chip_proofs: Vec<ZKVMChipProofInput>,
//     pub witin_commit: BasefoldCommitment,
//     pub pcs_proof: BasefoldProof,
// }

#[derive(DslVariable, Clone)]
pub struct ZKVMProofInputVariable<C: Config> {
    pub raw_pi: Array<C, Array<C, Felt<C::F>>>,
    pub raw_pi_num_variables: Array<C, Var<C::N>>,
    pub pi_evals: Array<C, Ext<C::F, C::EF>>,
    pub chip_proofs: Array<C, ZKVMChipProofInputVariable<C>>,
    pub max_num_var: Var<C::N>,
    pub max_width: Var<C::N>,
    pub witin_commit: BasefoldCommitmentVariable<C>,
    pub witin_perm: Array<C, Var<C::N>>,
    pub fixed_perm: Array<C, Var<C::N>>,
    pub pcs_proof: BasefoldProofVariable<C>,
}

impl<E: ExtensionField> Hintable<InnerConfig> for ZKVMProof<E> {
    type HintVariable = ZKVMProofInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let raw_pi = Vec::<Vec<F>>::read(builder);
        let raw_pi_num_variables = Vec::<usize>::read(builder);
        let pi_evals = Vec::<E>::read(builder);
        let chip_proofs = Vec::<ZKVMChipProofInput>::read(builder);
        let max_num_var = usize::read(builder);
        let max_width = usize::read(builder);
        let witin_commit = BasefoldCommitment::read(builder);
        let witin_perm = Vec::<usize>::read(builder);
        let fixed_perm = Vec::<usize>::read(builder);
        let pcs_proof = BasefoldProof::read(builder);

        ZKVMProofInputVariable {
            raw_pi,
            raw_pi_num_variables,
            pi_evals,
            chip_proofs,
            max_num_var,
            max_width,
            witin_commit,
            witin_perm,
            fixed_perm,
            pcs_proof,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        let raw_pi_num_variables: Vec<usize> = self
            .raw_pi
            .iter()
            .map(|v| ceil_log2(v.len().next_power_of_two()))
            .collect();
        let witin_num_vars = self
            .chip_proofs
            .iter()
            .map(|proof| proof.num_vars)
            .collect::<Vec<_>>();
        let witin_max_widths = self
            .chip_proofs
            .iter()
            .map(|proof| proof.wits_in_evals.len().max(1))
            .collect::<Vec<_>>();
        let fixed_num_vars = self
            .chip_proofs
            .iter()
            .filter(|proof| proof.fixed_in_evals.len() > 0)
            .map(|proof| proof.num_vars)
            .collect::<Vec<_>>();
        let fixed_max_widths = self
            .chip_proofs
            .iter()
            .filter(|proof| proof.fixed_in_evals.len() > 0)
            .map(|proof| proof.fixed_in_evals.len())
            .collect::<Vec<_>>();
        let max_num_var = witin_num_vars.iter().map(|x| *x).max().unwrap_or(0);
        let max_width = witin_max_widths
            .iter()
            .chain(fixed_max_widths.iter())
            .map(|x| *x)
            .max()
            .unwrap_or(0);
        let get_perm = |v: Vec<usize>| {
            let mut perm = vec![0; v.len()];
            v.into_iter()
                // the original order
                .enumerate()
                .sorted_by(|(_, nv_a), (_, nv_b)| Ord::cmp(nv_b, nv_a))
                .enumerate()
                // j is the new index where i is the original index
                .map(|(j, (i, _))| (i, j))
                .for_each(|(i, j)| {
                    perm[i] = j;
                });
            perm
        };
        let witin_perm = get_perm(witin_num_vars);
        let fixed_perm = get_perm(fixed_num_vars);

        stream.extend(self.raw_pi.write());
        stream.extend(raw_pi_num_variables.write());
        stream.extend(self.pi_evals.write());
        stream.extend(self.chip_proofs.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&max_num_var));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&max_width));
        stream.extend(self.witin_commit.write());
        stream.extend(witin_perm.write());
        stream.extend(fixed_perm.write());
        stream.extend(self.pcs_proof.write());

        stream
    }
}
