use std::collections::BTreeMap;

use crate::{
    arithmetics::{ceil_log2, next_pow2_instance_padding},
    basefold_verifier::basefold::{
        BasefoldCommitment, BasefoldCommitmentVariable, BasefoldProof, BasefoldProofVariable,
    },
    tower_verifier::binding::{
        IOPProverMessage, IOPProverMessageVec, IOPProverMessageVecVariable, PointVariable,
        ThreeDimensionalVecVariable, ThreeDimensionalVector,
    },
};
use ceno_zkvm::{
    scheme::{ZKVMChipProof, ZKVMProof},
    structs::{EccQuarkProof, TowerProofs},
};
use gkr_iop::gkr::{GKRProof, layer::sumcheck_layer::LayerProof};
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams};
use multilinear_extensions::mle::Point;
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config, Felt},
    prelude::*,
};
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::hints::{Hintable, VecAutoHintable};
use openvm_stark_backend::p3_field::{FieldAlgebra, extension::BinomialExtensionField};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::FieldExtensionAlgebra;
use sumcheck::structs::IOPProof;

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, 4>;
pub type RecPcs = Basefold<E, BasefoldRSParams>;
pub type InnerConfig = AsmConfig<F, E>;

pub fn decompose_minus_one_bits(n: usize) -> Vec<F> {
    let a = if n > 0 { n - 1 } else { 0 };
    let mut bit_decomp: Vec<F> = vec![];
    for i in 0..32usize {
        bit_decomp.push(F::from_canonical_usize((a >> i) & 1));
    }

    bit_decomp
}
pub fn decompose_prefixed_layer_bits(n: usize) -> (Vec<usize>, Vec<Vec<F>>) {
    let mut m = n;
    let mut r = vec![];
    let mut r_bits = vec![];

    r.push(m);
    r_bits.push(decompose_minus_one_bits(m));

    while m > 1 {
        let cur = m / 2;
        r.push(cur);
        r_bits.push(decompose_minus_one_bits(cur));
        m = m.div_ceil(2);
    }

    (r, r_bits)
}

#[derive(DslVariable, Clone)]
pub struct ZKVMProofInputVariable<C: Config> {
    pub shard_id: Usize<C::N>,
    pub raw_pi: Array<C, Array<C, Felt<C::F>>>,
    pub raw_pi_num_variables: Array<C, Var<C::N>>,
    pub pi_evals: Array<C, Ext<C::F, C::EF>>,
    pub chip_proofs: Array<C, Array<C, ZKVMChipProofInputVariable<C>>>,
    pub max_num_var: Var<C::N>,
    pub max_width: Var<C::N>,
    pub witin_commit: BasefoldCommitmentVariable<C>,
    pub witin_perm: Array<C, Var<C::N>>,
    pub fixed_perm: Array<C, Var<C::N>>,
    pub pcs_proof: BasefoldProofVariable<C>,
}

#[derive(DslVariable, Clone)]
pub struct TowerProofInputVariable<C: Config> {
    pub num_proofs: Usize<C::N>,
    pub proofs: Array<C, IOPProverMessageVecVariable<C>>,
    pub num_prod_specs: Usize<C::N>,
    pub prod_specs_eval: ThreeDimensionalVecVariable<C>,
    pub num_logup_specs: Usize<C::N>,
    pub logup_specs_eval: ThreeDimensionalVecVariable<C>,
}

pub(crate) struct ZKVMProofInput {
    pub shard_id: usize,
    pub raw_pi: Vec<Vec<F>>,
    // Evaluation of raw_pi.
    pub pi_evals: Vec<E>,
    pub chip_proofs: BTreeMap<usize, ZKVMChipProofs>,
    pub witin_commit: BasefoldCommitment,
    pub opening_proof: BasefoldProof,
}

impl From<(usize, ZKVMProof<E, RecPcs>)> for ZKVMProofInput {
    fn from(d: (usize, ZKVMProof<E, RecPcs>)) -> Self {
        ZKVMProofInput {
            shard_id: d.0,
            raw_pi: d.1.raw_pi,
            pi_evals: d.1.pi_evals,
            chip_proofs: d
                .1
                .chip_proofs
                .into_iter()
                .map(|(chip_idx, proofs)| {
                    (
                        chip_idx,
                        proofs
                            .into_iter()
                            .map(|proof| ZKVMChipProofInput::from((chip_idx, proof)))
                            .collect::<Vec<ZKVMChipProofInput>>()
                            .into(),
                    )
                })
                .collect::<BTreeMap<usize, ZKVMChipProofs>>(),
            witin_commit: d.1.witin_commit.into(),
            opening_proof: d.1.opening_proof.into(),
        }
    }
}

impl Hintable<InnerConfig> for ZKVMProofInput {
    type HintVariable = ZKVMProofInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let shard_id = Usize::Var(usize::read(builder));
        let raw_pi = Vec::<Vec<F>>::read(builder);
        let raw_pi_num_variables = Vec::<usize>::read(builder);
        let pi_evals = Vec::<E>::read(builder);
        let chip_proofs = Vec::<ZKVMChipProofs>::read(builder);
        let max_num_var = usize::read(builder);
        let max_width = usize::read(builder);
        let witin_commit = BasefoldCommitment::read(builder);
        let witin_perm: Array<AsmConfig<F, BinomialExtensionField<F, 4>>, Var<F>> =
            Vec::<usize>::read(builder);
        let fixed_perm = Vec::<usize>::read(builder);
        let pcs_proof = BasefoldProof::read(builder);

        ZKVMProofInputVariable {
            shard_id,
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
            .flat_map(|(_, proofs)| proofs.iter())
            .map(|proof| proof.num_instances.iter().sum())
            .collect::<Vec<_>>();
        let witin_max_widths = self
            .chip_proofs
            .iter()
            .flat_map(|(_, proofs)| proofs.iter())
            .map(|proof| proof.wits_in_evals.len().max(1))
            .collect::<Vec<_>>();
        let fixed_num_vars = self
            .chip_proofs
            .iter()
            .flat_map(|(_, proofs)| proofs.iter())
            .filter(|proof| !proof.fixed_in_evals.is_empty())
            .map(|proof| proof.num_instances.iter().sum())
            .collect::<Vec<_>>();
        let fixed_max_widths = self
            .chip_proofs
            .iter()
            .flat_map(|(_, proofs)| proofs.iter())
            .filter(|proof| !proof.fixed_in_evals.is_empty())
            .map(|proof| proof.fixed_in_evals.len())
            .collect::<Vec<_>>();
        let max_num_var = witin_num_vars.iter().copied().max().unwrap_or(0);
        let max_width = witin_max_widths
            .iter()
            .chain(fixed_max_widths.iter())
            .copied()
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

        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.shard_id));
        stream.extend(self.raw_pi.write());
        stream.extend(raw_pi_num_variables.write());
        stream.extend(self.pi_evals.write());
        stream.extend(vec![vec![F::from_canonical_usize(self.chip_proofs.len())]]);
        for proofs in self.chip_proofs.values() {
            stream.extend(proofs.write());
        }
        stream.extend(<usize as Hintable<InnerConfig>>::write(&max_num_var));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&max_width));
        stream.extend(self.witin_commit.write());
        stream.extend(witin_perm.write());
        stream.extend(fixed_perm.write());
        stream.extend(self.opening_proof.write());

        stream
    }
}

#[derive(Default, Debug)]
pub struct TowerProofInput {
    pub num_proofs: usize,
    pub proofs: Vec<IOPProverMessageVec>,
    // specs -> layers -> evals
    pub num_prod_specs: usize,
    pub prod_specs_eval: ThreeDimensionalVector,
    // specs -> layers -> evals
    pub num_logup_specs: usize,
    pub logup_specs_eval: ThreeDimensionalVector,
}

impl From<TowerProofs<E>> for TowerProofInput {
    fn from(p: TowerProofs<E>) -> Self {
        let proofs: Vec<IOPProverMessageVec> = p
            .proofs
            .iter()
            .map(|vec| {
                IOPProverMessageVec::from(
                    vec.iter()
                        .map(|p| IOPProverMessage {
                            evaluations: p.evaluations.clone(),
                        })
                        .collect::<Vec<IOPProverMessage>>(),
                )
            })
            .collect();
        Self {
            num_proofs: p.proofs.len(),
            proofs,
            num_prod_specs: p.prod_spec_size(),
            prod_specs_eval: ThreeDimensionalVector::from(p.prod_specs_eval.clone()),
            num_logup_specs: p.logup_spec_size(),
            logup_specs_eval: ThreeDimensionalVector::from(p.logup_specs_eval),
        }
    }
}

impl Hintable<InnerConfig> for TowerProofInput {
    type HintVariable = TowerProofInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let num_proofs = Usize::Var(usize::read(builder));
        let proofs = builder.dyn_array(num_proofs.clone());
        iter_zip!(builder, proofs).for_each(|idx_vec, builder| {
            let ptr = idx_vec[0];
            let proof = IOPProverMessageVec::read(builder);
            builder.iter_ptr_set(&proofs, ptr, proof);
        });

        let num_prod_specs = Usize::Var(usize::read(builder));
        let prod_specs_eval = ThreeDimensionalVector::read(builder);

        let num_logup_specs = Usize::Var(usize::read(builder));
        let logup_specs_eval = ThreeDimensionalVector::read(builder);

        TowerProofInputVariable {
            num_proofs,
            proofs,
            num_prod_specs,
            prod_specs_eval,
            num_logup_specs,
            logup_specs_eval,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.num_proofs));
        for p in &self.proofs {
            stream.extend(p.write());
        }
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.num_prod_specs,
        ));
        stream.extend(self.prod_specs_eval.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.num_logup_specs,
        ));
        stream.extend(self.logup_specs_eval.write());

        stream
    }
}

pub struct ZKVMChipProofInput {
    pub idx: usize,

    // product constraints
    pub r_out_evals_len: usize,
    pub w_out_evals_len: usize,
    pub lk_out_evals_len: usize,
    pub r_out_evals: Vec<Vec<E>>,
    pub w_out_evals: Vec<Vec<E>>,
    pub lk_out_evals: Vec<Vec<E>>,

    pub tower_proof: TowerProofInput,

    // main constraint and select sumcheck proof
    pub has_main_sumcheck_proofs: usize,
    pub main_sumcheck_proofs: IOPProverMessageVec,

    // gkr proof
    pub has_gkr_proof: usize,
    pub gkr_iop_proof: GKRProofInput,

    // ecc proof
    pub has_ecc_proof: usize,
    pub ecc_proof: EccQuarkProofInput,

    pub num_instances: Vec<usize>,

    pub wits_in_evals: Vec<E>,
    pub fixed_in_evals: Vec<E>,
}

impl VecAutoHintable for ZKVMChipProofInput {}

/// wrapper struct to allow us implement VecAutoHintable
pub struct ZKVMChipProofs(Vec<ZKVMChipProofInput>);

impl From<Vec<ZKVMChipProofInput>> for ZKVMChipProofs {
    fn from(v: Vec<ZKVMChipProofInput>) -> Self {
        Self(v)
    }
}

impl VecAutoHintable for ZKVMChipProofs {}

impl ZKVMChipProofs {
    pub fn iter(&self) -> std::slice::Iter<'_, ZKVMChipProofInput> {
        self.0.iter()
    }
}

impl Hintable<InnerConfig> for ZKVMChipProofs {
    type HintVariable = Array<InnerConfig, ZKVMChipProofInputVariable<InnerConfig>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        Vec::<ZKVMChipProofInput>::read(builder)
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        self.0.write()
    }
}

impl From<(usize, ZKVMChipProof<E>)> for ZKVMChipProofInput {
    fn from(d: (usize, ZKVMChipProof<E>)) -> Self {
        let idx = d.0;
        let p = d.1;

        Self {
            idx,
            r_out_evals_len: p.r_out_evals.len(),
            w_out_evals_len: p.w_out_evals.len(),
            lk_out_evals_len: p.lk_out_evals.len(),
            r_out_evals: p.r_out_evals,
            w_out_evals: p.w_out_evals,
            lk_out_evals: p.lk_out_evals,
            tower_proof: p.tower_proof.into(),
            has_main_sumcheck_proofs: if p.main_sumcheck_proofs.is_some() {
                1
            } else {
                0
            },
            main_sumcheck_proofs: if p.main_sumcheck_proofs.is_some() {
                let r = p.main_sumcheck_proofs.unwrap();
                r.iter()
                    .map(|p| IOPProverMessage {
                        evaluations: p.evaluations.clone(),
                    })
                    .collect::<Vec<IOPProverMessage>>()
                    .into()
            } else {
                IOPProverMessageVec::default()
            },
            has_gkr_proof: if p.gkr_iop_proof.is_some() { 1 } else { 0 },
            gkr_iop_proof: if p.gkr_iop_proof.is_some() {
                p.gkr_iop_proof.unwrap().into()
            } else {
                GKRProofInput::default()
            },
            has_ecc_proof: if p.ecc_proof.is_some() { 1 } else { 0 },
            ecc_proof: if p.ecc_proof.is_some() {
                p.ecc_proof.unwrap().into()
            } else {
                EccQuarkProofInput::dummy()
            },
            num_instances: p.num_instances,
            wits_in_evals: p.wits_in_evals,
            fixed_in_evals: p.fixed_in_evals,
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct ZKVMChipProofInputVariable<C: Config> {
    pub idx: Usize<C::N>,
    pub idx_felt: Felt<C::F>,

    pub sum_num_instances: Usize<C::N>,
    pub sum_num_instances_felt: Felt<C::F>,
    pub sum_num_instances_minus_one_bit_decomposition: Array<C, Felt<C::F>>,
    pub log2_num_instances: Usize<C::N>,

    pub r_out_evals_len: Usize<C::N>,
    pub w_out_evals_len: Usize<C::N>,
    pub lk_out_evals_len: Usize<C::N>,

    pub r_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub w_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub lk_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>>,

    pub has_main_sumcheck_proofs: Usize<C::N>,
    pub main_sumcheck_proofs: IOPProverMessageVecVariable<C>,
    pub has_gkr_iop_proof: Usize<C::N>,
    pub gkr_iop_proof: GKRProofVariable<C>,
    pub tower_proof: TowerProofInputVariable<C>,
    pub has_ecc_proof: Usize<C::N>,
    pub ecc_proof: EccQuarkProofVariable<C>,
    pub num_instances: Array<C, Var<C::N>>,
    pub n_inst_0_bit_decomps: Array<C, Felt<C::F>>,
    pub n_inst_1_bit_decomps: Array<C, Felt<C::F>>,

    pub fixed_in_evals: Array<C, Ext<C::F, C::EF>>,
    pub wits_in_evals: Array<C, Ext<C::F, C::EF>>,
}
impl Hintable<InnerConfig> for ZKVMChipProofInput {
    type HintVariable = ZKVMChipProofInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let idx = Usize::Var(usize::read(builder));
        let idx_felt = F::read(builder);

        let num_instances = Vec::<usize>::read(builder);

        // derive sum_num_instances from instances vector
        let sum_num_instances = Usize::from(Var::uninit(builder));
        builder.assign(&sum_num_instances, F::ZERO);
        iter_zip!(builder, num_instances).for_each(|ptr_vec, builder| {
            let num_instance = builder.iter_ptr_get(&num_instances, ptr_vec[0]);
            builder.assign(&sum_num_instances, sum_num_instances.clone() + num_instance);
        });
        builder.assert_nonzero(&sum_num_instances);
        let sum_num_instances_felt = builder.unsafe_cast_var_to_felt(sum_num_instances.get_var());

        let sum_num_instances_minus_one_bit_decomposition = {
            let bit_decompose_hints = Vec::<F>::read(builder);
            let const_zero: Felt<_> = builder.constant(F::ZERO);
            let const_one: Felt<_> = builder.constant(F::ONE);
            let const_two: Var<_> = builder.constant(F::TWO);
            let sum = Var::uninit(builder);
            builder.assign(&sum, F::ZERO);
            let pow2_factor = Var::uninit(builder);
            builder.assign(&pow2_factor, F::ONE);
            // traverse from lsb
            iter_zip!(builder, bit_decompose_hints).for_each(|ptr_vec, builder| {
                let bit = builder.iter_ptr_get(&bit_decompose_hints, ptr_vec[0]);
                // assert bit
                builder.assert_eq::<Felt<_>>(bit * (const_one - bit), const_zero);
                let bit_var = builder.cast_felt_to_var(bit);
                builder.assign(&sum, sum + bit_var * pow2_factor);
                builder.assign(&pow2_factor, pow2_factor * const_two);
            });
            let sum_felt = builder.unsafe_cast_var_to_felt(sum);
            // assert bit decompose result match sum_num_instances_felt
            let sum_instance_minus_one: Felt<_> = builder.eval(sum_num_instances_felt - const_one);
            builder.assert_eq::<Felt<_>>(sum_felt, sum_instance_minus_one);
            bit_decompose_hints
        };

        let log2_num_instances = {
            let derived_log2 = Usize::from(Var::uninit(builder));
            // min log2_num_instances 1
            builder.assign(&derived_log2, F::ONE);
            let const_one_bit: Var<_> = builder.constant(F::ONE);
            let bit_index = Usize::from(Var::uninit(builder));
            builder.assign(&bit_index, F::ZERO);
            iter_zip!(builder, sum_num_instances_minus_one_bit_decomposition).for_each(
                |ptr_vec, builder| {
                    let bit = builder
                        .iter_ptr_get(&sum_num_instances_minus_one_bit_decomposition, ptr_vec[0]);
                    let bit_var = builder.cast_felt_to_var(bit);
                    // Bits encode (sum_num_instances - 1). Highest set bit index + 1 == ceil(log2(sum)).
                    builder.if_eq(bit_var, const_one_bit).then(|builder| {
                        builder.assign(&derived_log2, bit_index.clone() + const_one_bit);
                    });
                    builder.assign(&bit_index, bit_index.clone() + const_one_bit);
                },
            );
            derived_log2
        };

        let r_out_evals_len = Usize::Var(usize::read(builder));
        let w_out_evals_len = Usize::Var(usize::read(builder));
        let lk_out_evals_len = Usize::Var(usize::read(builder));

        let r_out_evals = Vec::<Vec<E>>::read(builder);
        let w_out_evals = Vec::<Vec<E>>::read(builder);
        let lk_out_evals = Vec::<Vec<E>>::read(builder);

        let tower_proof = TowerProofInput::read(builder);
        let has_main_sumcheck_proofs = Usize::Var(usize::read(builder));
        let main_sumcheck_proofs = IOPProverMessageVec::read(builder);
        let has_gkr_iop_proof = Usize::Var(usize::read(builder));
        let gkr_iop_proof = GKRProofInput::read(builder);
        let has_ecc_proof = Usize::Var(usize::read(builder));
        let ecc_proof = EccQuarkProofInput::read(builder);

        let n_inst_0_bit_decomps = Vec::<F>::read(builder);
        let n_inst_1_bit_decomps = Vec::<F>::read(builder);

        let fixed_in_evals = Vec::<E>::read(builder);
        let wits_in_evals = Vec::<E>::read(builder);

        ZKVMChipProofInputVariable {
            idx,
            idx_felt,
            sum_num_instances,
            sum_num_instances_felt,
            sum_num_instances_minus_one_bit_decomposition,
            log2_num_instances,
            r_out_evals_len,
            w_out_evals_len,
            lk_out_evals_len,
            r_out_evals,
            w_out_evals,
            lk_out_evals,
            has_main_sumcheck_proofs,
            main_sumcheck_proofs,
            has_gkr_iop_proof,
            gkr_iop_proof,
            tower_proof,
            has_ecc_proof,
            ecc_proof,
            num_instances,
            n_inst_0_bit_decomps,
            n_inst_1_bit_decomps,
            fixed_in_evals,
            wits_in_evals,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();

        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.idx));
        let idx_u32: F = F::from_canonical_u32(self.idx as u32);
        stream.extend(idx_u32.write());

        let num_instances = self.num_instances.iter().sum();
        stream.extend(<Vec<usize> as Hintable<InnerConfig>>::write(
            &self.num_instances,
        ));

        let sum_num_instance_bit_decomp = decompose_minus_one_bits(num_instances);
        stream.extend(sum_num_instance_bit_decomp.write());

        let r_out_evals_len = self.r_out_evals.len();
        let w_out_evals_len = self.w_out_evals.len();
        let lk_out_evals_len = self.lk_out_evals.len();

        stream.extend(<usize as Hintable<InnerConfig>>::write(&r_out_evals_len));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&w_out_evals_len));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&lk_out_evals_len));

        stream.extend(self.r_out_evals.write());
        stream.extend(self.w_out_evals.write());
        stream.extend(self.lk_out_evals.write());

        stream.extend(self.tower_proof.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.has_main_sumcheck_proofs,
        ));
        stream.extend(self.main_sumcheck_proofs.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.has_gkr_proof));
        stream.extend(self.gkr_iop_proof.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.has_ecc_proof));
        stream.extend(self.ecc_proof.write());

        let n_inst_0 = self.num_instances[0];
        let n_inst_0_bit_decomps = decompose_minus_one_bits(n_inst_0);

        let n_inst_1 = if self.num_instances.len() > 1 {
            self.num_instances[1]
        } else {
            1usize
        };
        let n_inst_1_bit_decomps = decompose_minus_one_bits(n_inst_1);

        stream.extend(n_inst_0_bit_decomps.write());
        stream.extend(n_inst_1_bit_decomps.write());

        stream.extend(self.fixed_in_evals.write());
        stream.extend(self.wits_in_evals.write());

        stream
    }
}

#[derive(Default)]
pub struct SumcheckLayerProofInput {
    pub proof: IOPProverMessageVec,
    pub evals: Vec<E>,
}
#[derive(DslVariable, Clone)]
pub struct SumcheckLayerProofVariable<C: Config> {
    pub proof: IOPProverMessageVecVariable<C>,
    pub evals: Array<C, Ext<C::F, C::EF>>,
    pub evals_len_div_3: Var<C::N>,
}
impl VecAutoHintable for SumcheckLayerProofInput {}
impl Hintable<InnerConfig> for SumcheckLayerProofInput {
    type HintVariable = SumcheckLayerProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let proof = IOPProverMessageVec::read(builder);
        let evals = Vec::<E>::read(builder);
        let evals_len_div_3 = usize::read(builder);

        Self::HintVariable {
            proof,
            evals,
            evals_len_div_3,
        }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.proof.write());
        stream.extend(self.evals.write());
        let evals_len_div_3 = self.evals.len() / 3;
        stream.extend(<usize as Hintable<InnerConfig>>::write(&evals_len_div_3));
        stream
    }
}
pub struct LayerProofInput {
    pub has_rotation: usize,
    pub rotation: SumcheckLayerProofInput,
    pub main: SumcheckLayerProofInput,
}

impl From<LayerProof<E>> for LayerProofInput {
    fn from(p: LayerProof<E>) -> Self {
        Self {
            has_rotation: if p.rotation.is_some() { 1 } else { 0 },
            rotation: if p.rotation.is_some() {
                let r = p.rotation.unwrap();
                SumcheckLayerProofInput {
                    proof: IOPProverMessageVec::from(
                        r.proof
                            .proofs
                            .iter()
                            .map(|p| IOPProverMessage {
                                evaluations: p.evaluations.clone(),
                            })
                            .collect::<Vec<IOPProverMessage>>(),
                    ),
                    evals: r.evals,
                }
            } else {
                SumcheckLayerProofInput::default()
            },
            main: SumcheckLayerProofInput {
                proof: IOPProverMessageVec::from(
                    p.main
                        .proof
                        .proofs
                        .iter()
                        .map(|p| IOPProverMessage {
                            evaluations: p.evaluations.clone(),
                        })
                        .collect::<Vec<IOPProverMessage>>(),
                ),
                evals: p.main.evals,
            },
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct LayerProofVariable<C: Config> {
    pub has_rotation: Usize<C::N>,
    pub rotation: SumcheckLayerProofVariable<C>,
    pub main: SumcheckLayerProofVariable<C>,
}
impl VecAutoHintable for LayerProofInput {}
impl Hintable<InnerConfig> for LayerProofInput {
    type HintVariable = LayerProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let has_rotation = Usize::Var(usize::read(builder));
        let rotation = SumcheckLayerProofInput::read(builder);
        let main = SumcheckLayerProofInput::read(builder);

        Self::HintVariable {
            has_rotation,
            rotation,
            main,
        }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.has_rotation));
        stream.extend(self.rotation.write());
        stream.extend(self.main.write());
        stream
    }
}
#[derive(Default)]
pub struct GKRProofInput {
    pub layer_proofs: Vec<LayerProofInput>,
}

impl From<GKRProof<E>> for GKRProofInput {
    fn from(p: GKRProof<E>) -> Self {
        Self {
            layer_proofs: p
                .0
                .into_iter()
                .map(LayerProofInput::from)
                .collect::<Vec<LayerProofInput>>(),
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct GKRProofVariable<C: Config> {
    pub layer_proofs: Array<C, LayerProofVariable<C>>,
}
impl Hintable<InnerConfig> for GKRProofInput {
    type HintVariable = GKRProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let layer_proofs = Vec::<LayerProofInput>::read(builder);
        Self::HintVariable { layer_proofs }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.layer_proofs.write());
        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct ClaimAndPoint<C: Config> {
    pub evals: Array<C, Ext<C::F, C::EF>>,
    pub has_point: Usize<C::N>,
    pub point: PointVariable<C>,
}

#[derive(DslVariable, Clone)]
pub struct RotationClaim<C: Config> {
    pub left_evals: Array<C, Ext<C::F, C::EF>>,
    pub right_evals: Array<C, Ext<C::F, C::EF>>,
    pub target_evals: Array<C, Ext<C::F, C::EF>>,
    pub left_point: Array<C, Ext<C::F, C::EF>>,
    pub right_point: Array<C, Ext<C::F, C::EF>>,
    pub origin_point: Array<C, Ext<C::F, C::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct GKRClaimEvaluation<C: Config> {
    pub value: Ext<C::F, C::EF>,
    pub point: PointVariable<C>,
    pub poly: Usize<C::N>,
}

#[derive(DslVariable, Clone)]
pub struct SepticExtensionVariable<C: Config> {
    pub vs: Array<C, Ext<C::F, C::EF>>,
}

impl<C: Config> From<Array<C, Ext<C::F, C::EF>>> for SepticExtensionVariable<C> {
    fn from(slice: Array<C, Ext<C::F, C::EF>>) -> Self {
        Self { vs: slice }
    }
}

impl<C: Config> SepticExtensionVariable<C> {
    pub fn is_zero(&self, builder: &mut Builder<C>) -> Usize<C::N> {
        let r = Usize::uninit(builder);
        builder.assign(&r, Usize::from(1));

        let zero = Usize::from(0);

        iter_zip!(builder, self.vs).for_each(|ptr_vec, builder| {
            let e = builder.iter_ptr_get(&self.vs, ptr_vec[0]);
            let fs = builder.ext2felt(e);
            builder.range(0, fs.len()).for_each(|idx_vec, builder| {
                let f = builder.get(&fs, idx_vec[0]);
                let u = Usize::Var(builder.cast_felt_to_var(f));
                builder.if_ne(u, zero.clone()).then(|builder| {
                    builder.assign(&r, Usize::from(0));
                });
            });
        });

        r
    }
}

pub struct SepticPointInput {
    x: SepticExtensionInput,
    y: SepticExtensionInput,
    is_infinity: bool,
}

#[derive(DslVariable, Clone)]
pub struct SepticPointVariable<C: Config> {
    pub x: SepticExtensionVariable<C>,
    pub y: SepticExtensionVariable<C>,
    pub is_infinity: Usize<C::N>,
}

pub struct EccQuarkProofInput {
    pub zerocheck_proof: IOPProof<E>,
    pub num_instances: usize,
    pub evals: Vec<E>, // x[rt,0], x[rt,1], y[rt,0], y[rt,1], x[0,rt], y[0,rt], s[0,rt]
    pub rt: Point<E>,
    pub sum: SepticPointInput,
}

impl EccQuarkProofInput {
    pub fn dummy() -> Self {
        Self {
            zerocheck_proof: IOPProof { proofs: Vec::new() },
            num_instances: 0,
            evals: Vec::new(),
            rt: Vec::new(),
            sum: SepticPointInput {
                x: SepticExtensionInput { v: [F::ZERO; 7] },
                y: SepticExtensionInput { v: [F::ZERO; 7] },
                is_infinity: false,
            },
        }
    }
}

impl From<EccQuarkProof<E>> for EccQuarkProofInput {
    fn from(proof: EccQuarkProof<E>) -> Self {
        Self {
            zerocheck_proof: proof.zerocheck_proof,
            num_instances: proof.num_instances,
            evals: proof.evals,
            rt: proof.rt,
            sum: SepticPointInput {
                x: SepticExtensionInput { v: proof.sum.x.0 },
                y: SepticExtensionInput { v: proof.sum.y.0 },
                is_infinity: proof.sum.is_infinity,
            },
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct EccQuarkProofVariable<C: Config> {
    pub zerocheck_proof: IOPProverMessageVecVariable<C>,
    pub num_instances: Usize<C::N>,
    pub num_instances_layered_ns: Array<C, Var<C::N>>,
    pub num_instances_bit_decomps: Array<C, Array<C, Felt<C::F>>>,
    pub num_vars: Usize<C::N>, // next_pow2_instance_padding(proof.num_instances).ilog2()
    pub evals: Array<C, Ext<C::F, C::EF>>,
    pub rt: PointVariable<C>,
    pub sum: SepticPointVariable<C>,
}

impl Hintable<InnerConfig> for EccQuarkProofInput {
    type HintVariable = EccQuarkProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let zerocheck_proof = IOPProverMessageVec::read(builder);
        let num_instances = Usize::Var(usize::read(builder));
        let num_instances_layered_ns = Vec::<usize>::read(builder);
        let num_instances_bit_decomps = Vec::<Vec<F>>::read(builder);
        let num_vars = Usize::Var(usize::read(builder));
        let evals = Vec::<E>::read(builder);
        let rt_vec = Vec::<E>::read(builder);
        let rt = PointVariable { fs: rt_vec };
        let sum = SepticPointInput::read(builder);

        EccQuarkProofVariable {
            zerocheck_proof,
            num_instances,
            num_instances_layered_ns,
            num_instances_bit_decomps,
            num_vars,
            evals,
            rt,
            sum,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();

        let p_vec = IOPProverMessageVec::from(
            self.zerocheck_proof
                .proofs
                .clone()
                .into_iter()
                .map(|p| IOPProverMessage {
                    evaluations: p.evaluations,
                })
                .collect::<Vec<IOPProverMessage>>(),
        );
        stream.extend(p_vec.write());

        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.num_instances));
        let (ns, n_bits) = decompose_prefixed_layer_bits(self.num_instances);
        stream.extend(<Vec<usize> as Hintable<InnerConfig>>::write(&ns));
        stream.extend(<Vec<Vec<F>> as Hintable<InnerConfig>>::write(&n_bits));

        let num_vars = next_pow2_instance_padding(self.num_instances).ilog2() as usize;
        stream.extend(<usize as Hintable<InnerConfig>>::write(&num_vars));
        stream.extend(self.evals.write());
        stream.extend(self.rt.write());
        stream.extend(self.sum.write());

        stream
    }
}

pub struct SepticExtensionInput {
    v: [F; 7],
}

impl Hintable<InnerConfig> for SepticExtensionInput {
    type HintVariable = SepticExtensionVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let f_vec = Vec::<E>::read(builder);

        SepticExtensionVariable { vs: f_vec }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        let f_vec = self.v.to_vec();
        let e_vec: Vec<E> = f_vec.into_iter().map(E::from_base).collect();
        stream.extend(e_vec.write());
        stream
    }
}

impl Hintable<InnerConfig> for SepticPointInput {
    type HintVariable = SepticPointVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let x = SepticExtensionInput::read(builder);
        let y = SepticExtensionInput::read(builder);
        let is_infinity = Usize::Var(usize::read(builder));

        SepticPointVariable { x, y, is_infinity }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.x.write());
        stream.extend(self.y.write());

        if self.is_infinity {
            stream.extend(<usize as Hintable<InnerConfig>>::write(&1usize));
        } else {
            stream.extend(<usize as Hintable<InnerConfig>>::write(&0usize));
        }

        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct SelectorContextVariable<C: Config> {
    pub offset: Usize<C::N>,
    pub offset_bit_decomps: Array<C, Felt<C::F>>,
    pub num_instances: Usize<C::N>,
    pub num_instances_layered_ns: Array<C, Var<C::N>>,
    pub num_instances_bit_decomps: Array<C, Array<C, Felt<C::F>>>,
    pub offset_instance_sum_bit_decomps: Array<C, Felt<C::F>>,
    pub num_vars: Usize<C::N>,
}
