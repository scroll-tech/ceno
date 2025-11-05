use crate::arithmetics::next_pow2_instance_padding;
use crate::basefold_verifier::basefold::{
    BasefoldCommitment, BasefoldCommitmentVariable, BasefoldProof, BasefoldProofVariable,
};

use crate::tower_verifier::binding::{
    IOPProverMessageVariable, IOPProverMessageVec, IOPProverMessageVecVariable,
    ThreeDimensionalVecVariable, ThreeDimensionalVector,
};
use crate::{arithmetics::ceil_log2, tower_verifier::binding::PointVariable};
use itertools::Itertools;
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config, Felt},
    prelude::*,
};
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::hints::{Hintable, VecAutoHintable};
use openvm_stark_backend::p3_field::{extension::BinomialExtensionField, FieldAlgebra};
use openvm_stark_sdk::p3_baby_bear::BabyBear;

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, 4>;
pub type InnerConfig = AsmConfig<F, E>;

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

#[derive(DslVariable, Clone)]
pub struct TowerProofInputVariable<C: Config> {
    pub num_proofs: Usize<C::N>,
    pub proofs: Array<C, IOPProverMessageVecVariable<C>>,
    pub num_prod_specs: Usize<C::N>,
    pub prod_specs_eval: ThreeDimensionalVecVariable<C>,
    pub num_logup_specs: Usize<C::N>,
    pub logup_specs_eval: ThreeDimensionalVecVariable<C>,
}

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

pub(crate) struct ZKVMProofInput {
    pub raw_pi: Vec<Vec<F>>,
    // Evaluation of raw_pi.
    pub pi_evals: Vec<E>,
    pub chip_proofs: Vec<ZKVMChipProofInput>,
    pub witin_commit: BasefoldCommitment,
    pub pcs_proof: BasefoldProof,
}

impl Hintable<InnerConfig> for ZKVMProofInput {
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
    // this is the number of instructions before padding
    // it's possible that an instruction has multiple rows.
    pub num_instances: usize,
    // this is the number of variables of each polynomial in the witness matrix
    pub num_vars: usize,

    // product constraints
    pub record_r_out_evals_len: usize,
    pub record_w_out_evals_len: usize,
    pub record_lk_out_evals_len: usize,
    pub record_r_out_evals: Vec<Vec<E>>,
    pub record_w_out_evals: Vec<Vec<E>>,
    pub record_lk_out_evals: Vec<Vec<E>>,

    pub tower_proof: TowerProofInput,

    // main constraint and select sumcheck proof
    pub main_sumcheck_proofs: IOPProverMessageVec,
    pub wits_in_evals: Vec<E>,
    pub fixed_in_evals: Vec<E>,

    // gkr proof
    pub has_gkr_proof: bool,
    pub gkr_iop_proof: GKRProofInput,
}

impl VecAutoHintable for ZKVMChipProofInput {}

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
    pub num_var_with_rotation: usize,
    pub num_instances: usize,
    pub layer_proofs: Vec<LayerProofInput>,
}
#[derive(DslVariable, Clone)]
pub struct GKRProofVariable<C: Config> {
    pub num_var_with_rotation: Usize<C::N>,
    pub num_instances_minus_one_bit_decomposition: Array<C, Felt<C::F>>,
    pub layer_proofs: Array<C, LayerProofVariable<C>>,
}
impl Hintable<InnerConfig> for GKRProofInput {
    type HintVariable = GKRProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let num_var_with_rotation = Usize::Var(usize::read(builder));
        let num_instances_minus_one_bit_decomposition = Vec::<F>::read(builder);
        let layer_proofs = Vec::<LayerProofInput>::read(builder);
        Self::HintVariable {
            num_var_with_rotation,
            num_instances_minus_one_bit_decomposition,
            layer_proofs,
        }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.num_var_with_rotation,
        ));

        let eq_instance = self.num_instances - 1;
        let mut bit_decomp: Vec<F> = vec![];
        for i in 0..32usize {
            bit_decomp.push(F::from_canonical_usize((eq_instance >> i) & 1));
        }
        stream.extend(bit_decomp.write());
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

#[derive(DslVariable, Clone)]
pub struct SepticPointVariable<C: Config> {
    x: SepticExtensionVariable<C>,
    y: SepticExtensionVariable<C>,
    is_infinity: Usize<C::N>,
}

#[derive(DslVariable, Clone)]
pub struct EccQuarkProofVariable<C: Config> {
    pub zerocheck_proof: IOPProverMessageVecVariable<C>,
    pub num_instances: Usize<C::N>,
    pub num_instances_minus_one_bit_decomposition: Array<C, Felt<C::F>>,
    pub num_vars: Usize<C::N>, // next_pow2_instance_padding(proof.num_instances).ilog2()
    pub evals: Array<C, Ext<C::F, C::EF>>,
    pub rt: PointVariable<C>,
    pub sum: SepticPointVariable<C>,
    pub prefix_one_seq: Array<C, Usize<C::N>>,
}
