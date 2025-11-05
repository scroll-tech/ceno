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
