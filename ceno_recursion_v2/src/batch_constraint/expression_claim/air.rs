use std::borrow::Borrow;

use openvm_circuit_primitives::utils::{assert_array_eq, not};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    batch_constraint::bus::{
        BatchConstraintConductorBus, BatchConstraintConductorMessage,
        BatchConstraintInnerMessageType, EqNOuterBus, EqNOuterMessage, ExpressionClaimBus,
        ExpressionClaimMessage,
    },
    bus::{
        ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage, HyperdimBus, HyperdimBusMessage,
        MainExpressionClaimBus, MainExpressionClaimMessage,
    },
    primitives::bus::{PowerCheckerBus, PowerCheckerBusMessage},
    utils::{base_to_ext, ext_field_add, ext_field_multiply, ext_field_multiply_scalar},
};

/// For each proof, this AIR will receive 2t interaction claims and t constraint claims.
/// (2 interaction claims and 1 constraint claim per trace).
/// These values are folded (algebraic batching) with mu into a single value, which
/// should match the final sumcheck claim.
#[derive(AlignedBorrow, Copy, Clone, Debug)]
#[repr(C)]
pub struct ExpressionClaimCols<T> {
    pub is_valid: T,
    pub is_first: T,
    pub proof_idx: T,

    pub is_interaction: T,
    /// Index within the proof, 0 ~ 2t-1 are interaction claims, 0~t-1 are constraint claims.
    pub idx: T,
    pub idx_parity: T,
    pub trace_idx: T,
    /// The received evaluation claim. Note that for interactions, this is without norm_factor and
    /// eq_sharp_ns. These are interactions_evals (without norm_factor and eq_sharp_ns) and
    /// constraint_evals in the rust verifier.
    pub value: [T; D_EF],
    /// Receive from eq_ns AIR
    pub eq_sharp_ns: [T; D_EF],

    /// For folding with mu.
    pub cur_sum: [T; D_EF],
    pub mu: [T; D_EF],
    pub multiplier: [T; D_EF],

    /// Need to know n as if n<0, we need to multiply some norm_factor.
    pub n_abs: T,
    pub n_abs_pow: T,
    pub n_sign: T,
    /// The round idx for final sumcheck claim.
    pub num_multilinear_sumcheck_rounds: T,
}

pub struct ExpressionClaimAir {
    pub expression_claim_n_max_bus: ExpressionClaimNMaxBus,
    pub expr_claim_bus: ExpressionClaimBus,
    pub mu_bus: BatchConstraintConductorBus,
    pub main_claim_bus: MainExpressionClaimBus,
    pub eq_n_outer_bus: EqNOuterBus,
    pub pow_checker_bus: PowerCheckerBus,
    pub hyperdim_bus: HyperdimBus,
}

impl<F> BaseAirWithPublicValues<F> for ExpressionClaimAir {}
impl<F> PartitionedBaseAir<F> for ExpressionClaimAir {}

impl<F> BaseAir<F> for ExpressionClaimAir {
    fn width(&self) -> usize {
        ExpressionClaimCols::<F>::width()
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ExpressionClaimAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
    /* debug block: Step 1 placeholder - all constraints deferred pending trace implementation */
    #[allow(unused_variables)]
    let _ = &builder;
    }
}
