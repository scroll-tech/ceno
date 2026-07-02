use core::borrow::Borrow;

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::tower::bus::{
    TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage, TowerSumcheckInputBus,
    TowerSumcheckInputMessage, TowerSumcheckOutputBus, TowerSumcheckOutputMessage,
};
use recursion_circuit::{
    bus::{TranscriptBus, XiRandomnessBus},
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{
        assert_one_ext, ext_field_add, ext_field_multiply, ext_field_multiply_scalar,
        ext_field_one_minus, ext_field_subtract,
    },
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLayerSumcheckCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,
    pub proof_idx: T,
    pub chip_idx: T,
    pub layer_idx: T,
    pub is_first_idx: T,
    pub is_first_layer: T,
    pub is_first_round: T,

    /// Placeholder row for a chip whose tower has 0 or 1 layer, and
    /// therefore has no real layer-sumcheck rows.
    pub is_noop: T,

    pub is_last_layer: T,

    /// Sumcheck sub-round index within this layer_idx (0..layer_idx-1)
    // perf(ayush): can probably remove round if XiRandomnessMessage takes tidx instead
    pub round: T,

    /// Transcript index
    pub tidx: T,

    /// s(1) in extension field
    pub ev1: [T; D_EF],
    /// s(2) in extension field
    pub ev2: [T; D_EF],
    /// s(3) in extension field
    pub ev3: [T; D_EF],

    /// The claim coming into this sub-round (either from previous sub-round or initial)
    pub claim_in: [T; D_EF],
    /// The claim going out of this sub-round (result of cubic interpolation)
    pub claim_out: [T; D_EF],

    /// Component `round` of the original point ξ^{(j-1)}
    /// (corresponding to `gkr_r[round]`)
    pub prev_challenge: [T; D_EF],
    /// The sampled challenge for this sub-round (corresponds to `ri`)
    pub challenge: [T; D_EF],

    /// The eq value coming into this sub-round
    pub eq_in: [T; D_EF],
    /// The eq value going out (updated for this round)
    pub eq_out: [T; D_EF],
}

pub struct TowerLayerSumcheckAir {
    pub transcript_bus: TranscriptBus,
    pub xi_randomness_bus: XiRandomnessBus,
    pub sumcheck_input_bus: TowerSumcheckInputBus,
    pub sumcheck_output_bus: TowerSumcheckOutputBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
}

impl TowerLayerSumcheckAir {
    pub fn new(
        transcript_bus: TranscriptBus,
        xi_randomness_bus: XiRandomnessBus,
        sumcheck_input_bus: TowerSumcheckInputBus,
        sumcheck_output_bus: TowerSumcheckOutputBus,
        sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    ) -> Self {
        Self {
            transcript_bus,
            xi_randomness_bus,
            sumcheck_input_bus,
            sumcheck_output_bus,
            sumcheck_challenge_bus,
        }
    }
}

impl<F: Field> BaseAir<F> for TowerLayerSumcheckAir {
    fn width(&self) -> usize {
        TowerLayerSumcheckCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerLayerSumcheckAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerLayerSumcheckAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerLayerSumcheckAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerLayerSumcheckCols<AB::Var> = (*local).borrow();
        let next: &TowerLayerSumcheckCols<AB::Var> = (*next).borrow();

        ///////////////////////////////////////////////////////////////////////
        // Boolean Constraints
        ///////////////////////////////////////////////////////////////////////

        builder.assert_bool(local.is_noop);
        builder.assert_bool(local.is_last_layer);

        ///////////////////////////////////////////////////////////////////////
        // Proof Index and Loop Constraints
        ///////////////////////////////////////////////////////////////////////

        type LoopSubAir = NestedForLoopSubAir<3>;

        // The public/bus-facing layer index is 1-based. NestedForLoopSubAir
        // requires each counter to start from 0, so it receives layer_idx - 1.
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled.into(),
                    counter: [
                        local.proof_idx.into(),
                        local.chip_idx.into(),
                        local.layer_idx.into() - AB::Expr::ONE,
                    ],
                    is_first: [
                        local.is_first_idx.into(),
                        local.is_first_layer.into(),
                        local.is_first_round.into(),
                    ],
                },
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled.into(),
                    counter: [
                        next.proof_idx.into(),
                        next.chip_idx.into(),
                        next.layer_idx.into() - AB::Expr::ONE,
                    ],
                    is_first: [
                        next.is_first_idx.into(),
                        next.is_first_layer.into(),
                        next.is_first_round.into(),
                    ],
                },
            ),
        );

        let is_transition_round: AB::Expr =
            LoopSubAir::local_is_transition(next.is_enabled, next.is_first_round);
        let is_last_round: AB::Expr =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first_round);
        let is_last_chip: AB::Expr =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first_layer);

        // A no-op row stands in for a chip with no tower sumcheck proof. It must
        // be a single enabled row for the whole chip-local segment.
        builder.when(local.is_noop).assert_one(local.is_enabled);
        builder.when(local.is_noop).assert_one(local.is_first_layer);
        builder.when(local.is_noop).assert_one(local.is_first_round);
        builder.when(local.is_noop).assert_one(is_last_chip.clone());

        // is_last_layer is bound by TowerSumcheckInputBus on the first round.
        // Keep it fixed across the layer and check it against the chip boundary
        // at the layer's final round.
        builder
            .when(is_transition_round.clone())
            .assert_eq(next.is_last_layer, local.is_last_layer);
        builder
            .when(is_last_round.clone())
            .assert_eq(local.is_last_layer, is_last_chip.clone());

        // Sumcheck round flag starts at 0
        builder.when(local.is_first_round).assert_zero(local.round);
        // Sumcheck round flag increments by 1
        builder
            .when(is_transition_round.clone())
            .assert_eq(next.round, local.round + AB::Expr::ONE);
        // Sumcheck round flag end
        builder
            .when(is_last_round.clone())
            .assert_eq(local.round, local.layer_idx - AB::Expr::ONE);

        ///////////////////////////////////////////////////////////////////////
        // Round Constraints
        ///////////////////////////////////////////////////////////////////////

        // Eq initialization: eq_in = 1 at first round
        assert_one_ext(&mut builder.when(local.is_first_round), local.eq_in);

        // Eq update: incrementally compute eq *= (xi * ri + (1-xi) * (1-ri))
        let eq_out: [AB::Expr; D_EF] =
            update_eq(local.eq_in, local.prev_challenge, local.challenge);
        assert_array_eq(&mut builder.when(local.is_enabled), local.eq_out, eq_out);

        // Eq propagation
        assert_array_eq(
            &mut builder.when(is_transition_round.clone()),
            local.eq_out,
            next.eq_in,
        );

        // Compute s(0) = claim_in - s(1)
        let ev0: [AB::Expr; D_EF] = ext_field_subtract(local.claim_in, local.ev1);

        // Cubic interpolation: compute claim_out from polynomial evals at 0,1,2,3
        let claim_out: [AB::Expr; D_EF] =
            interpolate_cubic_at_0123(ev0, local.ev1, local.ev2, local.ev3, local.challenge);
        assert_array_eq(builder, local.claim_out, claim_out);

        // Claim propagation
        assert_array_eq(
            &mut builder.when(is_transition_round.clone()),
            local.claim_out,
            next.claim_in,
        );

        // Transcript index increment
        use crate::tower::tower_transcript_len::{
            LABEL_INTERNAL_ROUND, LABEL_INTERNAL_ROUND_VALUES, ROUND_LEN,
        };
        builder.when(is_transition_round.clone()).assert_eq(
            next.tidx,
            local.tidx.into() + AB::Expr::from_usize(ROUND_LEN),
        );

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let is_not_noop = AB::Expr::ONE - local.is_noop;

        // 1. TowerSumcheckInputBus
        // 1a. Receive initial sumcheck input on first round
        self.sumcheck_input_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckInputMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                is_last_layer: local.is_last_layer.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            local.is_first_round * is_not_noop.clone(),
        );
        // 2. TowerSumcheckOutputBus
        // 2a. Send output back to TowerLayerAir on final round
        self.sumcheck_output_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckOutputMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into() + AB::Expr::from_usize(ROUND_LEN),
                claim_out: local.claim_out.map(Into::into),
                eq_at_r_prime: local.eq_out.map(Into::into),
            },
            is_last_round.clone() * is_not_noop.clone(),
        );

        // 3. TowerSumcheckChallengeBus
        // 3a. Receive challenge from previous GKR layer_idx sumcheck
        self.sumcheck_challenge_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx - AB::Expr::ONE,
                sumcheck_round: local.round.into(),
                challenge: local.prev_challenge.map(Into::into),
            },
            local.is_enabled * is_not_noop.clone(),
        );
        // 3b. Send challenge to next GKR layer_idx sumcheck for eq calculation
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                sumcheck_round: local.round.into(),
                challenge: local.challenge.map(Into::into),
            },
            local.is_enabled * (AB::Expr::ONE - local.is_last_layer) * is_not_noop.clone(),
        );

        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TranscriptBus
        // 1a. Observe evaluations
        let mut tidx = local.tidx.into();
        for eval in [local.ev1, local.ev2, local.ev3].into_iter() {
            self.transcript_bus.observe_ext(
                builder,
                local.proof_idx,
                tidx.clone(),
                eval,
                local.is_enabled * is_not_noop.clone(),
            );
            tidx += AB::Expr::from_usize(D_EF);
        }
        for (i, value) in LABEL_INTERNAL_ROUND_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                local.is_enabled * is_not_noop.clone(),
            );
        }
        tidx += AB::Expr::from_usize(LABEL_INTERNAL_ROUND);
        // 1b. Sample challenge `ri`
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            tidx,
            local.challenge,
            local.is_enabled * is_not_noop.clone(),
        );

        let _ = &self.xi_randomness_bus;
    }
}

/// Interpolates a cubic polynomial at a point using evaluations at 0, 1, 2, 3.
///
/// Given evaluations `claim_in, ev1, ev2, ev3` (where ev0 = claim_in - ev1) and a point `x`,
/// computes `f(x)` using Lagrange interpolation optimized for these specific points.
pub(super) fn interpolate_cubic_at_0123<F, FA>(
    ev0: [FA; D_EF],
    ev1: [F; D_EF],
    ev2: [F; D_EF],
    ev3: [F; D_EF],
    x: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let three: FA = FA::from_usize(3);
    let inv2: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(2).inverse());
    let inv6: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(6).inverse());

    // s1 = ev1 - ev0
    let s1: [FA; D_EF] = ext_field_subtract(ev1, ev0.clone());
    // s2 = ev2 - ev0
    let s2: [FA; D_EF] = ext_field_subtract(ev2, ev0.clone());
    // s3 = ev3 - ev0
    let s3: [FA; D_EF] = ext_field_subtract(ev3, ev0.clone());

    // d3 = s3 - (s2 - s1) * 3
    let d3: [FA; D_EF] = ext_field_subtract::<FA>(
        s3,
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2.clone(), s1.clone()), three),
    );

    // p = d3 / 6
    let p: [FA; D_EF] = ext_field_multiply_scalar(d3.clone(), inv6);

    // q = (s2 - d3) / 2 - s1
    let q: [FA; D_EF] = ext_field_subtract::<FA>(
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2, d3), inv2),
        s1.clone(),
    );

    // r = s1 - p - q
    let r: [FA; D_EF] = ext_field_subtract::<FA>(s1, ext_field_add::<FA>(p.clone(), q.clone()));

    // result = ((p * x + q) * x + r) * x + ev0
    ext_field_add::<FA>(
        ext_field_multiply::<FA>(
            ext_field_add::<FA>(
                ext_field_multiply::<FA>(ext_field_add::<FA>(ext_field_multiply::<FA>(p, x), q), x),
                r,
            ),
            x,
        ),
        ev0,
    )
}

/// Updates the eq evaluation incrementally for one sumcheck round.
///
/// Computes: `eq_out = eq_in * (prev_challenge * challenge + (1 - prev_challenge) * (1 -
/// challenge))` where `prev_challenge` is xi and `challenge` is ri.
pub(super) fn update_eq<F, FA>(
    eq_in: [F; D_EF],
    prev_challenge: [F; D_EF],
    challenge: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    ext_field_multiply::<FA>(
        eq_in,
        ext_field_add::<FA>(
            ext_field_multiply::<FA>(prev_challenge, challenge),
            ext_field_multiply::<FA>(
                ext_field_one_minus::<FA>(prev_challenge),
                ext_field_one_minus::<FA>(challenge),
            ),
        ),
    )
}
