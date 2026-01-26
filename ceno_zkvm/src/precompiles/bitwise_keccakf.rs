use crate::scheme::utils::gkr_witness;
use ff_ext::ExtensionField;
use itertools::{Itertools, iproduct, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    ChallengeId, Expression, ToExpr, WitIn,
    mle::{MultilinearExtension, Point, PointAndEval},
    util::ceil_log2,
};
use p3::{field::FieldAlgebra, util::indices_arr};
use std::{array::from_fn, mem::transmute, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use tiny_keccak::keccakf;
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    cpu::{CpuBackend, CpuProver},
    error::CircuitBuilderError,
    evaluation::EvalExpression,
    gkr::{
        GKRCircuit, GKRProverOutput,
        booleanhypercube::CYCLIC_POW2_5,
        layer::Layer,
        layer_constraint_system::{LayerConstraintSystem, expansion_expr},
    },
    selector::{SelectorContext, SelectorType},
    utils::{indices_arr_with_offset, lk_multiplicity::LkMultiplicity, wits_fixed_and_eqs},
};

fn to_xyz(i: usize) -> (usize, usize, usize) {
    assert!(i < STATE_SIZE);
    (i / 64 % 5, (i / 64) / 5, i % 64)
}

fn from_xyz(x: usize, y: usize, z: usize) -> usize {
    64 * (5 * y + x) + z
}

fn and_expr<E: ExtensionField>(a: Expression<E>, b: Expression<E>) -> Expression<E> {
    a.clone() * b.clone()
}

fn not_expr<E: ExtensionField>(a: Expression<E>) -> Expression<E> {
    one_expr() - a
}

fn xor_expr<E: ExtensionField>(a: Expression<E>, b: Expression<E>) -> Expression<E> {
    a.clone() + b.clone() - E::BaseField::from_canonical_u32(2).expr() * a * b
}

fn zero_expr<E: ExtensionField>() -> Expression<E> {
    E::BaseField::ZERO.expr()
}

fn one_expr<E: ExtensionField>() -> Expression<E> {
    E::BaseField::ONE.expr()
}

fn c_expr<E: ExtensionField>(x: usize, z: usize, state_wits: &[Expression<E>]) -> Expression<E> {
    (0..5)
        .map(|y| state_wits[from_xyz(x, y, z)].clone())
        .fold(zero_expr(), xor_expr)
}

fn from_xz(x: usize, z: usize) -> usize {
    x * 64 + z
}

fn d_expr<E: ExtensionField>(x: usize, z: usize, c_wits: &[Expression<E>]) -> Expression<E> {
    let lhs = from_xz((x + 5 - 1) % 5, z);
    let rhs = from_xz((x + 1) % 5, (z + 64 - 1) % 64);
    xor_expr(c_wits[lhs].clone(), c_wits[rhs].clone())
}

fn keccak_phase1_witness<E: ExtensionField>(states: &[[u64; 25]]) -> RowMajorMatrix<E::BaseField> {
    let num_states = states.len();
    assert!(num_states.is_power_of_two());
    let mut values = vec![E::BaseField::ONE; STATE_SIZE * num_states];

    for (state_idx, state) in states.iter().enumerate() {
        for (word_idx, &word) in state.iter().enumerate() {
            for bit_idx in 0..64 {
                let bit = ((word >> bit_idx) & 1) == 1;
                values[state_idx * STATE_SIZE + word_idx * 64 + bit_idx] =
                    E::BaseField::from_bool(bit);
            }
        }
    }

    let mut rmm =
        RowMajorMatrix::new_by_values(values, STATE_SIZE, InstancePaddingStrategy::Default);
    rmm.padding_by_strategy();
    rmm
}

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

const X: usize = 5;
const Y: usize = 5;
const Z: usize = 64;
const STATE_SIZE: usize = X * Y * Z;
const C_SIZE: usize = X * Z;
const D_SIZE: usize = X * Z;

const KECCAK_OUTPUT32_SIZE: usize = 50;
const KECCAK_INPUT32_SIZE: usize = 50;

const KECCAK_OUT_EVAL_SIZE: usize = size_of::<KeccakOutEvals<u8>>();
const KECCAK_ALL_IN_EVAL_SIZE: usize = size_of::<KeccakInEvals<u8>>();

#[derive(Clone, Debug)]
pub struct KeccakParams;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakOutEvals<T> {
    pub output32: [T; KECCAK_OUTPUT32_SIZE],
    pub input32: [T; KECCAK_INPUT32_SIZE],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Output32Layer<WitT, EqT> {
    output: [WitT; STATE_SIZE],
    sel: EqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct IotaLayer<WitT, EqT> {
    chi_output: [WitT; Z],
    eq: EqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct RhoPiAndChiLayer<WitT, EqT> {
    theta_output: [WitT; STATE_SIZE],
    eq_round_out: EqT,
    eq_iota: EqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ThetaThirdLayer<WitT, EqT> {
    d: [WitT; D_SIZE],
    state_copy: [WitT; STATE_SIZE],
    eq: EqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ThetaSecondLayer<WitT, EqT> {
    c: [WitT; C_SIZE],
    eq: EqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ThetaFirstLayer<WitT, EqT, OptionEqT> {
    round_input: [WitT; STATE_SIZE],
    eq_c: EqT,
    eq_copy: EqT,
    sel_keccak_out: OptionEqT,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakRound<WitT, EqT, OptionEqT> {
    iota: IotaLayer<WitT, EqT>,
    rho_pi_and_chi: RhoPiAndChiLayer<WitT, EqT>,
    theta_third: ThetaThirdLayer<WitT, EqT>,
    theta_second: ThetaSecondLayer<WitT, EqT>,
    theta_first: ThetaFirstLayer<WitT, EqT, OptionEqT>,
}

const OUTPUT32_WIT_SIZE: usize = size_of::<Output32Layer<u8, ()>>();
const IOTA_WIT_SIZE: usize = size_of::<IotaLayer<u8, ()>>();
const RHO_PI_AND_CHI_WIT_SIZE: usize = size_of::<RhoPiAndChiLayer<u8, ()>>();
const THETA_THIRD_WIT_SIZE: usize = size_of::<ThetaThirdLayer<u8, ()>>();
const THETA_SECOND_WIT_SIZE: usize = size_of::<ThetaSecondLayer<u8, ()>>();
const THETA_FIRST_WIT_SIZE: usize = size_of::<ThetaFirstLayer<u8, (), ()>>();

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakRoundEval<T> {
    iota: [T; IOTA_WIT_SIZE],
    rho_pi_and_chi: [T; RHO_PI_AND_CHI_WIT_SIZE],
    theta_third: [T; THETA_THIRD_WIT_SIZE],
    theta_second: [T; THETA_SECOND_WIT_SIZE],
    theta_first: [T; THETA_FIRST_WIT_SIZE],
}

#[derive(Clone, Debug)]
pub struct KeccakLayers<WitT, EqT> {
    pub output32: Output32Layer<WitT, EqT>,
    pub inner_rounds: [KeccakRound<WitT, EqT, ()>; 23],
    pub first_round: KeccakRound<WitT, EqT, EqT>,
}

#[derive(Clone, Debug)]
pub struct KeccakInEvals<T> {
    pub output32: [T; STATE_SIZE],
    pub inner_rounds: [KeccakRoundEval<T>; 23],
    pub first_round: KeccakRoundEval<T>,
}

#[derive(Clone, Debug)]
pub struct KeccakLayout<E: ExtensionField> {
    pub layers: KeccakLayers<WitIn, WitIn>,
    pub layer_in_evals: KeccakInEvals<usize>,
    pub final_out_evals: KeccakOutEvals<usize>,
    pub alpha: Expression<E>,
    pub beta: Expression<E>,
}

#[allow(clippy::missing_transmute_annotations)]
fn allocate_round<OptionEqT>(
    theta_first: fn() -> ThetaFirstLayer<WitIn, WitIn, OptionEqT>,
) -> KeccakRound<WitIn, WitIn, OptionEqT> {
    const IOTA_EQ_SIZE: usize = std::mem::size_of::<IotaLayer<(), u8>>();
    const RHO_PI_AND_CHI_EQ_SIZE: usize = std::mem::size_of::<RhoPiAndChiLayer<(), u8>>();
    const THETA_THIRD_EQ_SIZE: usize = std::mem::size_of::<ThetaThirdLayer<(), u8>>();
    const THETA_SECOND_EQ_SIZE: usize = std::mem::size_of::<ThetaSecondLayer<(), u8>>();

    let iota = wits_fixed_and_eqs::<IOTA_WIT_SIZE, 0, IOTA_EQ_SIZE>();
    let iota = IotaLayer {
        chi_output: iota.0,
        eq: iota.2[0],
    };

    let (theta_output, _, [eq_round_out, eq_iota]) =
        wits_fixed_and_eqs::<RHO_PI_AND_CHI_WIT_SIZE, 0, RHO_PI_AND_CHI_EQ_SIZE>();
    let rho_pi_and_chi = RhoPiAndChiLayer {
        theta_output,
        eq_round_out,
        eq_iota,
    };

    let (theta_third_input, _, [eq]) =
        wits_fixed_and_eqs::<THETA_THIRD_WIT_SIZE, 0, THETA_THIRD_EQ_SIZE>();
    let (d, state_copy) = unsafe { transmute(theta_third_input) };
    let theta_third = ThetaThirdLayer { d, state_copy, eq };

    let (c, _, [eq]) = wits_fixed_and_eqs::<THETA_SECOND_WIT_SIZE, 0, THETA_SECOND_EQ_SIZE>();
    let theta_second = ThetaSecondLayer { c, eq };

    let theta_first = theta_first();
    KeccakRound {
        iota,
        rho_pi_and_chi,
        theta_third,
        theta_second,
        theta_first,
    }
}

impl<E: ExtensionField> Default for KeccakLayout<E> {
    #[allow(clippy::missing_transmute_annotations)]
    fn default() -> Self {
        // allocate evaluation expressions
        let final_out_evals = {
            let final_out_evals = indices_arr::<KECCAK_OUT_EVAL_SIZE>();
            unsafe {
                transmute::<[usize; KECCAK_OUT_EVAL_SIZE], KeccakOutEvals<usize>>(final_out_evals)
            }
        };

        let layer_in_evals = {
            let layer_in_evals =
                indices_arr_with_offset::<KECCAK_ALL_IN_EVAL_SIZE, KECCAK_OUT_EVAL_SIZE>();
            unsafe {
                transmute::<[usize; KECCAK_ALL_IN_EVAL_SIZE], KeccakInEvals<usize>>(layer_in_evals)
            }
        };

        // allocate witnesses, fixed, and eqs
        let layers = {
            let (output, _, [sel]) = wits_fixed_and_eqs::<OUTPUT32_WIT_SIZE, 0, 1>();
            let output32 = Output32Layer { output, sel };
            let inner_rounds = from_fn(|_| {
                allocate_round(|| {
                    const THETA_FIRST_EQ_SIZE: usize = size_of::<ThetaFirstLayer<(), u8, ()>>();
                    let (round_input, _, eqs) =
                        wits_fixed_and_eqs::<THETA_FIRST_WIT_SIZE, 0, THETA_FIRST_EQ_SIZE>();
                    let (eq_c, eq_copy) = unsafe { transmute(eqs) };
                    ThetaFirstLayer {
                        round_input,
                        eq_c,
                        eq_copy,
                        sel_keccak_out: (),
                    }
                })
            });
            let first_round = allocate_round(|| {
                const KECCAK_FIRST_EQ_SIZE: usize = size_of::<ThetaFirstLayer<(), u8, u8>>();
                let (round_input, _, eqs) =
                    wits_fixed_and_eqs::<THETA_FIRST_WIT_SIZE, 0, KECCAK_FIRST_EQ_SIZE>();
                let (eq_c, eq_copy, sel_keccak_out) = unsafe { transmute(eqs) };
                ThetaFirstLayer {
                    round_input,
                    eq_c,
                    eq_copy,
                    sel_keccak_out,
                }
            });
            KeccakLayers {
                output32,
                inner_rounds,
                first_round,
            }
        };

        Self {
            layers,
            layer_in_evals,
            final_out_evals,
            alpha: Expression::Challenge(0 as ChallengeId, 1, E::ONE, E::ZERO),
            beta: Expression::Challenge(1 as ChallengeId, 1, E::ONE, E::ZERO),
        }
    }
}

fn output32_layer<E: ExtensionField>(
    layer: &Output32Layer<WitIn, WitIn>,
    out_evals: &[usize],
    in_evals: &[usize],
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(STATE_SIZE, 0, 0, None, alpha, beta);

    let keccak_output = &layer.output;
    let mut keccak_output32_iter = out_evals.iter().map(|x| EvalExpression::Single(*x));

    // process keccak output
    let sel_type = SelectorType::OrderedSparse {
        num_vars: 5,
        indices: vec![CYCLIC_POW2_5[ROUNDS - 1] as usize],
        expression: layer.sel.expr(),
    };
    for x in 0..X {
        for y in 0..Y {
            for k in 0..2 {
                // create an expression combining 4 elements of state8 into a single 32-bit felt
                let expr = expansion_expr::<E, 32>(
                    &keccak_output[from_xyz(x, y, 32 * k)..from_xyz(x, y, 32 * (k + 1))]
                        .iter()
                        .map(|e| (1, e.expr()))
                        .collect_vec(),
                );
                system.add_non_zero_constraint(
                    expr,
                    (sel_type.clone(), keccak_output32_iter.next().unwrap()),
                    format!("build 32-bit output: {x}, {y}, {k}"),
                );
            }
        }
    }

    system.into_layer("Round 23: final".to_string(), in_evals.to_vec(), 0)
}

fn iota_layer<E: ExtensionField>(
    layer: &IotaLayer<WitIn, WitIn>,
    iota_out_evals: &[usize],
    iota_in_evals: &[usize],
    round_id: usize,
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system =
        LayerConstraintSystem::new(STATE_SIZE, 0, 0, Some(layer.eq.expr()), alpha, beta);

    let bits = layer.chi_output.iter().map(|e| e.expr()).collect_vec();
    let round_value = RC[round_id];
    let sel_type = SelectorType::Whole(layer.eq.expr());
    iota_out_evals.iter().enumerate().for_each(|(i, out_eval)| {
        let expr = {
            let round_bit = E::BaseField::from_canonical_u64((round_value >> i) & 1).expr();
            xor_expr(bits[i].clone(), round_bit)
        };
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), EvalExpression::Single(*out_eval)),
            format!("Round {round_id}: Iota:: compute output {i}"),
        );
    });

    system.into_layer(
        format!("Round {round_id}: Iota:: compute output"),
        iota_in_evals.to_vec(),
        0,
    )
}

fn chi_expr<E: ExtensionField>(i: usize, bits: &[Expression<E>]) -> Expression<E> {
    assert_eq!(bits.len(), STATE_SIZE);

    let (x, y, z) = to_xyz(i);
    let rhs = and_expr(
        not_expr(bits[from_xyz((x + 1) % X, y, z)].clone()),
        bits[from_xyz((x + 2) % X, y, z)].clone(),
    );
    xor_expr((bits[i]).clone(), rhs)
}

fn rho_pi_and_chi_layer<E: ExtensionField>(
    layer: &RhoPiAndChiLayer<WitIn, WitIn>,
    out_evals: &[usize],
    in_evals: &[usize],
    round_id: usize,
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(STATE_SIZE, 0, 0, None, alpha, beta);
    // Apply the effects of the rho + pi permutation directly o the argument of chi
    // No need for a separate layer
    let perm = rho_and_pi_permutation();

    let theta_output = &layer.theta_output;
    let permuted = (0..STATE_SIZE)
        .map(|i| theta_output[perm[i]].expr())
        .collect_vec();

    let mut out_eval_iter = out_evals.iter().map(|o| EvalExpression::Single(*o));
    (0..STATE_SIZE).for_each(|i| {
        let (x, y, _z) = to_xyz(i);
        let eq = if x == 0 && y == 0 {
            layer.eq_iota.expr()
        } else {
            layer.eq_round_out.expr()
        };
        let sel_type = SelectorType::Whole(eq);
        system.add_non_zero_constraint(
            chi_expr(i, &permuted),
            (sel_type, out_eval_iter.next().unwrap()),
            format!("Round {round_id}: Chi:: apply rho, pi and chi [{i}]"),
        )
    });

    system.into_layer(
        format!("Round {round_id}: Chi:: apply rho, pi and chi"),
        in_evals.to_vec(),
        0,
    )
}

fn theta_third_layer<E: ExtensionField>(
    layer: &ThetaThirdLayer<WitIn, WitIn>,
    out_evals: &[usize],
    in_evals: &[usize],
    round_id: usize,
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(D_SIZE + STATE_SIZE, 0, 0, None, alpha, beta);
    // Compute post-theta state using original state and D[][] values
    let mut out_eval_iter = out_evals.iter().map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq.expr());
    (0..STATE_SIZE).for_each(|i| {
        let (x, _, z) = to_xyz(i);
        let expr = xor_expr(layer.state_copy[i].expr(), layer.d[from_xz(x, z)].expr());
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::compute output [{i}]"),
        );
    });

    system.into_layer(
        format!("Round {round_id}: Theta::compute output"),
        in_evals.to_vec(),
        0,
    )
}

fn theta_second_layer<E: ExtensionField>(
    layer: &ThetaSecondLayer<WitIn, WitIn>,
    out_evals: &[usize],
    in_evals: &[usize],
    round_id: usize,
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(D_SIZE + STATE_SIZE, 0, 0, None, alpha, beta);
    // Compute D[][] from C[][] values
    let c = layer.c.iter().map(|c| c.expr()).collect_vec();
    let mut out_eval_iter = out_evals.iter().map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq.expr());
    iproduct!(0..5usize, 0..64usize).for_each(|(x, z)| {
        let expr = d_expr(x, z, &c);
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::compute D[{x}][{z}]"),
        );
    });

    system.into_layer(
        format!("Round {round_id}: Theta::compute D[x][z]"),
        in_evals.to_vec(),
        0,
    )
}

fn theta_first_layer<E: ExtensionField>(
    layer: &ThetaFirstLayer<WitIn, WitIn, ()>,
    d_out_evals: &[usize],
    state_copy_out_evals: &[usize],
    in_evals: &[usize],
    round_id: usize,
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(STATE_SIZE, 0, 0, None, alpha, beta);
    let state_wits = layer.round_input.iter().map(|s| s.expr()).collect_vec();

    // Compute C[][] from state
    let mut out_eval_iter = d_out_evals.iter().map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq_c.expr());
    iproduct!(0..5usize, 0..64usize).for_each(|(x, z)| {
        let expr = c_expr(x, z, &state_wits);
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::compute C[{x}][{z}]"),
        );
    });

    // Copy state
    let mut out_eval_iter = state_copy_out_evals
        .iter()
        .map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq_copy.expr());
    state_wits.into_iter().enumerate().for_each(|(i, expr)| {
        let (x, y, z) = to_xyz(i);
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::copy state[{x}][{y}][{z}]"),
        )
    });

    system.into_layer(
        format!("Round {round_id}: Theta::compute C[x][z]"),
        in_evals.to_vec(),
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn keccak_first_layer<E: ExtensionField>(
    layer: &ThetaFirstLayer<WitIn, WitIn, WitIn>,
    d_out_evals: &[usize],
    state_copy_out_evals: &[usize],
    input32_out_evals: &[usize],
    in_evals: &[usize],
    alpha: Expression<E>,
    beta: Expression<E>,
) -> Layer<E> {
    let mut system = LayerConstraintSystem::new(STATE_SIZE, 0, 0, None, alpha, beta);
    let state_wits = layer.round_input.iter().map(|s| s.expr()).collect_vec();

    // Compute C[][] from state
    let mut out_eval_iter = d_out_evals.iter().map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq_c.expr());
    iproduct!(0..5usize, 0..64usize).for_each(|(x, z)| {
        let expr = c_expr(x, z, &state_wits);
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::compute C[{x}][{z}]"),
        );
    });

    // Copy state
    let mut out_eval_iter = state_copy_out_evals
        .iter()
        .map(|o| EvalExpression::Single(*o));
    let sel_type = SelectorType::Whole(layer.eq_copy.expr());
    state_wits.into_iter().enumerate().for_each(|(i, expr)| {
        let (x, y, z) = to_xyz(i);
        system.add_non_zero_constraint(
            expr,
            (sel_type.clone(), out_eval_iter.next().unwrap()),
            format!("Theta::copy state[{x}][{y}][{z}]"),
        )
    });

    // process keccak output
    let mut out_eval_iter = input32_out_evals.iter().map(|x| EvalExpression::Single(*x));
    let sel_type = SelectorType::OrderedSparse {
        num_vars: 5,
        indices: vec![CYCLIC_POW2_5[0] as usize],
        expression: layer.sel_keccak_out.expr(),
    };
    for x in 0..X {
        for y in 0..Y {
            for k in 0..2 {
                // create an expression combining 4 elements of state8 into a single 32-bit felt
                let expr = expansion_expr::<E, 32>(
                    &layer.round_input[from_xyz(x, y, 32 * k)..from_xyz(x, y, 32 * (k + 1))]
                        .iter()
                        .map(|e| (1, e.expr()))
                        .collect_vec(),
                );
                system.add_non_zero_constraint(
                    expr,
                    (sel_type.clone(), out_eval_iter.next().unwrap()),
                    format!("build 32-bit input: {x}, {y}, {k}"),
                );
            }
        }
    }

    system.into_layer(
        "Round 0: Theta::compute C[x][z], build 32-bit input".to_string(),
        in_evals.to_vec(),
        0,
    )
}

impl<E: ExtensionField> KeccakLayout<E> {
    pub fn build_gkr_chip_old(
        _cb: &mut CircuitBuilder<E>,
        _params: KeccakParams,
    ) -> Result<(Self, Chip<E>), CircuitBuilderError> {
        let layout = Self::default();
        let mut chip = Chip {
            n_fixed: 0,
            n_committed: STATE_SIZE,
            n_challenges: 0,
            n_evaluations: KECCAK_ALL_IN_EVAL_SIZE + KECCAK_OUT_EVAL_SIZE,
            layers: vec![],
            final_out_evals: unsafe {
                transmute::<KeccakOutEvals<usize>, [usize; KECCAK_OUT_EVAL_SIZE]>(
                    layout.final_out_evals.clone(),
                )
            }
            .to_vec(),
        };
        chip.add_layer(output32_layer(
            &layout.layers.output32,
            &layout.final_out_evals.output32,
            &layout.layer_in_evals.output32,
            layout.alpha.clone(),
            layout.beta.clone(),
        ));

        macro_rules! add_common_layers {
            ($round_layers:expr, $round_output:expr, $round_in_evals:expr, $round_id:expr, $alpha:expr, $beta:expr) => {
                chip.add_layer(iota_layer(
                    &$round_layers.iota,
                    &$round_output[..Z],
                    &$round_in_evals.iota,
                    $round_id,
                    $alpha,
                    $beta,
                ));

                let rho_pi_and_chi_out_evals =
                    [$round_in_evals.iota.to_vec(), $round_output[Z..].to_vec()].concat();
                chip.add_layer(rho_pi_and_chi_layer(
                    &$round_layers.rho_pi_and_chi,
                    &rho_pi_and_chi_out_evals,
                    &$round_in_evals.rho_pi_and_chi,
                    $round_id,
                    $alpha,
                    $beta,
                ));
                chip.add_layer(theta_third_layer(
                    &$round_layers.theta_third,
                    &$round_in_evals.rho_pi_and_chi,
                    &$round_in_evals.theta_third,
                    $round_id,
                    $alpha,
                    $beta,
                ));
                chip.add_layer(theta_second_layer(
                    &$round_layers.theta_second,
                    &$round_in_evals.theta_third,
                    &$round_in_evals.theta_second,
                    $round_id,
                    $alpha,
                    $beta,
                ));
            };
        }

        // add Round 1..24
        let round_output = izip!(
            (1..ROUNDS),
            &layout.layers.inner_rounds,
            &layout.layer_in_evals.inner_rounds
        )
        .rev()
        .fold(
            &layout.layer_in_evals.output32,
            |round_output, (round_id, round_layers, round_in_evals)| {
                add_common_layers!(
                    round_layers,
                    round_output,
                    round_in_evals,
                    round_id,
                    layout.alpha.clone(),
                    layout.beta.clone()
                );
                chip.add_layer(theta_first_layer(
                    &round_layers.theta_first,
                    &round_in_evals.theta_second,
                    &round_in_evals.theta_third[D_SIZE..],
                    &round_in_evals.theta_first,
                    round_id,
                    layout.alpha.clone(),
                    layout.beta.clone(),
                ));
                &round_in_evals.theta_first
            },
        );

        // add Round 0
        let (round_layers, round_in_evals) = (
            &layout.layers.first_round,
            &layout.layer_in_evals.first_round,
        );

        add_common_layers!(
            round_layers,
            round_output,
            round_in_evals,
            0,
            layout.alpha.clone(),
            layout.beta.clone()
        );

        chip.add_layer(keccak_first_layer(
            &round_layers.theta_first,
            &round_in_evals.theta_second,
            &round_in_evals.theta_third[D_SIZE..],
            &layout.final_out_evals.input32,
            &round_in_evals.theta_first,
            layout.alpha.clone(),
            layout.beta.clone(),
        ));
        Ok((layout, chip))
    }
}
impl<E: ExtensionField> ProtocolBuilder<E> for KeccakLayout<E> {
    type Params = KeccakParams;

    fn finalize(&mut self, _cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        unimplemented!()
    }

    fn build_layer_logic(
        _cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        unimplemented!()
    }

    fn n_committed(&self) -> usize {
        STATE_SIZE
    }

    fn n_fixed(&self) -> usize {
        0
    }

    fn n_challenges(&self) -> usize {
        0
    }

    fn n_layers(&self) -> usize {
        5 * ROUNDS + 1
    }

    fn n_evaluations(&self) -> usize {
        KECCAK_ALL_IN_EVAL_SIZE + KECCAK_OUT_EVAL_SIZE
    }
}

pub struct KeccakTrace<E: ExtensionField> {
    pub bits: RowMajorMatrix<E::BaseField>,
}

impl<E> ProtocolWitnessGenerator<E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace<E>;

    fn phase1_witness_group(
        &self,
        _phase1: Self::Trace,
        _wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        _lk_multiplicity: &mut LkMultiplicity,
    ) {
        // phase1.bits
    }

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new_by_values(vec![], 1, InstancePaddingStrategy::Default)
    }
}

// based on
// https://github.com/0xPolygonHermez/zkevm-prover/blob/main/tools/sm/keccak_f/keccak_rho.cpp
fn rho<T: Copy + Default>(state: &[T]) -> Vec<T> {
    assert_eq!(state.len(), STATE_SIZE);
    let (mut x, mut y) = (1, 0);
    let mut ret = [T::default(); STATE_SIZE];

    for z in 0..Z {
        ret[from_xyz(0, 0, z)] = state[from_xyz(0, 0, z)];
    }
    for t in 0..24 {
        for z in 0..Z {
            let new_z = (1000 * Z + z - (t + 1) * (t + 2) / 2) % Z;
            ret[from_xyz(x, y, z)] = state[from_xyz(x, y, new_z)];
        }
        (x, y) = (y, (2 * x + 3 * y) % Y);
    }

    ret.to_vec()
}

// https://github.com/0xPolygonHermez/zkevm-prover/blob/main/tools/sm/keccak_f/keccak_pi.cpp
fn pi<T: Copy + Default>(state: &[T]) -> Vec<T> {
    assert_eq!(state.len(), STATE_SIZE);
    let mut ret = [T::default(); STATE_SIZE];

    iproduct!(0..X, 0..Y, 0..Z)
        .map(|(x, y, z)| ret[from_xyz(x, y, z)] = state[from_xyz((x + 3 * y) % X, x, z)])
        .count();

    ret.to_vec()
}

// Combines rho and pi steps into a single permutation
fn rho_and_pi_permutation() -> Vec<usize> {
    let perm: [usize; STATE_SIZE] = from_fn(|i| i);
    pi(&rho(&perm))
}

pub fn setup_gkr_circuit<E: ExtensionField>()
-> Result<(KeccakLayout<E>, GKRCircuit<E>), CircuitBuilderError> {
    let params = KeccakParams {};
    let mut cs = ConstraintSystem::new(|| "bitwise_keccak");
    let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
    let (layout, chip) = KeccakLayout::build_gkr_chip_old(&mut circuit_builder, params)?;
    Ok((layout, chip.gkr_circuit()))
}

pub fn run_keccakf<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>(
    gkr_circuit: GKRCircuit<E>,
    states: Vec<[u64; 25]>,
    verify: bool,
    test: bool,
) {
    let num_instances = states.len();
    let log2_num_instances = ceil_log2(num_instances);
    let num_threads = optimal_sumcheck_threads(log2_num_instances);

    let span = entered_span!("keccak_witness", profiling_1 = true);
    let bits = keccak_phase1_witness::<E>(&states);
    exit_span!(span);
    let span = entered_span!("phase1_witness_group", profiling_1 = true);
    let phase1_witness = bits;
    exit_span!(span);
    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    // Omit the commit phase1 and phase2.
    let span = entered_span!("gkr_witness", profiling_1 = true);
    let phase1_witness_group = phase1_witness
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    #[allow(clippy::type_complexity)]
    let (gkr_witness, gkr_output) = gkr_witness::<E, PCS, CpuBackend<E, PCS>, CpuProver<_>>(
        &gkr_circuit,
        &phase1_witness_group,
        &[],
        &[],
        &[],
        &[],
        &[],
    );
    exit_span!(span);

    let out_evals = {
        let mut point = Point::new();
        point.extend(prover_transcript.sample_vec(log2_num_instances).to_vec());

        if test {
            // sanity check on first instance only
            // TODO test all instances
            let result_from_witness = gkr_witness.layers[0]
                .iter()
                .map(|bit| {
                    if <E as ExtensionField>::BaseField::ZERO == bit.get_base_field_vec()[0] {
                        <E as ExtensionField>::BaseField::ZERO
                    } else {
                        <E as ExtensionField>::BaseField::ONE
                    }
                })
                .collect_vec();
            let mut state = states.clone();
            keccakf(&mut state[0]);

            // TODO test this
            assert_eq!(
                keccak_phase1_witness::<E>(&state) // result from tiny keccak
                    .to_mles()
                    .into_iter()
                    .map(|b: MultilinearExtension<'_, E>| b.get_base_field_vec()[0])
                    .collect_vec(),
                result_from_witness
            );
        }

        gkr_output
            .0
            .iter()
            .map(|bit| PointAndEval {
                point: point.clone(),
                eval: bit.evaluate(&point),
            })
            .collect_vec()
    };

    let span = entered_span!("prove", profiling_1 = true);
    let selector_ctxs = vec![
        SelectorContext::new(0, num_instances, log2_num_instances);
        gkr_circuit
            .layers
            .first()
            .map(|layer| layer.out_sel_and_eval_exprs.len())
            .unwrap()
    ];
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instances,
            gkr_witness,
            &out_evals,
            &[],
            &[],
            &mut prover_transcript,
            &selector_ctxs,
        )
        .expect("Failed to prove phase");
    exit_span!(span);

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

            // TODO verify output
            let mut point = Point::new();
            point.extend(verifier_transcript.sample_vec(log2_num_instances).to_vec());

            gkr_circuit
                .verify(
                    log2_num_instances,
                    gkr_proof,
                    &out_evals,
                    &[],
                    &[],
                    &[],
                    &mut verifier_transcript,
                    &selector_ctxs,
                )
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ext::GoldilocksExt2;
    use mpcs::BasefoldDefault;
    use rand::{RngCore, SeedableRng};

    #[test]
    #[ignore = "stack overflow. force enable it will cause occationally cause unittest ci hang"]
    fn test_keccakf() {
        type E = GoldilocksExt2;
        type Pcs = BasefoldDefault<E>;
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();

        let random_u64: u64 = rand::random();
        // Use seeded rng for debugging convenience
        let mut rng = rand::rngs::StdRng::seed_from_u64(random_u64);
        let num_instances = 4;
        let states: Vec<[u64; 25]> = (0..num_instances)
            .map(|_| std::array::from_fn(|_| rng.next_u64()))
            .collect_vec();
        run_keccakf::<E, Pcs>(
            setup_gkr_circuit().expect("setup gkr circuit error").1,
            states,
            false,
            true,
        ); // `verify` is temporarily false because the error `Extrapolation for degree 6 not implemented`.
    }
}
