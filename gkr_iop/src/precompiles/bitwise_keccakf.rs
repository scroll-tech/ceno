use std::{array::from_fn, marker::PhantomData, sync::Arc};

use crate::{
    Phase1WitnessGroup, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    evaluation::EvalExpression,
    gkr::{
        GKRCircuit, GKRProverOutput,
        layer::{Layer, LayerType},
    },
};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct};
use multilinear_extensions::{
    Expression, ToExpr,
    mle::{MultilinearExtension, Point, PointAndEval},
    util::ceil_log2,
};
use p3_field::PrimeCharacteristicRing;
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use tiny_keccak::keccakf;
use transcript::{BasicTranscript, Transcript};

#[derive(Clone, Debug, Default)]
pub struct KeccakParams {}

#[derive(Clone, Debug, Default)]
pub struct KeccakLayout<E: ExtensionField> {
    _params: KeccakParams,

    committed_bits_id: usize,

    _result: Vec<EvalExpression<E>>,
    _marker: PhantomData<E>,
}

const X: usize = 5;
const Y: usize = 5;
const Z: usize = 64;
const STATE_SIZE: usize = X * Y * Z;
const C_SIZE: usize = X * Z;
const D_SIZE: usize = X * Z;

fn to_xyz(i: usize) -> (usize, usize, usize) {
    assert!(i < STATE_SIZE);
    (i / 64 % 5, (i / 64) / 5, i % 64)
}

fn from_xyz(x: usize, y: usize, z: usize) -> usize {
    assert!(x < 5 && y < 5 && z < 64);
    64 * (5 * y + x) + z
}

fn and_expr<E: ExtensionField>(a: Expression<E>, b: Expression<E>) -> Expression<E> {
    a.clone() * b.clone()
}

fn not_expr<E: ExtensionField>(a: Expression<E>) -> Expression<E> {
    one_expr() - a
}

fn xor_expr<E: ExtensionField>(a: Expression<E>, b: Expression<E>) -> Expression<E> {
    a.clone() + b.clone() - E::BaseField::from_u32(2).expr() * a * b
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

fn keccak_witness<'a, E: ExtensionField>(
    states: &[[u64; 25]],
) -> [MultilinearExtension<'a, E>; STATE_SIZE] {
    let num_states = states.len();
    assert!(num_states.is_power_of_two());
    let log_num_states = ceil_log2(num_states);
    let mut bits = from_fn(|_| vec![false; num_states]);

    for (state_idx, state) in states.iter().enumerate() {
        for (word_idx, &word) in state.iter().enumerate() {
            for bit_idx in 0..64 {
                let bit = ((word >> bit_idx) & 1) == 1;
                bits[word_idx * 64 + bit_idx][state_idx] = bit;
            }
        }
    }

    bits.map(|bit_column| {
        MultilinearExtension::from_evaluation_vec_smart(
            log_num_states,
            bit_column
                .into_iter()
                .map(|b| E::BaseField::from_bool(b))
                .collect::<Vec<_>>(),
        )
    })
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

fn iota_expr<E: ExtensionField>(
    bits: &[Expression<E>],
    index: usize,
    round_value: u64,
) -> Expression<E> {
    assert_eq!(bits.len(), STATE_SIZE);
    let (x, y, z) = to_xyz(index);

    if x > 0 || y > 0 {
        bits[index].clone()
    } else {
        let round_bit = E::BaseField::from_u64((round_value >> index) & 1).expr();
        xor_expr(bits[from_xyz(0, 0, z)].clone(), round_bit)
    }
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

impl<E: ExtensionField> ProtocolBuilder<E> for KeccakLayout<E> {
    type Params = KeccakParams;

    fn init(params: Self::Params) -> Self {
        Self {
            _params: params,
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip<E>) {
        [self.committed_bits_id] = chip.allocate_committed();
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip<E>) {
        let final_output = chip.allocate_output_evals::<STATE_SIZE>();

        (0..ROUNDS).rev().fold(final_output, |round_output, round| {
            let (chi_output, [eq]) = chip.allocate_wits_in_zero_layer::<STATE_SIZE, 1>();

            let exprs = (0..STATE_SIZE)
                .map(|i| {
                    iota_expr(
                        &chi_output.iter().map(|e| e.0.expr()).collect_vec(),
                        i,
                        RC[round],
                    )
                })
                .collect_vec();

            chip.add_layer(Layer::new(
                format!("Round {round}: Iota:: compute output"),
                LayerType::Zerocheck,
                exprs,
                vec![],
                chi_output.iter().map(|e| e.1.clone()).collect_vec(),
                vec![(Some(eq.0.expr()), round_output.to_vec())],
                vec![],
            ));

            let (theta_output, [eq]) = chip.allocate_wits_in_zero_layer::<STATE_SIZE, 1>();

            // Apply the effects of the rho + pi permutation directly o the argument of chi
            // No need for a separate layer
            let perm = rho_and_pi_permutation();
            let permuted = (0..STATE_SIZE)
                .map(|i| theta_output[perm[i]].0.expr())
                .collect_vec();

            let exprs = (0..STATE_SIZE)
                .map(|i| chi_expr(i, &permuted))
                .collect_vec();

            chip.add_layer(Layer::new(
                format!("Round {round}: Chi:: apply rho, pi and chi"),
                LayerType::Zerocheck,
                exprs,
                vec![],
                theta_output.iter().map(|e| e.1.clone()).collect_vec(),
                vec![(
                    Some(eq.0.expr()),
                    chi_output.iter().map(|e| e.1.clone()).collect_vec(),
                )],
                vec![],
            ));

            let (d_and_state, [eq]) =
                chip.allocate_wits_in_zero_layer::<{ D_SIZE + STATE_SIZE }, 1>();
            let (d, state2) = d_and_state.split_at(D_SIZE);

            // Compute post-theta state using original state and D[][] values
            let exprs = (0..STATE_SIZE)
                .map(|i| {
                    let (x, _, z) = to_xyz(i);
                    xor_expr(state2[i].0.expr(), d[from_xz(x, z)].0.expr())
                })
                .collect_vec();

            chip.add_layer(Layer::new(
                format!("Round {round}: Theta::compute output"),
                LayerType::Zerocheck,
                exprs,
                vec![],
                d_and_state.iter().map(|e| e.1.clone()).collect_vec(),
                vec![(
                    Some(eq.0.expr()),
                    theta_output.iter().map(|e| e.1.clone()).collect_vec(),
                )],
                vec![],
            ));

            let (c, [eq]) = chip.allocate_wits_in_zero_layer::<{ C_SIZE }, 1>();

            let c_wits = c.iter().map(|e| e.0.expr()).collect_vec();
            // Compute D[][] from C[][] values
            let d_exprs = iproduct!(0..5usize, 0..64usize)
                .map(|(x, z)| d_expr(x, z, &c_wits))
                .collect_vec();

            chip.add_layer(Layer::new(
                format!("Round {round}: Theta::compute D[x][z]"),
                LayerType::Zerocheck,
                d_exprs,
                vec![],
                c.iter().map(|e| e.1.clone()).collect_vec(),
                vec![(
                    Some(eq.0.expr()),
                    d.iter().map(|e| e.1.clone()).collect_vec(),
                )],
                vec![],
            ));

            let (state, [eq0, eq1]) = chip.allocate_wits_in_zero_layer::<STATE_SIZE, 2>();
            let state_wits = state.iter().map(|s| s.0.expr()).collect_vec();

            // Compute C[][] from state
            let c_exprs = iproduct!(0..5usize, 0..64usize)
                .map(|(x, z)| c_expr(x, z, &state_wits))
                .collect_vec();

            // Copy state
            let id_exprs = (0..STATE_SIZE).map(|i| state_wits[i].clone()).collect_vec();

            chip.add_layer(Layer::new(
                format!("Round {round}: Theta::compute C[x][z]"),
                LayerType::Zerocheck,
                chain!(c_exprs, id_exprs).collect_vec(),
                vec![],
                state.iter().map(|t| t.1.clone()).collect_vec(),
                vec![
                    (
                        Some(eq0.0.expr()),
                        c.iter().map(|e| e.1.clone()).collect_vec(),
                    ),
                    (
                        Some(eq1.0.expr()),
                        state2.iter().map(|e| e.1.clone()).collect_vec(),
                    ),
                ],
                vec![],
            ));

            state.iter().map(|e| e.1.clone()).collect_vec()
        });

        // Skip base opening allocation
    }
}

pub struct KeccakTrace<'a, E: ExtensionField> {
    pub bits: [MultilinearExtension<'a, E>; STATE_SIZE],
}

impl<'a, E> ProtocolWitnessGenerator<'a, E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace<'a, E>;
    fn phase1_witness_group(&self, phase1: Self::Trace) -> Phase1WitnessGroup<'a, E> {
        phase1.bits.into_iter().map(Arc::new).collect_vec()
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

pub fn setup_gkr_circuit<E: ExtensionField>() -> (KeccakLayout<E>, GKRCircuit<E>) {
    let params = KeccakParams {};
    let (layout, chip) = KeccakLayout::build(params);
    (layout, chip.gkr_circuit())
}

pub fn run_keccakf<E: ExtensionField>(
    (layout, gkr_circuit): (KeccakLayout<E>, GKRCircuit<E>),
    states: Vec<[u64; 25]>,
    verify: bool,
    test: bool,
) {
    let num_instances = states.len();
    let log2_num_instances = ceil_log2(num_instances);
    let num_threads = optimal_sumcheck_threads(log2_num_instances);

    let span = entered_span!("keccak_witness", profiling_1 = true);
    let bits = keccak_witness(&states);
    exit_span!(span);
    let span = entered_span!("phase1_witness_group", profiling_1 = true);
    let phase1_witness = layout.phase1_witness_group(KeccakTrace { bits });
    exit_span!(span);
    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    // Omit the commit phase1 and phase2.
    let span = entered_span!("gkr_witness", profiling_1 = true);
    let gkr_witness = layout.gkr_witness(&gkr_circuit, phase1_witness, &[]);
    exit_span!(span);

    let out_evals = {
        let mut point = Point::new();
        point.extend(prover_transcript.sample_vec(log2_num_instances).to_vec());

        if test {
            // sanity check on first instance only
            // TODO test all instances
            let result_from_witness = gkr_witness.layers[0]
                .bases
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
                keccak_witness(&state) // result from tiny keccak
                    .into_iter()
                    .map(|b: MultilinearExtension<'_, E>| b.get_base_field_vec()[0])
                    .collect_vec(),
                result_from_witness
            );
        }

        gkr_witness.layers[0]
            .bases
            .iter()
            .map(|bit| PointAndEval {
                point: point.clone(),
                eval: bit.evaluate(&point),
            })
            .collect_vec()
    };

    let span = entered_span!("prove", profiling_1 = true);
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove(
            num_threads,
            log2_num_instances,
            gkr_witness,
            &out_evals,
            &[],
            &mut prover_transcript,
        )
        .expect("Failed to prove phase");
    exit_span!(span);

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

            // TODO verify output
            let mut point = Point::new();
            point.extend(verifier_transcript.sample_vec(1).to_vec());

            gkr_circuit
                .verify(1, gkr_proof, &out_evals, &[], &mut verifier_transcript)
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ext::GoldilocksExt2;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_keccakf() {
        type E = GoldilocksExt2;
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();

        let random_u64: u64 = rand::random();
        // Use seeded rng for debugging convenience
        let mut rng = rand::rngs::StdRng::seed_from_u64(random_u64);
        let num_instance = 4;
        let states: Vec<[u64; 25]> = (0..num_instance)
            .map(|_| std::array::from_fn(|_| rng.gen()))
            .collect_vec();
        run_keccakf::<E>(setup_gkr_circuit(), states, false, true);
    }
}
