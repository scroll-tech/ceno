use std::{array::from_fn, marker::PhantomData, sync::Arc};

use crate::{
    chip::Chip,
    evaluation::{EvalExpression, PointAndEval},
    gkr::{
        layer::{Layer, LayerType, LayerWitness},
        GKRCircuitWitness, GKRProverOutput,
    },
    ProtocolBuilder, ProtocolWitnessGenerator,
};
use ff_ext::ExtensionField;
use itertools::{chain, iproduct, Itertools};
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;

use subprotocols::expression::{Constant, Expression, Witness};
use tiny_keccak::keccakf;
use transcript::BasicTranscript;

type E = BinomialExtensionField<Goldilocks, 2>;
#[derive(Clone, Debug, Default)]
struct KeccakParams {}

#[derive(Clone, Debug, Default)]
struct KeccakLayout<E> {
    params: KeccakParams,

    committed_bits_id: usize,

    result: Vec<EvalExpression>,
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

fn xor<F: Field>(a: F, b: F) -> F {
    a + b - a * b - a * b
}

fn and_expr(a: Expression, b: Expression) -> Expression {
    a.clone() * b.clone()
}

fn not_expr(a: Expression) -> Expression {
    one_expr() - a
}

fn xor_expr(a: Expression, b: Expression) -> Expression {
    a.clone() + b.clone() - Expression::Const(Constant::Base(2)) * a * b
}

fn zero_expr() -> Expression {
    Expression::Const(Constant::Base(0))
}

fn one_expr() -> Expression {
    Expression::Const(Constant::Base(1))
}

fn c<F: Field>(x: usize, z: usize, bits: &[F]) -> F {
    (0..5)
        .map(|y| bits[from_xyz(x, y, z)])
        .fold(F::ZERO, |acc, x| xor(acc, x))
}

fn c_expr(x: usize, z: usize, state_wits: &[Witness]) -> Expression {
    (0..5)
        .map(|y| Expression::from(state_wits[from_xyz(x, y, z)]))
        .fold(zero_expr(), |acc, x| xor_expr(acc, x))
}

fn from_xz(x: usize, z: usize) -> usize {
    x * 64 + z
}

fn d<F: Field>(x: usize, z: usize, c_vals: &[F]) -> F {
    let lhs = from_xz((x + 5 - 1) % 5, z);
    let rhs = from_xz((x + 1) % 5, (z + 64 - 1) % 64);
    xor(c_vals[lhs], c_vals[rhs])
}

fn d_expr(x: usize, z: usize, c_wits: &[Witness]) -> Expression {
    let lhs = from_xz((x + 5 - 1) % 5, z);
    let rhs = from_xz((x + 1) % 5, (z + 64 - 1) % 64);
    xor_expr(c_wits[lhs].into(), c_wits[rhs].into())
}

fn theta<F: Field>(bits: Vec<F>) -> Vec<F> {
    assert_eq!(bits.len(), STATE_SIZE);

    let c_vals = iproduct!(0..5, 0..64)
        .map(|(x, z)| c(x, z, &bits))
        .collect_vec();

    let d_vals = iproduct!(0..5, 0..64)
        .map(|(x, z)| d(x, z, &c_vals))
        .collect_vec();

    bits.iter()
        .enumerate()
        .map(|(i, bit)| {
            let (x, _, z) = to_xyz(i);
            xor(*bit, d_vals[from_xz(x, z)])
        })
        .collect()
}

fn and<F: Field>(a: F, b: F) -> F {
    a * b
}

fn not<F: Field>(a: F) -> F {
    F::ONE - a
}

fn bools_to_u64s(state: &[bool]) -> Vec<u64> {
    state
        .chunks(64)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u64, |acc, (i, &bit)| acc | ((bit as u64) << i))
        })
        .collect::<Vec<u64>>()
}

fn u64s_to_bools(state64: &[u64]) -> Vec<bool> {
    state64
        .iter()
        .flat_map(|&word| (0..64).map(move |i| ((word >> i) & 1) == 1))
        .collect()
}

fn dbg_vec<F: Field>(vec: &Vec<F>) {
    let res = vec
        .iter()
        .map(|f| if *f == F::ZERO { false } else { true })
        .collect_vec();
    // println!("{:?}", bools_to_u64s(&res));
}
fn chi<F: Field>(bits: &Vec<F>) -> Vec<F> {
    assert_eq!(bits.len(), STATE_SIZE);

    bits.iter()
        .enumerate()
        .map(|(i, bit)| {
            let (x, y, z) = to_xyz(i);
            let rhs = and(
                not(bits[from_xyz((x + 1) % X, y, z)]),
                bits[from_xyz((x + 2) % X, y, z)],
            );
            xor(*bit, rhs)
        })
        .collect()
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

fn iota<F: Field>(bits: &Vec<F>, round_value: u64) -> Vec<F> {
    assert_eq!(bits.len(), STATE_SIZE);
    let mut ret = bits.clone();

    let cast = |x| match x {
        0 => F::ZERO,
        1 => F::ONE,
        _ => unreachable!(),
    };

    for z in 0..Z {
        ret[from_xyz(0, 0, z)] = xor(bits[from_xyz(0, 0, z)], cast((round_value >> z) & 1));
    }

    ret
}

fn iota_expr(bits: &[Witness], index: usize, round_value: u64) -> Expression {
    assert_eq!(bits.len(), STATE_SIZE);
    let (x, y, z) = to_xyz(index);

    if x > 0 || y > 0 {
        bits[index].into()
    } else {
        let round_bit = Expression::Const(Constant::Base(
            ((round_value >> index) & 1).try_into().unwrap(),
        ));
        xor_expr(bits[from_xyz(0, 0, z)].into(), round_bit)
    }
}

fn chi_expr(i: usize, bits: &[Witness]) -> Expression {
    assert_eq!(bits.len(), STATE_SIZE);

    let (x, y, z) = to_xyz(i);
    let rhs = and_expr(
        not_expr(bits[from_xyz((x + 1) % X, y, z)].into()),
        bits[from_xyz((x + 2) % X, y, z)].into(),
    );
    xor_expr((bits[i]).into(), rhs)
}

impl<E: ExtensionField> ProtocolBuilder for KeccakLayout<E> {
    type Params = KeccakParams;

    fn init(params: Self::Params) -> Self {
        Self {
            params,
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip) {
        [self.committed_bits_id] = chip.allocate_committed_base();
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip) {
        let final_output = chip.allocate_output_evals::<STATE_SIZE>();

        (0..ROUNDS)
            .rev()
            .into_iter()
            .fold(final_output, |round_output, round| {
                let (chi_output, _) = chip.allocate_wits_in_layer::<STATE_SIZE, 0>();

                let exprs = (0..STATE_SIZE)
                    .map(|i| iota_expr(&chi_output.iter().map(|e| e.0).collect_vec(), i, RC[round]))
                    .collect_vec();

                chip.add_layer(Layer::new(
                    format!("Round {round}: Iota:: compute output"),
                    LayerType::Zerocheck,
                    exprs,
                    vec![],
                    chi_output.iter().map(|e| e.1.clone()).collect_vec(),
                    vec![],
                    round_output.to_vec(),
                    vec![],
                ));

                let (theta_output, _) = chip.allocate_wits_in_layer::<STATE_SIZE, 0>();

                // Apply the effects of the rho + pi permutation directly o the argument of chi
                // No need for a separate layer
                let perm = rho_and_pi_permutation();
                let permuted = (0..STATE_SIZE)
                    .map(|i| theta_output[perm[i]].0)
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
                    vec![],
                    chi_output.iter().map(|e| e.1.clone()).collect_vec(),
                    vec![],
                ));

                let (d_and_state, _) = chip.allocate_wits_in_layer::<{ D_SIZE + STATE_SIZE }, 0>();
                let (d, state2) = d_and_state.split_at(D_SIZE);

                // Compute post-theta state using original state and D[][] values
                let exprs = (0..STATE_SIZE)
                    .map(|i| {
                        let (x, y, z) = to_xyz(i);
                        xor_expr(state2[i].0.into(), d[from_xz(x, z)].0.into())
                    })
                    .collect_vec();

                chip.add_layer(Layer::new(
                    format!("Round {round}: Theta::compute output"),
                    LayerType::Zerocheck,
                    exprs,
                    vec![],
                    d_and_state.iter().map(|e| e.1.clone()).collect_vec(),
                    vec![],
                    theta_output.iter().map(|e| e.1.clone()).collect_vec(),
                    vec![],
                ));

                let (c, []) = chip.allocate_wits_in_layer::<{ C_SIZE }, 0>();

                let c_wits = c.iter().map(|e| e.0.clone()).collect_vec();
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
                    vec![],
                    d.iter().map(|e| e.1.clone()).collect_vec(),
                    vec![],
                ));

                let (state, []) = chip.allocate_wits_in_layer::<STATE_SIZE, 0>();
                let state_wits = state.iter().map(|s| s.0).collect_vec();

                // Compute C[][] from state
                let c_exprs = iproduct!(0..5usize, 0..64usize)
                    .map(|(x, z)| c_expr(x, z, &state_wits))
                    .collect_vec();

                // Copy state
                let id_exprs: Vec<Expression> =
                    (0..STATE_SIZE).map(|i| state_wits[i].into()).collect_vec();

                chip.add_layer(Layer::new(
                    format!("Round {round}: Theta::compute C[x][z]"),
                    LayerType::Zerocheck,
                    chain!(c_exprs, id_exprs).collect_vec(),
                    vec![],
                    state.iter().map(|t| t.1.clone()).collect_vec(),
                    vec![],
                    chain!(
                        c.iter().map(|e| e.1.clone()),
                        state2.iter().map(|e| e.1.clone())
                    )
                    .collect_vec(),
                    vec![],
                ));

                state
                    .iter()
                    .map(|e| e.1.clone())
                    .collect_vec()
                    .try_into()
                    .unwrap()
            });

        // Skip base opening allocation
    }
}

pub struct KeccakTrace {
    pub bits: [bool; STATE_SIZE],
}

impl<E> ProtocolWitnessGenerator<E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace;

    fn phase1_witness(&self, phase1: Self::Trace) -> Vec<Vec<E::BaseField>> {
        let mut res = vec![vec![]; 1];
        res[0] = phase1
            .bits
            .into_iter()
            .map(|b| E::BaseField::from_u64(b as u64))
            .collect();
        res
    }

    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], challenges: &[E]) -> GKRCircuitWitness<E> {
        let mut bits = phase1[self.committed_bits_id].clone();

        let n_layers = 100;
        let mut layer_wits = Vec::<LayerWitness<E>>::with_capacity(n_layers + 1);

        for i in 0..24 {
            if i == 0 {
                layer_wits.push(LayerWitness::new(
                    bits.clone().into_iter().map(|b| vec![b]).collect_vec(),
                    vec![],
                ));
            }

            let c_wits = iproduct!(0..5usize, 0..64usize)
                .map(|(x, z)| c(x, z, &bits))
                .collect_vec();

            layer_wits.push(LayerWitness::new(
                chain!(
                    c_wits.clone().into_iter().map(|b| vec![b]),
                    // Note: it seems test pass even if this is uncommented.
                    // Maybe it's good to assert there are no unused witnesses
                    // bits.clone().into_iter().map(|b| vec![b])
                )
                .collect_vec(),
                vec![],
            ));

            let d_wits = iproduct!(0..5usize, 0..64usize)
                .map(|(x, z)| d(x, z, &c_wits))
                .collect_vec();

            layer_wits.push(LayerWitness::new(
                chain!(
                    d_wits.clone().into_iter().map(|b| vec![b]),
                    bits.clone().into_iter().map(|b| vec![b])
                )
                .collect_vec(),
                vec![],
            ));

            bits = theta(bits);
            layer_wits.push(LayerWitness::new(
                bits.clone().into_iter().map(|b| vec![b]).collect_vec(),
                vec![],
            ));

            bits = chi(&pi(&rho(&bits)));
            layer_wits.push(LayerWitness::new(
                bits.clone().into_iter().map(|b| vec![b]).collect_vec(),
                vec![],
            ));

            if i < 23 {
                bits = iota(&bits, RC[i]);
                layer_wits.push(LayerWitness::new(
                    bits.clone().into_iter().map(|b| vec![b]).collect_vec(),
                    vec![],
                ));
            }
        }

        // Assumes one input instance
        let total_witness_size: usize = layer_wits.iter().map(|layer| layer.bases.len()).sum();
        dbg!(total_witness_size);

        layer_wits.reverse();

        GKRCircuitWitness { layers: layer_wits }
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

    return ret.to_vec();
}

// https://github.com/0xPolygonHermez/zkevm-prover/blob/main/tools/sm/keccak_f/keccak_pi.cpp
fn pi<T: Copy + Default>(state: &[T]) -> Vec<T> {
    assert_eq!(state.len(), STATE_SIZE);
    let mut ret = [T::default(); STATE_SIZE];

    iproduct!(0..X, 0..Y, 0..Z)
        .into_iter()
        .map(|(x, y, z)| ret[from_xyz(x, y, z)] = state[from_xyz((x + 3 * y) % X, x, z)])
        .count();

    return ret.to_vec();
}

// Combines rho and pi steps into a single permutation
fn rho_and_pi_permutation() -> Vec<usize> {
    let perm: [usize; STATE_SIZE] = from_fn(|i| i);
    pi(&rho(&perm))
}

pub fn run_keccakf(state: [u64; 25], verify: bool, test: bool) -> () {
    let params = KeccakParams {};
    let (layout, chip) = KeccakLayout::build(params);
    let gkr_circuit = chip.gkr_circuit();

    let bits = u64s_to_bools(&state);

    let phase1_witness = layout.phase1_witness(KeccakTrace {
        bits: bits.try_into().unwrap(),
    });
    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    // Omit the commit phase1 and phase2.
    let gkr_witness = layout.gkr_witness(&phase1_witness, &vec![]);

    let out_evals = {
        let point = Arc::new(vec![]);

        let last_witness = gkr_witness.layers[0]
            .bases
            .clone()
            .into_iter()
            .flatten()
            .collect_vec();

        // Last witness is missing the final sub-round; apply it now
        let expected_result_manual = iota(&last_witness, RC[23]);

        if test {
            let mut state = state.clone();
            keccakf(&mut state);
            let state = u64s_to_bools(&state)
                .into_iter()
                .map(|b| Goldilocks::from_u64(b as u64))
                .collect_vec();
            assert_eq!(state, expected_result_manual);
        }

        expected_result_manual
            .iter()
            .map(|bit| PointAndEval {
                point: point.clone(),
                eval: E::from_bases(&[*bit, Goldilocks::ZERO]),
            })
            .collect_vec()
    };

    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove(gkr_witness, &out_evals, &vec![], &mut prover_transcript)
        .expect("Failed to prove phase");

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

            gkr_circuit
                .verify(gkr_proof, &out_evals, &vec![], &mut verifier_transcript)
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_keccakf() {
        for _ in 0..3 {
            let random_u64: u64 = rand::random();
            // Use seeded rng for debugging convenience
            let mut rng = rand::rngs::StdRng::seed_from_u64(random_u64);
            let state: [u64; 25] = std::array::from_fn(|_| rng.gen());
            run_keccakf(state, true, true);
        }
    }
}
