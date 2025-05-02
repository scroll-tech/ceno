use std::{cmp::Ordering, marker::PhantomData, sync::Arc};

use crate::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    evaluation::{EvalExpression, PointAndEval},
    gkr::{
        GKRCircuitWitness, GKRProverOutput,
        layer::{Layer, LayerType, LayerWitness},
    },
    precompiles::utils::{MaskRepresentation, nest, not8_expr, zero_expr},
};
use ndarray::{ArrayView, Ix2, Ix3, s};

use super::utils::{CenoLookup, u64s_to_felts, zero_eval};
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};

use ff_ext::{ExtensionField, SmallField};
use itertools::{Itertools, chain, iproduct, zip_eq};
use p3_goldilocks::Goldilocks;
use subprotocols::expression::{Constant, Expression, Witness};
use tiny_keccak::keccakf;
use transcript::BasicTranscript;

type E = BinomialExtensionField<Goldilocks, 2>;

#[derive(Clone, Debug, Default)]
pub struct KeccakParams {}

#[derive(Clone, Debug, Default)]
pub struct KeccakLayout<E> {
    _params: KeccakParams,
    _input_columns: Vec<usize>,
    _result: Vec<EvalExpression>,
    _marker: PhantomData<E>,
}

fn expansion_expr<const SIZE: usize>(expansion: &[(usize, Witness)]) -> Expression {
    let (total, ret) = expansion
        .iter()
        .rev()
        .fold((0, zero_expr()), |acc, (sz, felt)| {
            (
                acc.0 + sz,
                acc.1 * Expression::Const(Constant::Base(1 << sz)) + (*felt).into(),
            )
        });

    assert_eq!(total, SIZE);
    ret
}

/// Compute an adequate split of 64-bits into chunks for performing a rotation
/// by `delta`. The first element of the return value is the vec of chunk sizes.
/// The second one is the length of its suffix that needs to be rotated
fn rotation_split(delta: usize) -> (Vec<usize>, usize) {
    let delta = delta % 64;

    if delta == 0 {
        return (vec![32, 32], 0);
    }

    // This split meets all requirements except for <= 16 sizes
    let split32 = match delta.cmp(&32) {
        Ordering::Less => vec![32 - delta, delta, 32 - delta, delta],
        Ordering::Equal => vec![32, 32],
        Ordering::Greater => vec![32 - (delta - 32), delta - 32, 32 - (delta - 32), delta - 32],
    };

    // Split off large chunks
    let split16 = split32
        .into_iter()
        .flat_map(|size| {
            assert!(size < 32);
            if size <= 16 {
                vec![size]
            } else {
                vec![16, size - 16]
            }
        })
        .collect_vec();

    let mut sum = 0;
    for (i, size) in split16.iter().rev().enumerate() {
        sum += size;
        if sum == delta {
            return (split16, i + 1);
        }
    }

    panic!();
}

struct ConstraintSystem {
    expressions: Vec<Expression>,
    expr_names: Vec<String>,
    evals: Vec<EvalExpression>,
    and_lookups: Vec<CenoLookup>,
    xor_lookups: Vec<CenoLookup>,
    range_lookups: Vec<CenoLookup>,
}

impl ConstraintSystem {
    fn new() -> Self {
        ConstraintSystem {
            expressions: vec![],
            evals: vec![],
            expr_names: vec![],
            and_lookups: vec![],
            xor_lookups: vec![],
            range_lookups: vec![],
        }
    }

    fn add_constraint(&mut self, expr: Expression, name: String) {
        self.expressions.push(expr);
        self.evals.push(zero_eval());
        self.expr_names.push(name);
    }

    fn lookup_and8(&mut self, a: Expression, b: Expression, c: Expression) {
        self.and_lookups.push(CenoLookup::And(a, b, c));
    }

    fn lookup_xor8(&mut self, a: Expression, b: Expression, c: Expression) {
        self.xor_lookups.push(CenoLookup::Xor(a, b, c));
    }

    /// Generates U16 lookups to prove that `value` fits on `size < 16` bits.
    /// In general it can be done by two U16 checks: one for `value` and one for
    /// `value << (16 - size)`.
    fn lookup_range(&mut self, value: Expression, size: usize) {
        assert!(size <= 16);
        self.range_lookups.push(CenoLookup::U16(value.clone()));
        if size < 16 {
            self.range_lookups.push(CenoLookup::U16(
                value * Expression::Const(Constant::Base(1 << (16 - size))),
            ))
        }
    }

    fn constrain_eq(&mut self, lhs: Expression, rhs: Expression, name: String) {
        self.add_constraint(lhs - rhs, name);
    }

    // Constrains that lhs and rhs encode the same value of SIZE bits
    // WARNING: Assumes that forall i, (lhs[i].1 < (2 ^ lhs[i].0))
    // This needs to be constrained separately
    fn constrain_reps_eq<const SIZE: usize>(
        &mut self,
        lhs: &[(usize, Witness)],
        rhs: &[(usize, Witness)],
        name: String,
    ) {
        self.add_constraint(
            expansion_expr::<SIZE>(lhs) - expansion_expr::<SIZE>(rhs),
            name,
        );
    }

    /// Checks that `rot8` is equal to `input8` left-rotated by `delta`.
    /// `rot8` and `input8` each consist of 8 chunks of 8-bits.
    ///
    /// `split_rep` is a chunk representation of the input which
    /// allows to reduce the required rotation to an array rotation. It may use
    /// non-uniform chunks.
    ///
    /// For example, when `delta = 2`, the 64 bits are split into chunks of
    /// sizes `[16a, 14b, 2c, 16d, 14e, 2f]` (here the first chunks contains the
    /// least significant bits so a left rotation will become a right rotation
    /// of the array). To perform the required rotation, we can
    /// simply rotate the array: [2f, 16a, 14b, 2c, 16d, 14e].
    ///
    /// In the first step, we check that `rot8` and `split_rep` represent the
    /// same 64 bits. In the second step we check that `rot8` and the appropiate
    /// array rotation of `split_rep` represent the same 64 bits.
    ///
    /// This type of representation-equality check is done by packing chunks
    /// into sizes of exactly 32 (so for `delta = 2` we compare [16a, 14b,
    /// 2c] to the first 4 elements of `rot8`). In addition, we do range
    /// checks on `split_rep` which check that the felts meet the required
    /// sizes.
    ///
    /// This algorithm imposes the following general requirements for
    /// `split_rep`:
    /// - There exists a suffix of `split_rep` which sums to exactly `delta`.
    ///   This suffix can contain several elements.
    /// - Chunk sizes are at most 16 (so they can be range-checked) or they are
    ///   exactly equal to 32.
    /// - There exists a prefix of chunks which sums exactly to 32. This must
    ///   hold for the rotated array as well.
    /// - The number of chunks should be as small as possible.
    ///
    /// Consult the method `rotation_split` to see how splits are computed for a
    /// given `delta
    ///
    /// Note that the function imposes range checks on chunk values, but it
    /// makes two exceptions:
    ///     1. It doesn't check the 8-bit reps (input and output). This is
    ///        because all 8-bit reps in the global circuit are implicitly
    ///        range-checked because they are lookup arguments.
    ///     2. It doesn't range-check 32-bit chunks. This is because a 32-bit
    ///        chunk value is checked to be equal to the composition of 4 8-bit
    ///        chunks. As mentioned in 1., these can be trusted to be range
    ///        checked, so the resulting 32-bit is correct by construction as
    ///        well.
    fn constrain_left_rotation64(
        &mut self,
        input8: &[Witness],
        split_rep: &[(usize, Witness)],
        rot8: &[Witness],
        delta: usize,
        label: String,
    ) {
        assert_eq!(input8.len(), 8);
        assert_eq!(rot8.len(), 8);

        // Assert that the given split witnesses are correct for this delta
        let (sizes, chunks_rotation) = rotation_split(delta);
        assert_eq!(sizes, split_rep.iter().map(|e| e.0).collect_vec());

        // Lookup ranges
        for (size, elem) in split_rep {
            if *size != 32 {
                self.lookup_range((*elem).into(), *size);
            }
        }

        // constrain the fact that rep8 and repX.rotate_left(chunks_rotation) are
        // the same 64 bitstring
        let mut helper = |rep8: &[Witness], rep_x: &[(usize, Witness)], chunks_rotation: usize| {
            // Do the same thing for the two 32-bit halves
            let mut rep_x = rep_x.to_owned();
            rep_x.rotate_right(chunks_rotation);

            for i in 0..2 {
                // The respective 4 elements in the byte representation
                let lhs = rep8[4 * i..4 * (i + 1)]
                    .iter()
                    .map(|wit| (8, *wit))
                    .collect_vec();
                let cnt = rep_x.len() / 2;
                let rhs = &rep_x[cnt * i..cnt * (i + 1)];

                assert_eq!(rhs.iter().map(|e| e.0).sum::<usize>(), 32);

                self.constrain_reps_eq::<32>(
                    &lhs,
                    rhs,
                    format!(
                        "rotation internal {label}, round {i}, rot: {chunks_rotation}, delta: {delta}, {:?}",
                        sizes
                    ),
                );
            }
        };

        helper(input8, split_rep, 0);
        helper(rot8, split_rep, chunks_rotation);
    }
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

const ROTATION_CONSTANTS: [[usize; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

pub const KECCAK_INPUT_SIZE: usize = 50;
pub const KECCAK_OUTPUT_SIZE: usize = 50;

pub const AND_LOOKUPS_PER_ROUND: usize = 200;
pub const XOR_LOOKUPS_PER_ROUND: usize = 608;
pub const RANGE_LOOKUPS_PER_ROUND: usize = 290;
pub const LOOKUP_FELTS_PER_ROUND: usize =
    3 * AND_LOOKUPS_PER_ROUND + 3 * XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND;

pub const AND_LOOKUPS: usize = ROUNDS * AND_LOOKUPS_PER_ROUND;
pub const XOR_LOOKUPS: usize = ROUNDS * XOR_LOOKUPS_PER_ROUND;
pub const RANGE_LOOKUPS: usize = ROUNDS * RANGE_LOOKUPS_PER_ROUND;

macro_rules! allocate_and_split {
        ($chip:expr, $total:expr, $( $size:expr ),* ) => {{
            let (witnesses, _) = $chip.allocate_wits_in_layer::<$total, 0>();
            let mut iter = witnesses.into_iter();
            (
                $(
                    iter.by_ref().take($size).collect_vec(),
                )*
            )
        }};
    }

impl<E: ExtensionField> ProtocolBuilder for KeccakLayout<E> {
    type Params = KeccakParams;

    fn init(params: Self::Params) -> Self {
        Self {
            _params: params,
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip) {
        let _ = chip.allocate_committed_base::<{ 50 + 40144 }>();
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip) {
        let final_outputs =
            chip.allocate_output_evals::<{ KECCAK_OUTPUT_SIZE + KECCAK_INPUT_SIZE + LOOKUP_FELTS_PER_ROUND * ROUNDS }>();

        let mut final_outputs_iter = final_outputs.iter();

        let [keccak_output32, keccak_input32, lookup_outputs] = [
            KECCAK_OUTPUT_SIZE,
            KECCAK_INPUT_SIZE,
            // LOOKUPS_PER_ROUND
            LOOKUP_FELTS_PER_ROUND * ROUNDS,
        ]
        .map(|many| final_outputs_iter.by_ref().take(many).collect_vec());

        let keccak_output32 = keccak_output32.to_vec();
        let keccak_input32 = keccak_input32.to_vec();
        let lookup_outputs = lookup_outputs.to_vec();

        let (keccak_output8, []) = chip.allocate_wits_in_layer::<200, 0>();

        let keccak_output8: ArrayView<(Witness, EvalExpression), Ix3> =
            ArrayView::from_shape((5, 5, 8), &keccak_output8).unwrap();

        let mut expressions = vec![];
        let mut evals = vec![];
        let mut expr_names = vec![];

        let mut global_and_lookup = 0;
        let mut global_xor_lookup = 3 * AND_LOOKUPS;
        let mut global_range_lookup = 3 * AND_LOOKUPS + 3 * XOR_LOOKUPS;

        let mut openings = 0;

        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<32>(
                        &keccak_output8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0))
                            .collect_vec(),
                    );
                    expressions.push(expr);
                    evals.push(keccak_output32[evals.len()].clone());
                    expr_names.push(format!("build 32-bit output: {x}, {y}, {k}"));
                }
            }
        }

        chip.add_layer(Layer::new(
            "build 32-bit output".to_string(),
            LayerType::Zerocheck,
            expressions,
            vec![],
            keccak_output8
                .into_iter()
                .map(|e| e.1.clone())
                .collect_vec(),
            vec![],
            evals,
            expr_names,
        ));

        let state8_loop = (0..ROUNDS).rev().fold(
            keccak_output8.iter().map(|e| e.1.clone()).collect_vec(),
            |round_output, round| {
                #[allow(non_snake_case)]
                let (
                    state8,
                    c_aux,
                    c_temp,
                    c_rot,
                    d,
                    theta_output,
                    rotation_witness,
                    rhopi_output,
                    nonlinear,
                    chi_output,
                    iota_output,
                ) = allocate_and_split!(
                    chip, 1656, 200, 200, 30, 40, 40, 200, 146, 200, 200, 200, 200
                );

                let total_witnesses = 200 + 200 + 30 + 40 + 40 + 200 + 146 + 200 + 200 + 200 + 200;
                // dbg!(total_witnesses);
                assert_eq!(1656, total_witnesses);

                let bases = chain!(
                    state8.clone(),
                    c_aux.clone(),
                    c_temp.clone(),
                    c_rot.clone(),
                    d.clone(),
                    theta_output.clone(),
                    rotation_witness.clone(),
                    rhopi_output.clone(),
                    nonlinear.clone(),
                    chi_output.clone(),
                    iota_output.clone(),
                )
                .collect_vec();

                for wit in &bases {
                    chip.allocate_base_opening(openings, wit.clone().1);
                    openings += 1;
                }

                // TODO: ndarrays can be replaced with normal arrays

                // Input state of the round in 8-bit chunks
                let state8: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &state8).unwrap();

                let mut system = ConstraintSystem::new();

                // The purpose is to compute the auxiliary array
                // c[i] = XOR (state[j][i]) for j in 0..5
                // We unroll it into
                // c_aux[i][j] = XOR (state[k][i]) for k in 0..j
                // We use c_aux[i][4] instead of c[i]
                // c_aux is also stored in 8-bit chunks
                let c_aux: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &c_aux).unwrap();

                for i in 0..5 {
                    for k in 0..8 {
                        // Initialize first element
                        system.constrain_eq(
                            state8[[0, i, k]].0.into(),
                            c_aux[[i, 0, k]].0.into(),
                            "init c_aux".to_string(),
                        );
                    }
                    for j in 1..5 {
                        // Check xor using lookups over all chunks
                        for k in 0..8 {
                            system.lookup_xor8(
                                c_aux[[i, j - 1, k]].0.into(),
                                state8[[j, i, k]].0.into(),
                                c_aux[[i, j, k]].0.into(),
                            );
                        }
                    }
                }

                // Compute c_rot[i] = c[i].rotate_left(1)
                // To understand how rotations are performed in general, consult the
                // documentation of `constrain_left_rotation64`. Here c_temp is the split
                // witness for a 1-rotation.

                let c_temp: ArrayView<(Witness, EvalExpression), Ix2> =
                    ArrayView::from_shape((5, 6), &c_temp).unwrap();
                let c_rot: ArrayView<(Witness, EvalExpression), Ix2> =
                    ArrayView::from_shape((5, 8), &c_rot).unwrap();

                let (sizes, _) = rotation_split(1);

                for i in 0..5 {
                    assert_eq!(c_temp.slice(s![i, ..]).iter().len(), sizes.iter().len());

                    system.constrain_left_rotation64(
                        &c_aux.slice(s![i, 4, ..]).iter().map(|e| e.0).collect_vec(),
                        &zip_eq(c_temp.slice(s![i, ..]).iter(), sizes.iter())
                            .map(|(e, sz)| (*sz, e.0))
                            .collect_vec(),
                        &c_rot.slice(s![i, ..]).iter().map(|e| e.0).collect_vec(),
                        1,
                        "theta rotation".to_string(),
                    );
                }

                // d is computed simply as XOR of required elements of c (and rotations)
                // again stored as 8-bit chunks
                let d: ArrayView<(Witness, EvalExpression), Ix2> =
                    ArrayView::from_shape((5, 8), &d).unwrap();

                for i in 0..5 {
                    for k in 0..8 {
                        system.lookup_xor8(
                            c_aux[[(i + 5 - 1) % 5, 4, k]].0.into(),
                            c_rot[[(i + 1) % 5, k]].0.into(),
                            d[[i, k]].0.into(),
                        )
                    }
                }

                // output state of the Theta sub-round, simple XOR, in 8-bit chunks
                let theta_output: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &theta_output).unwrap();

                for i in 0..5 {
                    for j in 0..5 {
                        for k in 0..8 {
                            system.lookup_xor8(
                                state8[[j, i, k]].0.into(),
                                d[[i, k]].0.into(),
                                theta_output[[j, i, k]].0.into(),
                            )
                        }
                    }
                }

                // output state after applying both Rho and Pi sub-rounds
                // sub-round Pi is a simple permutation of 64-bit lanes
                // sub-round Rho requires rotations
                let rhopi_output: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &rhopi_output).unwrap();

                // iterator over split witnesses
                let mut rotation_witness = rotation_witness.iter();

                for i in 0..5 {
                    #[allow(clippy::needless_range_loop)]
                    for j in 0..5 {
                        let arg = theta_output
                            .slice(s!(j, i, ..))
                            .iter()
                            .map(|e| e.0)
                            .collect_vec();
                        let (sizes, _) = rotation_split(ROTATION_CONSTANTS[j][i]);
                        let many = sizes.len();
                        let rep_split = zip_eq(sizes, rotation_witness.by_ref().take(many))
                            .map(|(sz, (wit, _))| (sz, *wit))
                            .collect_vec();
                        let arg_rotated = rhopi_output
                            .slice(s!((2 * i + 3 * j) % 5, j, ..))
                            .iter()
                            .map(|e| e.0)
                            .collect_vec();
                        system.constrain_left_rotation64(
                            &arg,
                            &rep_split,
                            &arg_rotated,
                            ROTATION_CONSTANTS[j][i],
                            format!("RHOPI {i}, {j}"),
                        );
                    }
                }

                let chi_output: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &chi_output).unwrap();

                // for the Chi sub-round, we use an intermediate witness storing the result of
                // the required AND
                let nonlinear: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &nonlinear).unwrap();

                for i in 0..5 {
                    for j in 0..5 {
                        for k in 0..8 {
                            system.lookup_and8(
                                not8_expr(rhopi_output[[j, (i + 1) % 5, k]].0.into()),
                                rhopi_output[[j, (i + 2) % 5, k]].0.into(),
                                nonlinear[[j, i, k]].0.into(),
                            );

                            system.lookup_xor8(
                                rhopi_output[[j, i, k]].0.into(),
                                nonlinear[[j, i, k]].0.into(),
                                chi_output[[j, i, k]].0.into(),
                            );
                        }
                    }
                }

                // TODO: 24/25 elements stay the same after Iota; eliminate duplication?
                let iota_output: ArrayView<(Witness, EvalExpression), Ix3> =
                    ArrayView::from_shape((5, 5, 8), &iota_output).unwrap();

                for i in 0..5 {
                    for j in 0..5 {
                        if i == 0 && j == 0 {
                            for k in 0..8 {
                                system.lookup_xor8(
                                    chi_output[[j, i, k]].0.into(),
                                    Expression::Const(Constant::Base(
                                        ((RC[round] >> (k * 8)) & 0xFF) as i64,
                                    )),
                                    iota_output[[j, i, k]].0.into(),
                                );
                            }
                        } else {
                            for k in 0..8 {
                                system.constrain_eq(
                                    iota_output[[j, i, k]].0.into(),
                                    chi_output[[j, i, k]].0.into(),
                                    "nothing special".to_string(),
                                );
                            }
                        }
                    }
                }

                let ConstraintSystem {
                    mut expressions,
                    mut expr_names,
                    mut evals,
                    and_lookups,
                    xor_lookups,
                    range_lookups,
                    ..
                } = system;

                iota_output
                    .into_iter()
                    .enumerate()
                    .map(|(i, val)| {
                        expressions.push(val.0.into());
                        expr_names.push(format!("iota_output {i}"));
                        evals.push(round_output[i].clone());
                    })
                    .count();

                for (i, lookup) in chain!(and_lookups, xor_lookups, range_lookups)
                    .flatten()
                    .enumerate()
                {
                    expressions.push(lookup);
                    expr_names.push(format!("round {round}: {i}th lookup felt"));
                    let idx = if i < 3 * AND_LOOKUPS_PER_ROUND {
                        &mut global_and_lookup
                    } else if i < 3 * AND_LOOKUPS_PER_ROUND + 3 * XOR_LOOKUPS_PER_ROUND {
                        &mut global_xor_lookup
                    } else {
                        &mut global_range_lookup
                    };
                    evals.push(lookup_outputs[*idx].clone());
                    *idx += 1;
                }

                chip.add_layer(Layer::new(
                    format!("Round {round}"),
                    LayerType::Zerocheck,
                    expressions,
                    vec![],
                    bases.into_iter().map(|e| e.1).collect_vec(),
                    vec![],
                    evals,
                    expr_names,
                ));

                state8.into_iter().map(|e| e.1.clone()).collect_vec()
            },
        );

        assert!(global_and_lookup == 3 * AND_LOOKUPS);
        assert!(global_xor_lookup == 3 * AND_LOOKUPS + 3 * XOR_LOOKUPS);
        assert!(global_range_lookup == LOOKUP_FELTS_PER_ROUND * ROUNDS);

        let (state8, _) = chip.allocate_wits_in_layer::<200, 0>();

        let state8: ArrayView<(Witness, EvalExpression), Ix3> =
            ArrayView::from_shape((5, 5, 8), &state8).unwrap();

        let mut expressions = vec![];
        let mut evals = vec![];
        let mut expr_names = vec![];

        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<32>(
                        state8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0))
                            .collect_vec()
                            .as_slice(),
                    );
                    expressions.push(expr);
                    evals.push(keccak_input32[evals.len()].clone());
                    expr_names.push(format!("build 32-bit input: {x}, {y}, {k}"));
                }
            }
        }

        // TODO: eliminate this duplication
        zip_eq(state8.iter(), state8_loop.iter())
            .map(|(e, e_loop)| {
                expressions.push(e.0.into());
                evals.push(e_loop.clone());
                expr_names.push("state8 identity".to_string());
            })
            .count();

        chip.add_layer(Layer::new(
            "build 32-bit input".to_string(),
            LayerType::Zerocheck,
            expressions,
            vec![],
            state8.into_iter().map(|e| e.1.clone()).collect_vec(),
            vec![],
            evals,
            expr_names,
        ));

        // TODO: allocate everything
        chip.allocate_base_opening(0, state8[[0, 0, 0]].clone().1);
        chip.allocate_base_opening(1, state8[[0, 0, 1]].clone().1);
    }
}

#[derive(Clone, Default)]
pub struct KeccakTrace {
    pub instances: Vec<[u32; KECCAK_INPUT_SIZE]>,
}

impl<E> ProtocolWitnessGenerator<E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace;

    fn phase1_witness(&self, phase1: Self::Trace) -> Vec<Vec<E::BaseField>> {
        let mut poly = vec![vec![]; KECCAK_INPUT_SIZE];
        for instance in phase1.instances {
            let felts = u64s_to_felts::<E>(instance.into_iter().map(|e| e as u64).collect_vec());
            for i in 0..KECCAK_INPUT_SIZE {
                poly[i].push(felts[i]);
            }
        }
        poly
    }

    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], _challenges: &[E]) -> GKRCircuitWitness<E> {
        let n_layers = 24 + 2 + 1;
        let mut layer_wits = vec![
            LayerWitness {
                bases: vec![],
                exts: vec![],
                num_vars: 1
            };
            n_layers
        ];

        let num_instances = phase1[0].len();

        for i in 0..num_instances {
            fn conv64to8(input: u64) -> [u64; 8] {
                MaskRepresentation::new(vec![(64, input).into()])
                    .convert(vec![8; 8])
                    .values()
                    .try_into()
                    .unwrap()
            }

            let mut com_state = vec![];
            #[allow(clippy::needless_range_loop)]
            for j in 0..KECCAK_INPUT_SIZE {
                com_state.push(phase1[j][i]);
            }

            let mut and_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];
            let mut xor_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];
            let mut range_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];

            let mut add_and = |a: u64, b: u64, round: usize| {
                let c = a & b;
                assert!(a < (1 << 8));
                assert!(b < (1 << 8));
                and_lookups[round].extend(vec![a, b, c]);
            };

            let mut add_xor = |a: u64, b: u64, round: usize| {
                let c = a ^ b;
                assert!(a < (1 << 8));
                assert!(b < (1 << 8));
                xor_lookups[round].extend(vec![a, b, c]);
            };

            let mut add_range = |value: u64, size: usize, round: usize| {
                assert!(size <= 16, "{size}");
                range_lookups[round].push(value);
                if size < 16 {
                    range_lookups[round].push(value << (16 - size));
                    assert!(value << (16 - size) < (1 << 16));
                }
            };

            let state32 = com_state
                .into_iter()
                // TODO double check assumptions about canonical
                .map(|e| e.to_canonical_u64())
                .collect_vec();

            let mut state64 = [[0u64; 5]; 5];
            let mut state8 = [[[0u64; 8]; 5]; 5];

            zip_eq(iproduct!(0..5, 0..5), state32.clone().iter().tuples())
                .map(|((x, y), (lo, hi))| {
                    state64[x][y] = lo | (hi << 32);
                })
                .count();

            for x in 0..5 {
                for y in 0..5 {
                    state8[x][y] = conv64to8(state64[x][y]);
                }
            }

            let mut curr_layer = 0;
            let mut push_instance = |wits: Vec<u64>| {
                let felts = u64s_to_felts::<E>(wits);
                if layer_wits[curr_layer].bases.is_empty() {
                    layer_wits[curr_layer] = LayerWitness::new(nest::<E>(&felts), vec![]);
                } else {
                    assert_eq!(felts.len(), layer_wits[curr_layer].bases.len());
                    for (i, base) in layer_wits[curr_layer].bases.iter_mut().enumerate() {
                        base.push(felts[i]);
                    }
                }
                curr_layer += 1;
            };

            push_instance(state8.into_iter().flatten().flatten().collect_vec());

            #[allow(clippy::needless_range_loop)]
            for round in 0..ROUNDS {
                let mut c_aux64 = [[0u64; 5]; 5];
                let mut c_aux8 = [[[0u64; 8]; 5]; 5];

                for i in 0..5 {
                    c_aux64[i][0] = state64[0][i];
                    c_aux8[i][0] = conv64to8(c_aux64[i][0]);
                    for j in 1..5 {
                        c_aux64[i][j] = state64[j][i] ^ c_aux64[i][j - 1];
                        c_aux8[i][j] = conv64to8(c_aux64[i][j]);

                        for k in 0..8 {
                            add_xor(c_aux8[i][j - 1][k], state8[j][i][k], round);
                        }
                    }
                }

                let mut c64 = [0u64; 5];
                let mut c8 = [[0u64; 8]; 5];

                for x in 0..5 {
                    c64[x] = c_aux64[x][4];
                    c8[x] = conv64to8(c64[x]);
                }

                let mut c_temp = [[0u64; 6]; 5];
                for i in 0..5 {
                    let rep = MaskRepresentation::new(vec![(64, c64[i]).into()])
                        .convert(vec![16, 15, 1, 16, 15, 1]);
                    c_temp[i] = rep.values().try_into().unwrap();
                    for mask in rep.rep {
                        add_range(mask.value, mask.size, round);
                    }
                }

                let mut crot64 = [0u64; 5];
                let mut crot8 = [[0u64; 8]; 5];
                for i in 0..5 {
                    crot64[i] = c64[i].rotate_left(1);
                    crot8[i] = conv64to8(crot64[i]);
                }

                let mut d64 = [0u64; 5];
                let mut d8 = [[0u64; 8]; 5];
                for x in 0..5 {
                    d64[x] = c64[(x + 4) % 5] ^ c64[(x + 1) % 5].rotate_left(1);
                    d8[x] = conv64to8(d64[x]);
                    for k in 0..8 {
                        add_xor(c_aux8[(x + 4) % 5][4][k], crot8[(x + 1) % 5][k], round);
                    }
                }

                let mut theta_state64 = state64;
                let mut theta_state8 = [[[0u64; 8]; 5]; 5];
                let mut rotation_witness = vec![];

                for x in 0..5 {
                    for y in 0..5 {
                        theta_state64[y][x] ^= d64[x];
                        theta_state8[y][x] = conv64to8(theta_state64[y][x]);

                        for k in 0..8 {
                            add_xor(state8[y][x][k], d8[x][k], round);
                        }

                        let (sizes, _) = rotation_split(ROTATION_CONSTANTS[y][x]);
                        let rep = MaskRepresentation::new(vec![(64, theta_state64[y][x]).into()])
                            .convert(sizes);
                        for mask in rep.rep.iter() {
                            if mask.size != 32 {
                                add_range(mask.value, mask.size, round);
                            }
                        }
                        rotation_witness.extend(rep.values());
                    }
                }

                // Rho and Pi steps
                let mut rhopi_output64 = [[0u64; 5]; 5];
                let mut rhopi_output8 = [[[0u64; 8]; 5]; 5];

                for x in 0..5 {
                    for y in 0..5 {
                        rhopi_output64[(2 * x + 3 * y) % 5][y % 5] =
                            theta_state64[y][x].rotate_left(ROTATION_CONSTANTS[y][x] as u32);
                    }
                }

                for x in 0..5 {
                    for y in 0..5 {
                        rhopi_output8[x][y] = conv64to8(rhopi_output64[x][y]);
                    }
                }

                // Chi step

                let mut nonlinear64 = [[0u64; 5]; 5];
                let mut nonlinear8 = [[[0u64; 8]; 5]; 5];
                for x in 0..5 {
                    for y in 0..5 {
                        nonlinear64[y][x] =
                            !rhopi_output64[y][(x + 1) % 5] & rhopi_output64[y][(x + 2) % 5];
                        nonlinear8[y][x] = conv64to8(nonlinear64[y][x]);

                        for k in 0..8 {
                            add_and(
                                0xFF - rhopi_output8[y][(x + 1) % 5][k],
                                rhopi_output8[y][(x + 2) % 5][k],
                                round,
                            );
                        }
                    }
                }

                let mut chi_output64 = [[0u64; 5]; 5];
                let mut chi_output8 = [[[0u64; 8]; 5]; 5];
                for x in 0..5 {
                    for y in 0..5 {
                        chi_output64[y][x] = nonlinear64[y][x] ^ rhopi_output64[y][x];
                        chi_output8[y][x] = conv64to8(chi_output64[y][x]);
                        for k in 0..8 {
                            add_xor(rhopi_output8[y][x][k], nonlinear8[y][x][k], round)
                        }
                    }
                }

                // Iota step
                let mut iota_output64 = chi_output64;
                let mut iota_output8 = [[[0u64; 8]; 5]; 5];
                iota_output64[0][0] ^= RC[round];

                for k in 0..8 {
                    add_xor(chi_output8[0][0][k], (RC[round] >> (k * 8)) & 0xFF, round);
                }

                for x in 0..5 {
                    for y in 0..5 {
                        iota_output8[x][y] = conv64to8(iota_output64[x][y]);
                    }
                }

                let all_wits64 = [
                    state8.into_iter().flatten().flatten().collect_vec(),
                    c_aux8.into_iter().flatten().flatten().collect_vec(),
                    c_temp.into_iter().flatten().collect_vec(),
                    crot8.into_iter().flatten().collect_vec(),
                    d8.into_iter().flatten().collect_vec(),
                    theta_state8.into_iter().flatten().flatten().collect_vec(),
                    rotation_witness,
                    rhopi_output8.into_iter().flatten().flatten().collect_vec(),
                    nonlinear8.into_iter().flatten().flatten().collect_vec(),
                    chi_output8.into_iter().flatten().flatten().collect_vec(),
                    iota_output8.into_iter().flatten().flatten().collect_vec(),
                ];

                push_instance(all_wits64.into_iter().flatten().collect_vec());

                state8 = iota_output8;
                state64 = iota_output64;
            }

            let mut keccak_output32 = vec![vec![vec![0; 2]; 5]; 5];

            for x in 0..5 {
                for y in 0..5 {
                    keccak_output32[x][y] = MaskRepresentation::from(
                        state8[x][y].into_iter().map(|e| (8, e)).collect_vec(),
                    )
                    .convert(vec![32; 2])
                    .values();
                }
            }

            push_instance(state8.into_iter().flatten().flatten().collect_vec());

            // For temporary convenience, use one extra layer to store the correct outputs
            // of the circuit This is not used during proving
            let lookups = chain!(
                (0..ROUNDS).rev().flat_map(|i| and_lookups[i].clone()),
                (0..ROUNDS).rev().flat_map(|i| xor_lookups[i].clone()),
                (0..ROUNDS).rev().flat_map(|i| range_lookups[i].clone())
            )
            .collect_vec();

            push_instance(
                chain!(
                    keccak_output32.into_iter().flatten().flatten(),
                    state32,
                    lookups
                )
                .collect_vec(),
            );
        }

        let len = layer_wits.len() - 1;
        layer_wits[..len].reverse();

        GKRCircuitWitness { layers: layer_wits }
    }
}

pub fn run_faster_keccakf(states: Vec<[u64; 25]>, verify: bool, test_outputs: bool) {
    let params = KeccakParams {};
    let (layout, chip) = KeccakLayout::build(params);

    let mut instances = vec![];
    for state in &states {
        let state_mask64 = MaskRepresentation::from(state.iter().map(|e| (64, *e)).collect_vec());
        let state_mask32 = state_mask64.convert(vec![32; 50]);

        instances.push(
            state_mask32
                .values()
                .iter()
                .map(|e| *e as u32)
                .collect_vec()
                .try_into()
                .unwrap(),
        );
    }

    let num_instances = instances.len();
    let phase1_witness = layout.phase1_witness(KeccakTrace {
        instances: instances.clone(),
    });

    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    // Omit the commit phase1 and phase2.
    let gkr_witness: GKRCircuitWitness<E> = layout.gkr_witness(&phase1_witness, &[]);

    let out_evals = {
        let log2_num_instances = num_instances.next_power_of_two().trailing_zeros();
        let point = Arc::new(vec![E::from_u64(29); log2_num_instances as usize]);

        if test_outputs {
            // Confront outputs with tiny_keccak::keccakf call
            let mut instance_outputs = vec![vec![]; num_instances];
            for base in gkr_witness
                .layers
                .last()
                .unwrap()
                .bases
                .iter()
                .take(KECCAK_OUTPUT_SIZE)
            {
                assert_eq!(base.len(), num_instances);
                for i in 0..num_instances {
                    instance_outputs[i].push(base[i]);
                }
            }

            for i in 0..num_instances {
                let mut state = states[i];
                keccakf(&mut state);
                assert_eq!(
                    state
                        .to_vec()
                        .iter()
                        .flat_map(|e| vec![*e as u32, (e >> 32) as u32])
                        .map(|e| Goldilocks::from_u64(e as u64))
                        .collect_vec(),
                    instance_outputs[i]
                );
            }
        }

        let out_evals = gkr_witness
            .layers
            .last()
            .unwrap()
            .bases
            .iter()
            .map(|base| PointAndEval {
                point: point.clone(),
                eval: subprotocols::utils::evaluate_mle_ext(base, &point),
            })
            .collect_vec();

        assert_eq!(
            out_evals.len(),
            KECCAK_INPUT_SIZE + KECCAK_OUTPUT_SIZE + LOOKUP_FELTS_PER_ROUND * ROUNDS
        );

        out_evals
    };

    let gkr_circuit = chip.gkr_circuit();
    dbg!(&gkr_circuit.layers.len());
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove(gkr_witness, &out_evals, &[], &mut prover_transcript)
        .expect("Failed to prove phase");

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

            gkr_circuit
                .verify(gkr_proof, &out_evals, &[], &mut verifier_transcript)
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_keccakf() {
        for _ in 0..3 {
            // let random_u64: u64 = rand::random();
            // Use seeded rng for debugging convenience
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);

            let num_instances = 8;
            let mut states: Vec<[u64; 25]> = vec![];

            for _ in 0..num_instances {
                states.push(std::array::from_fn(|_| rng.gen()))
            }
            run_faster_keccakf(states, true, true);
        }
    }

    // TODO: make it pass
    #[ignore]
    #[test]
    fn test_keccakf_nonpow2() {
        for _ in 0..3 {
            // let random_u64: u64 = rand::random();
            // Use seeded rng for debugging convenience
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);

            let num_instances = 3;
            let mut states: Vec<[u64; 25]> = vec![];

            for _ in 0..num_instances {
                states.push(std::array::from_fn(|_| rng.gen()))
            }
            run_faster_keccakf(states, true, true);
        }
    }
}
