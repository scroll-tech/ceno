use std::{
    array::from_fn,
    cmp::Ordering,
    iter::{once, zip},
    marker::PhantomData,
    sync::Arc,
};

use crate::{
    chip::Chip,
    evaluation::{EvalExpression, PointAndEval},
    gkr::{
        layer::{Layer, LayerType, LayerWitness},
        GKRCircuitWitness, GKRProverOutput,
    },
    precompiles::utils::{nest, not8_expr, zero_expr, MaskRepresentation},
    ProtocolBuilder, ProtocolWitnessGenerator,
};
use ndarray::{range, s, ArrayView, Ix2, Ix3};

use witness::RowMajorMatrix;

use super::utils::{u64s_to_felts, zero_eval, CenoLookup};
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};

use ff_ext::{ExtensionField, SmallField};
use itertools::{chain, iproduct, zip_eq, Itertools};
use p3_goldilocks::Goldilocks;
use subprotocols::expression::{Constant, Expression, Witness};
use tiny_keccak::keccakf;
use transcript::BasicTranscript;

type E = BinomialExtensionField<Goldilocks, 2>;

#[derive(Clone, Debug, Default)]
pub struct KeccakParams {}

#[derive(Clone, Debug, Default)]
pub struct KeccakLayout<E> {
    params: KeccakParams,

    committed_bits_id: usize,

    result: Vec<EvalExpression>,
    _marker: PhantomData<E>,
}

fn expansion_expr<const SIZE: usize>(expansion: &[(usize, Witness)]) -> Expression {
    let (total, ret) = expansion
        .iter()
        .rev()
        .fold((0, zero_expr()), |acc, (sz, felt)| {
            (
                acc.0 + sz,
                acc.1 * Expression::Const(Constant::Base(1 << sz)) + felt.clone().into(),
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
    /// This suffix can contain several elements.
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
                self.lookup_range(elem.clone().into(), *size);
            }
        }

        // constrain the fact that rep8 and repX.rotate_left(chunks_rotation) are
        // the same 64 bitstring
        let mut helper = |rep8: &[Witness], repX: &[(usize, Witness)], chunks_rotation: usize| {
            // Do the same thing for the two 32-bit halves
            let mut repX = repX.to_owned();
            repX.rotate_right(chunks_rotation);

            for i in 0..2 {
                // The respective 4 elements in the byte representation
                let lhs = rep8[4 * i..4 * (i + 1)]
                    .iter()
                    .map(|wit| (8, wit.clone()))
                    .collect_vec();
                let cnt = repX.len() / 2;
                let rhs = &repX[cnt * i..cnt * (i + 1)];

                assert_eq!(rhs.iter().map(|e| e.0).sum::<usize>(), 32);

                self.constrain_reps_eq::<32>(
                    &lhs,
                    &rhs,
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
pub const LOOKUPS_PER_ROUND: usize =
    AND_LOOKUPS_PER_ROUND + XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND;

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
            params,
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip) {
        [self.committed_bits_id] = chip.allocate_committed_base();
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip) {
        let final_outputs =
            chip.allocate_output_evals::<{ KECCAK_OUTPUT_SIZE + KECCAK_INPUT_SIZE + LOOKUPS_PER_ROUND * ROUNDS }>();

        let mut final_outputs_iter = final_outputs.iter();

        let [keccak_output32, keccak_input32, lookup_outputs] = [
            KECCAK_OUTPUT_SIZE,
            KECCAK_INPUT_SIZE,
            LOOKUPS_PER_ROUND * ROUNDS,
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

        let mut lookup_index = 0;

        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<32>(
                        &keccak_output8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0.clone()))
                            .collect_vec()
                            .as_slice(),
                    );
                    expressions.push(expr);
                    evals.push(keccak_output32[evals.len()].clone());
                    expr_names.push(format!("build 32-bit output: {x}, {y}, {k}"));
                }
            }
        }

        chip.add_layer(Layer::new(
            format!("build 32-bit output"),
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

        let state8_loop = (0..ROUNDS).rev().into_iter().fold(
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

                // TODO: replace ndarrays

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
                    for j in 0..5 {
                        let arg = theta_output
                            .slice(s!(j, i, ..))
                            .iter()
                            .map(|e| e.0)
                            .collect_vec();
                        let (sizes, _) = rotation_split(ROTATION_CONSTANTS[j][i]);
                        let many = sizes.len();
                        let rep_split = zip_eq(sizes, rotation_witness.by_ref().take(many))
                            .map(|(sz, (wit, _))| (sz, wit.clone()))
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

                // TODO: use real challenge
                let alpha = Constant::Base(1 << 8);
                let beta = Constant::Base(0);

                // Send all lookups to the final output layer
                for (i, lookup) in chain!(and_lookups, xor_lookups, range_lookups).enumerate() {
                    expressions.push(lookup.compress(alpha.clone(), beta.clone()));
                    expr_names.push(format!("{i}th: {:?}", lookup));
                    evals.push(lookup_outputs[lookup_index].clone());
                    lookup_index += 1;
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

                state8
                    .into_iter()
                    .map(|e| e.1.clone())
                    .collect_vec()
                    .try_into()
                    .unwrap()
            },
        );

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
                        &state8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0.clone()))
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
                expressions.push(e.0.clone().into());
                evals.push(e_loop.clone());
                expr_names.push(format!("state8 identity"));
            })
            .count();

        chip.add_layer(Layer::new(
            format!("build 32-bit input"),
            LayerType::Zerocheck,
            expressions,
            vec![],
            state8.into_iter().map(|e| e.1.clone()).collect_vec(),
            vec![],
            evals,
            expr_names,
        ));
    }
}

#[derive(Clone, Default)]
pub struct KeccakTrace {
    pub instances: Vec<[u32; KECCAK_INPUT_SIZE]>,
}

use p3_field::Field;

impl<F: Field> From<RowMajorMatrix<F>> for KeccakTrace {
    fn from(value: RowMajorMatrix<F>) -> Self {
        unimplemented!();
    }
}

impl<E> ProtocolWitnessGenerator<E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace;

    fn phase1_witness(&self, phase1: Self::Trace) -> Vec<Vec<E::BaseField>> {
        let mut res = vec![];
        for instance in phase1.instances {
            res.push(u64s_to_felts::<E>(
                instance.into_iter().map(|e| e as u64).collect_vec(),
            ));
        }
        res
    }

    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], challenges: &[E]) -> GKRCircuitWitness<E> {
        let n_layers = 24 + 2 + 1;
        let mut layer_wits = vec![
            LayerWitness {
                bases: vec![],
                exts: vec![],
                num_vars: 1
            };
            n_layers
        ];

        for com_state in phase1 {
            fn conv64to8(input: u64) -> [u64; 8] {
                MaskRepresentation::new(vec![(64, input).into()])
                    .convert(vec![8; 8])
                    .values()
                    .try_into()
                    .unwrap()
            }

            let mut and_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];
            let mut xor_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];
            let mut range_lookups: Vec<Vec<u64>> = vec![vec![]; ROUNDS];

            let mut add_and = |a: u64, b: u64, round: usize| {
                let c = a & b;
                and_lookups[round].push((c << 16) + (b << 8) + a);
            };

            let mut add_xor = |a: u64, b: u64, round: usize| {
                let c = a ^ b;
                xor_lookups[round].push((c << 16) + (b << 8) + a);
            };

            let mut add_range = |value: u64, size: usize, round: usize| {
                assert!(size <= 16, "{size}");
                range_lookups[round].push(value);
                if size < 16 {
                    range_lookups[round].push(value << (16 - size));
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
                    for (i, bases) in layer_wits[curr_layer].bases.iter_mut().enumerate() {
                        bases.push(felts[i]);
                    }
                }
                curr_layer += 1;
            };

            push_instance(state8.clone().into_iter().flatten().flatten().collect_vec());

            for round in 0..24 {
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

                let mut theta_state64 = state64.clone();
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
                let mut iota_output64 = chi_output64.clone();
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
                    iota_output8
                        .clone()
                        .into_iter()
                        .flatten()
                        .flatten()
                        .collect_vec(),
                ];

                // let sizes = all_wits64.iter().map(|e| e.len()).collect_vec();
                // dbg!(&sizes);

                // let all_wits = nest::<E>(
                //     &all_wits64
                //         .into_iter()
                //         .flat_map(|v| u64s_to_felts::<E>(v))
                //         .collect_vec(),
                // );

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

            push_instance(state8.clone().into_iter().flatten().flatten().collect_vec());

            // For temporary convenience, use one extra layer to store the correct outputs
            // of the circuit This is not used during proving
            let lookups = (0..24)
                .into_iter()
                .rev()
                .flat_map(|i| {
                    chain!(
                        and_lookups[i].clone(),
                        xor_lookups[i].clone(),
                        range_lookups[i].clone()
                    )
                })
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

pub fn run_faster_keccakf(states: Vec<[u64; 25]>, verify: bool, test: bool) -> () {
    let params = KeccakParams {};
    let (layout, chip) = KeccakLayout::build(params);
    let gkr_circuit = chip.gkr_circuit();

    let mut instances = vec![];
    for state in states {
        let state_mask64 =
            MaskRepresentation::from(state.into_iter().map(|e| (64, e)).collect_vec());
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

    let phase1_witness = layout.phase1_witness(KeccakTrace { instances });

    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    // Omit the commit phase1 and phase2.
    let gkr_witness: GKRCircuitWitness<E> = layout.gkr_witness(&phase1_witness, &vec![]);

    let out_evals = {
        let point1 = Arc::new(vec![E::ZERO]);
        let point2 = Arc::new(vec![E::ONE]);
        let final_output1 = gkr_witness
            .layers
            .last()
            .unwrap()
            .bases
            //.clone()
            .iter()
            .map(|base| base[0].clone())
            .collect_vec();
        let final_output2 = gkr_witness
            .layers
            .last()
            .unwrap()
            .bases
            //.clone()
            .iter()
            .map(|base| base[1].clone())
            .collect_vec();

        // if test {
        //     // confront outputs with tiny_keccak result
        //     let mut keccak_output64 = state_mask64.values().try_into().unwrap();
        //     keccakf(&mut keccak_output64);

        //     let keccak_output32 = MaskRepresentation::from(
        //         keccak_output64.into_iter().map(|e| (64, e)).collect_vec(),
        //     )
        //     .convert(vec![32; 50])
        //     .values();

        //     let keccak_output32 = u64s_to_felts::<E>(keccak_output32);
        //     assert_eq!(keccak_output32, final_output[..50]);
        // }

        let len = final_output1.len();
        let gkr_outputs = chain!(
            zip(final_output1, once(point1).cycle().take(len)),
            zip(final_output2, once(point2).cycle().take(len))
        );
        gkr_outputs
            .into_iter()
            .map(|(elem, point)| PointAndEval {
                point: point.clone(),
                eval: E::from_bases(&[elem, Goldilocks::ZERO]),
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
    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_v2_keccakf() {
        for _ in 0..3 {
            let random_u64: u64 = rand::random();
            // Use seeded rng for debugging convenience
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);
            let state1: [u64; 25] = std::array::from_fn(|_| rng.gen());
            let state2: [u64; 25] = std::array::from_fn(|_| rng.gen());
            // let state = [0; 50];
            run_faster_keccakf(vec![state1, state2], true, true);
        }
    }
}
