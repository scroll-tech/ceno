use std::{cmp::Ordering, marker::PhantomData};

use crate::gkr::booleanhypercube::BooleanHypercube;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct, izip, zip_eq};
use multilinear_extensions::{Expression, ToExpr, WitIn, mle::PointAndEval, util::ceil_log2};
use ndarray::{ArrayView, Ix2, Ix3, s};
use p3_field::FieldAlgebra;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
        ParallelIterator,
    },
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use transcript::{BasicTranscript, Transcript};
use witness::{
    CAPACITY_RESERVED_FACTOR, InstancePaddingStrategy, RowMajorMatrix, next_pow2_instance_padding,
};

use crate::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    error::BackendError,
    evaluation::EvalExpression,
    gkr::{
        GKRCircuit, GKRProof, GKRProverOutput,
        layer::{Layer, LayerType},
    },
    precompiles::utils::{
        MaskRepresentation, not8_expr, set_slice_felts_from_u64 as push_instance,
    },
};

use super::utils::CenoLookup;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeccakParams {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeccakLayout<E> {
    input8: Vec<usize>,
    c_aux: Vec<usize>,
    c_temp: Vec<usize>,
    c_rot: Vec<usize>,
    d: Vec<usize>,
    theta_output: Vec<usize>,
    rotation_witness: Vec<usize>,
    rhopi_output: Vec<usize>,
    nonlinear: Vec<usize>,
    chi_output: Vec<usize>,
    iota_output: Vec<usize>,
    _marker: PhantomData<E>,
}

fn expansion_expr<E: ExtensionField, const SIZE: usize>(
    expansion: &[(usize, Expression<E>)],
) -> Expression<E> {
    let (total, ret) =
        expansion
            .iter()
            .rev()
            .fold((0, E::BaseField::ZERO.expr()), |acc, (sz, felt)| {
                (
                    acc.0 + sz,
                    acc.1 * E::BaseField::from_canonical_u64(1 << sz).expr() + felt.expr(),
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

#[derive(Default)]
struct ConstraintSystem<E: ExtensionField> {
    // expressions include zero & non-zero expression, differentiate via evals
    // zero expr represented as Linear with all 0 value
    // TODO we should define an Zero enum for it
    expressions: Vec<Expression<E>>,
    expr_names: Vec<String>,
    evals: Vec<EvalExpression<E>>,

    and_lookups: Vec<CenoLookup<E>>,
    xor_lookups: Vec<CenoLookup<E>>,
    range_lookups: Vec<CenoLookup<E>>,
}

impl<E: ExtensionField> ConstraintSystem<E> {
    fn new() -> Self {
        ConstraintSystem::default()
    }

    fn add_zero_constraint(&mut self, expr: Expression<E>, name: String) {
        self.expressions.push(expr);
        self.evals.push(EvalExpression::Zero);
        self.expr_names.push(name);
    }

    fn add_non_zero_constraint(
        &mut self,
        expr: Expression<E>,
        eval: EvalExpression<E>,
        name: String,
    ) {
        self.expressions.push(expr);
        self.evals.push(eval);
        self.expr_names.push(name);
    }

    fn lookup_and8(&mut self, a: Expression<E>, b: Expression<E>, c: Expression<E>) {
        self.and_lookups.push(CenoLookup::And(a, b, c));
    }

    fn lookup_xor8(&mut self, a: Expression<E>, b: Expression<E>, c: Expression<E>) {
        self.xor_lookups.push(CenoLookup::Xor(a, b, c));
    }

    /// Generates U16 lookups to prove that `value` fits on `size < 16` bits.
    /// In general it can be done by two U16 checks: one for `value` and one for
    /// `value << (16 - size)`.
    fn lookup_range(&mut self, value: Expression<E>, size: usize) {
        assert!(size <= 16);
        self.range_lookups.push(CenoLookup::U16(value.clone()));
        if size < 16 {
            self.range_lookups.push(CenoLookup::U16(
                value * E::BaseField::from_canonical_u64(1 << (16 - size)).expr(),
            ))
        }
    }

    fn constrain_eq(&mut self, lhs: Expression<E>, rhs: Expression<E>, name: String) {
        self.add_zero_constraint(lhs - rhs, name);
    }

    // Constrains that lhs and rhs encode the same value of SIZE bits
    // WARNING: Assumes that forall i, (lhs[i].1 < (2 ^ lhs[i].0))
    // This needs to be constrained separately
    fn constrain_reps_eq<const SIZE: usize>(
        &mut self,
        lhs: &[(usize, Expression<E>)],
        rhs: &[(usize, Expression<E>)],
        name: String,
    ) {
        self.add_zero_constraint(
            expansion_expr::<E, SIZE>(lhs) - expansion_expr::<E, SIZE>(rhs),
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
        input8: &[Expression<E>],
        split_rep: &[(usize, Expression<E>)],
        rot8: &[Expression<E>],
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
                self.lookup_range(elem.expr(), *size);
            }
        }

        // constrain the fact that rep8 and repX.rotate_left(chunks_rotation) are
        // the same 64 bitstring
        let mut helper = |rep8: &[Expression<E>],
                          rep_x: &[(usize, Expression<E>)],
                          chunks_rotation: usize| {
            // Do the same thing for the two 32-bit halves
            let mut rep_x = rep_x.to_owned();
            rep_x.rotate_right(chunks_rotation);

            for i in 0..2 {
                // The respective 4 elements in the byte representation
                let lhs = rep8[4 * i..4 * (i + 1)]
                    .iter()
                    .map(|wit| (8, wit.expr()))
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
const ROUNDS_CEIL_LOG2: usize = 5; // log_2(2^32)

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

pub const KECCAK_LAYER_BYTE_SIZE: usize = 200;

pub const AND_LOOKUPS_PER_ROUND: usize = 200;
pub const XOR_LOOKUPS_PER_ROUND: usize = 608;
pub const RANGE_LOOKUPS_PER_ROUND: usize = 290;
pub const LOOKUP_FELTS_PER_ROUND: usize =
    3 * AND_LOOKUPS_PER_ROUND + 3 * XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND;

pub const AND_LOOKUPS: usize = AND_LOOKUPS_PER_ROUND;
pub const XOR_LOOKUPS: usize = XOR_LOOKUPS_PER_ROUND;
pub const RANGE_LOOKUPS: usize = RANGE_LOOKUPS_PER_ROUND;

pub const KECCAK_OUT_EVAL_SIZE: usize =
    KECCAK_INPUT_SIZE + KECCAK_OUTPUT_SIZE + LOOKUP_FELTS_PER_ROUND;

pub const KECCAK_WIT_SIZE_PER_ROUND: usize = 1264;
pub const KECCAK_WIT_SIZE: usize = KECCAK_WIT_SIZE_PER_ROUND + KECCAK_LAYER_BYTE_SIZE;

#[allow(unused)]
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

macro_rules! split_from_offset {
    ($witnesses:expr, $offset:expr, $total:expr, $( $size:expr ),* ) => {{
        let mut iter = $witnesses[$offset..].iter().cloned();
        (
            $(
                iter.by_ref().take($size).collect_vec(),
            )*
        )
    }};
}

impl<E: ExtensionField> ProtocolBuilder<E> for KeccakLayout<E> {
    type Params = KeccakParams;

    fn init(_params: Self::Params) -> Self {
        Self {
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip<E>) {
        let bases = chip.allocate_committed::<KECCAK_WIT_SIZE>();

        (
            self.input8,
            self.c_aux,
            self.c_temp,
            self.c_rot,
            self.d,
            self.theta_output,
            self.rotation_witness,
            self.rhopi_output,
            self.nonlinear,
            self.chi_output,
            self.iota_output,
        ) = split_from_offset!(
            bases,
            0,
            KECCAK_WIT_SIZE,
            KECCAK_LAYER_BYTE_SIZE,
            200,
            30,
            40,
            40,
            200,
            146,
            200,
            200,
            8,
            200
        );
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip<E>) {
        let final_outputs =
            chip.allocate_output_evals::<{ KECCAK_OUTPUT_SIZE + KECCAK_INPUT_SIZE + LOOKUP_FELTS_PER_ROUND }>();

        let mut final_outputs_iter = final_outputs.iter();

        // TODO we can rlc lookup via alpha/beta challenge, so gkr output layer only got rlc result
        // with that, we save more prover cost with less allocation

        let [keccak_output32, keccak_input32, lookup_outputs] = [
            KECCAK_OUTPUT_SIZE,
            KECCAK_INPUT_SIZE,
            LOOKUP_FELTS_PER_ROUND,
        ]
        .map(|many| final_outputs_iter.by_ref().take(many).collect_vec());

        assert!(final_outputs_iter.next().is_none());

        let lookup_outputs = lookup_outputs.to_vec();

        // TODO we should separate into different eq group, because they should reduce from differenent points
        // TODO it should be at least 2 group.
        // TODO   - group1: lookup one group (due to same tower prover length)
        // TODO   - group2: read/write another group
        // NOTE: eq order must follow gkr prover/verifier backend concat eq order
        let (wits, [eq_zero, eq_rotation_left, eq_rotation_right, eq_rotation]) =
            chip.allocate_wits_in_zero_layer::<KECCAK_WIT_SIZE, 4>();
        for (openings, wit) in wits.iter().enumerate() {
            chip.allocate_opening(openings, wit.1.clone());
        }

        let keccak_input8 = &wits[..KECCAK_LAYER_BYTE_SIZE];
        let keccak_output8 = &wits[KECCAK_WIT_SIZE - KECCAK_LAYER_BYTE_SIZE..];

        let mut system = ConstraintSystem::new();

        #[allow(non_snake_case)]
        let (
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
        ) = split_from_offset!(
            wits,
            KECCAK_LAYER_BYTE_SIZE,
            KECCAK_WIT_SIZE,
            200,
            30,
            40,
            40,
            200,
            146,
            200,
            200,
            8,
            200
        );

        {
            let n_wits =
                KECCAK_LAYER_BYTE_SIZE + 200 + 30 + 40 + 40 + 200 + 146 + 200 + 200 + 8 + 200;
            assert_eq!(KECCAK_WIT_SIZE, n_wits);
        }

        // TODO: ndarrays can be replaced with normal arrays

        // Input state of the round in 8-bit chunks
        let state8: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), keccak_input8).unwrap();

        // The purpose is to compute the auxiliary array
        // c[i] = XOR (state[j][i]) for j in 0..5
        // We unroll it into
        // c_aux[i][j] = XOR (state[k][i]) for k in 0..j
        // We use c_aux[i][4] instead of c[i]
        // c_aux is also stored in 8-bit chunks
        let c_aux: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
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

        let c_temp: ArrayView<(WitIn, EvalExpression<E>), Ix2> =
            ArrayView::from_shape((5, 6), &c_temp).unwrap();
        let c_rot: ArrayView<(WitIn, EvalExpression<E>), Ix2> =
            ArrayView::from_shape((5, 8), &c_rot).unwrap();

        let (sizes, _) = rotation_split(1);

        for i in 0..5 {
            assert_eq!(c_temp.slice(s![i, ..]).iter().len(), sizes.iter().len());

            system.constrain_left_rotation64(
                &c_aux
                    .slice(s![i, 4, ..])
                    .iter()
                    .map(|e| e.0.expr())
                    .collect_vec(),
                &zip_eq(c_temp.slice(s![i, ..]).iter(), sizes.iter())
                    .map(|(e, sz)| (*sz, e.0.expr()))
                    .collect_vec(),
                &c_rot
                    .slice(s![i, ..])
                    .iter()
                    .map(|e| e.0.expr())
                    .collect_vec(),
                1,
                "theta rotation".to_string(),
            );
        }

        // d is computed simply as XOR of required elements of c (and rotations)
        // again stored as 8-bit chunks
        let d: ArrayView<(WitIn, EvalExpression<E>), Ix2> =
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
        let theta_output: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
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
        let rhopi_output: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), &rhopi_output).unwrap();

        // iterator over split witnesses
        let mut rotation_witness = rotation_witness.iter();

        for i in 0..5 {
            #[allow(clippy::needless_range_loop)]
            for j in 0..5 {
                let arg = theta_output
                    .slice(s!(j, i, ..))
                    .iter()
                    .map(|e| e.0.expr())
                    .collect_vec();
                let (sizes, _) = rotation_split(ROTATION_CONSTANTS[j][i]);
                let many = sizes.len();
                let rep_split = zip_eq(sizes, rotation_witness.by_ref().take(many))
                    .map(|(sz, (wit, _))| (sz, wit.expr()))
                    .collect_vec();
                let arg_rotated = rhopi_output
                    .slice(s!((2 * i + 3 * j) % 5, j, ..))
                    .iter()
                    .map(|e| e.0.expr())
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

        let mut chi_output = chi_output;
        chi_output.extend(iota_output[8..].to_vec());
        let chi_output: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), &chi_output).unwrap();

        // for the Chi sub-round, we use an intermediate witness storing the result of
        // the required AND
        let nonlinear: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
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

        let iota_output_arr: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), &iota_output).unwrap();

        for k in 0..8 {
            system.lookup_xor8(
                chi_output[[0, 0, k]].0.into(),
                // TODO figure out how to deal with RC, since it's not a constant in rotation
                E::BaseField::from_canonical_u64((RC[0] >> (k * 8)) & 0xFF).expr(),
                iota_output_arr[[0, 0, k]].0.into(),
            );
        }

        let keccak_input8: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), keccak_input8).unwrap();
        let keccak_input32 = keccak_input32.to_vec();
        let mut keccak_input32_iter = keccak_input32.iter().cloned();

        let keccak_output32 = keccak_output32.to_vec();
        let keccak_output8: ArrayView<(WitIn, EvalExpression<E>), Ix3> =
            ArrayView::from_shape((5, 5, 8), keccak_output8).unwrap();
        let mut keccak_output32_iter = keccak_output32.iter().cloned();

        // process keccak output
        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<E, 32>(
                        &keccak_output8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0.expr()))
                            .collect_vec(),
                    );
                    system.add_non_zero_constraint(
                        expr,
                        keccak_output32_iter.next().unwrap().clone(),
                        format!("build 32-bit output: {x}, {y}, {k}"),
                    );
                }
            }
        }

        // process keccak input
        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<E, 32>(
                        keccak_input8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.0.expr()))
                            .collect_vec()
                            .as_slice(),
                    );
                    system.add_non_zero_constraint(
                        expr,
                        keccak_input32_iter.next().unwrap().clone(),
                        format!("build 32-bit input: {x}, {y}, {k}"),
                    );
                }
            }
        }

        let mut global_and_lookup = 0;
        let mut global_xor_lookup = 3 * AND_LOOKUPS;
        let mut global_range_lookup = 3 * AND_LOOKUPS + 3 * XOR_LOOKUPS;

        for (i, lookup) in chain!(
            system.and_lookups.clone(),
            system.xor_lookups.clone(),
            system.range_lookups.clone()
        )
        .flatten()
        .enumerate()
        {
            let idx = if i < 3 * AND_LOOKUPS {
                &mut global_and_lookup
            } else if i < 3 * AND_LOOKUPS + 3 * XOR_LOOKUPS {
                &mut global_xor_lookup
            } else {
                &mut global_range_lookup
            };
            system.add_non_zero_constraint(
                lookup,
                lookup_outputs[*idx].clone(),
                format!("round 0th: {i}th lookup felt"),
            );
            *idx += 1;
        }

        assert_eq!(global_and_lookup, 3 * AND_LOOKUPS);
        assert_eq!(global_xor_lookup, 3 * AND_LOOKUPS + 3 * XOR_LOOKUPS);
        assert_eq!(global_range_lookup, LOOKUP_FELTS_PER_ROUND);

        // rotation constrain: rotation(keccak_input8).next() == keccak_output8
        let rotations = izip!(keccak_input8, keccak_output8)
            .map(|((input, _), (output, _))| (input.expr(), output.expr()))
            .collect_vec();

        let ConstraintSystem {
            expressions,
            expr_names,
            evals,
            ..
        } = system;

        chip.add_layer(Layer::new(
            "Rounds".to_string(),
            LayerType::Zerocheck,
            expressions,
            vec![],
            wits.into_iter().map(|e| e.1).collect_vec(),
            vec![(Some(eq_zero.0.expr()), evals)],
            (
                (
                    Some([
                        eq_rotation_left.0.expr(),
                        eq_rotation_right.0.expr(),
                        eq_rotation.0.expr(),
                    ]),
                    rotations,
                ),
                ROUNDS_CEIL_LOG2,
                ROUNDS - 1,
            ),
            expr_names,
        ));
    }
}

#[derive(Clone, Default)]
pub struct KeccakTrace {
    pub instances: Vec<[u32; KECCAK_INPUT_SIZE]>,
}

impl<E> ProtocolWitnessGenerator<'_, E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace;

    fn phase1_witness_group(&self, phase1: Self::Trace) -> RowMajorMatrix<E::BaseField> {
        let instances = &phase1.instances;
        let num_instances = instances.len();

        fn conv64to8(input: u64) -> [u64; 8] {
            MaskRepresentation::new(vec![(64, input).into()])
                .convert(vec![8; 8])
                .values()
                .try_into()
                .unwrap()
        }

        // TODO take structural id information from circuit to do wits assignment
        // 1 instance will derive 24 round result + 8 round padding to pow2 for easiler rotation design
        let n_row_padding = next_pow2_instance_padding(num_instances * ROUNDS.next_power_of_two());
        let mut wits =
            Vec::with_capacity(n_row_padding * KECCAK_WIT_SIZE * CAPACITY_RESERVED_FACTOR);
        wits.par_extend(
            (0..n_row_padding * KECCAK_WIT_SIZE)
                .into_par_iter()
                .map(|_| E::BaseField::ZERO),
        );

        // keccak instance full rounds (24 rounds + 8 round padding) as chunk size
        // we need to do assignment on respective 31 cyclic group index
        wits.par_chunks_mut(KECCAK_WIT_SIZE * ROUNDS.next_power_of_two())
            .enumerate()
            .take(num_instances)
            .for_each(|(instance_id, wits)| {
                let state_32_iter = instances[instance_id].iter().map(|&e| e as u64);
                let mut state64 = [[0u64; 5]; 5];
                zip_eq(iproduct!(0..5, 0..5), state_32_iter.tuples())
                    .map(|((x, y), (lo, hi))| {
                        state64[x][y] = lo | (hi << 32);
                    })
                    .count();

                let bh = BooleanHypercube::new(ROUNDS_CEIL_LOG2);
                let mut cyclic_group = bh.into_iter();

                #[allow(clippy::needless_range_loop)]
                for _round in 0..ROUNDS {
                    let round_index = cyclic_group.next().unwrap();
                    let mut wits_start_index = round_index as usize * KECCAK_WIT_SIZE;
                    let mut state8 = [[[0u64; 8]; 5]; 5];
                    for x in 0..5 {
                        for y in 0..5 {
                            state8[x][y] = conv64to8(state64[x][y]);
                        }
                    }

                    push_instance::<E, _>(
                        wits,
                        &mut wits_start_index,
                        state8.into_iter().flatten().flatten(),
                    );

                    let mut c_aux64 = [[0u64; 5]; 5];
                    let mut c_aux8 = [[[0u64; 8]; 5]; 5];

                    for i in 0..5 {
                        c_aux64[i][0] = state64[0][i];
                        c_aux8[i][0] = conv64to8(c_aux64[i][0]);
                        for j in 1..5 {
                            c_aux64[i][j] = state64[j][i] ^ c_aux64[i][j - 1];
                            c_aux8[i][j] = conv64to8(c_aux64[i][j]);
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
                    }

                    let mut theta_state64 = state64;
                    let mut theta_state8 = [[[0u64; 8]; 5]; 5];
                    let mut rotation_witness = vec![];

                    for x in 0..5 {
                        for y in 0..5 {
                            theta_state64[y][x] ^= d64[x];
                            theta_state8[y][x] = conv64to8(theta_state64[y][x]);

                            let (sizes, _) = rotation_split(ROTATION_CONSTANTS[y][x]);
                            let rep =
                                MaskRepresentation::new(vec![(64, theta_state64[y][x]).into()])
                                    .convert(sizes);
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
                        }
                    }

                    let mut chi_output64 = [[0u64; 5]; 5];
                    let mut chi_output8 = [[[0u64; 8]; 5]; 5];
                    for x in 0..5 {
                        for y in 0..5 {
                            chi_output64[y][x] = nonlinear64[y][x] ^ rhopi_output64[y][x];
                            chi_output8[y][x] = conv64to8(chi_output64[y][x]);
                        }
                    }

                    // Iota step
                    let mut iota_output64 = chi_output64;
                    let mut iota_output8 = [[[0u64; 8]; 5]; 5];
                    // TODO figure out how to deal with RC, since it's not a constant in rotation
                    iota_output64[0][0] ^= RC[0];

                    for x in 0..5 {
                        for y in 0..5 {
                            iota_output8[x][y] = conv64to8(iota_output64[x][y]);
                        }
                    }

                    let all_wits64 = chain!(
                        c_aux8.into_iter().flatten().flatten(),
                        c_temp.into_iter().flatten(),
                        crot8.into_iter().flatten(),
                        d8.into_iter().flatten(),
                        theta_state8.into_iter().flatten().flatten(),
                        rotation_witness.into_iter(),
                        rhopi_output8.into_iter().flatten().flatten(),
                        nonlinear8.into_iter().flatten().flatten(),
                        chi_output8[0][0].iter().copied(),
                        iota_output8.into_iter().flatten().flatten(),
                    );

                    push_instance::<E, _>(wits, &mut wits_start_index, all_wits64);

                    state64 = iota_output64;
                }
            });
        RowMajorMatrix::new_by_values(wits, KECCAK_WIT_SIZE, InstancePaddingStrategy::Default)
    }
}

pub fn setup_gkr_circuit<E: ExtensionField>() -> (KeccakLayout<E>, GKRCircuit<E>) {
    let params = KeccakParams {};
    let (layout, chip) = KeccakLayout::build(params);
    (layout, chip.gkr_circuit())
}

#[tracing::instrument(
    skip_all,
    name = "run_faster_keccakf",
    level = "trace",
    fields(profiling_1)
)]
pub fn run_faster_keccakf<E: ExtensionField>(
    (layout, gkr_circuit): (KeccakLayout<E>, GKRCircuit<E>),
    states: Vec<[u64; 25]>,
    verify: bool,
    test_outputs: bool,
) -> Result<GKRProof<E>, BackendError<E>> {
    let num_instances = states.len();
    let num_instances_rounds = num_instances * ROUNDS.next_power_of_two();
    let log2_num_instance_rounds = ceil_log2(num_instances_rounds);
    let num_threads = optimal_sumcheck_threads(log2_num_instance_rounds);
    let mut instances = Vec::with_capacity(num_instances);

    let span = entered_span!("instances", profiling_2 = true);
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
    exit_span!(span);

    let span = entered_span!("phase1_witness", profiling_2 = true);
    let phase1_witness = layout.phase1_witness_group(KeccakTrace { instances });
    exit_span!(span);

    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

    let span = entered_span!("gkr_witness", profiling_2 = true);
    let (gkr_witness, gkr_output) = layout.gkr_witness(&gkr_circuit, &phase1_witness, &[]);
    exit_span!(span);

    let span = entered_span!("out_eval", profiling_2 = true);
    let out_evals = {
        let mut point = Vec::with_capacity(log2_num_instance_rounds);
        point.extend(
            prover_transcript
                .sample_vec(log2_num_instance_rounds)
                .to_vec(),
        );

        if test_outputs {
            // Confront outputs with tiny_keccak::keccakf call
            let mut instance_outputs = vec![vec![]; num_instances];
            for base in gkr_witness
                .layers
                .last()
                .unwrap()
                .wits
                .iter()
                .take(KECCAK_OUTPUT_SIZE)
            {
                assert_eq!(
                    base.evaluations().len(),
                    (num_instances * ROUNDS.next_power_of_two()).next_power_of_two()
                );

                for (i, instance_output) in
                    instance_outputs.iter_mut().enumerate().take(num_instances)
                {
                    instance_output.push(base.get_base_field_vec()[i]);
                }
            }

            // TODO Need fix to check rotation mode
            // for i in 0..num_instances {
            //     let mut state = states[i];
            //     keccakf(&mut state);
            //     assert_eq!(
            //         state
            //             .to_vec()
            //             .iter()
            //             .flat_map(|e| vec![*e as u32, (e >> 32) as u32])
            //             .map(|e| Goldilocks::from_canonical_u64(e as u64))
            //             .collect_vec(),
            //         instance_outputs[i]
            //     );
            // }
        }

        let out_evals = gkr_output
            .0
            .wits
            .par_iter()
            .map(|wit| PointAndEval {
                point: point.clone(),
                eval: if wit.num_vars() == 0 {
                    wit.get_base_field_vec()[0].into()
                } else {
                    wit.evaluate(&point)
                },
            })
            .collect::<Vec<_>>();

        assert_eq!(out_evals.len(), KECCAK_OUT_EVAL_SIZE);

        out_evals
    };
    exit_span!(span);

    let span = entered_span!("create_proof", profiling_2 = true);
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove(
            num_threads,
            log2_num_instance_rounds,
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

            // This is to make prover/verifier match
            let mut point = Vec::with_capacity(log2_num_instance_rounds);
            point.extend(
                verifier_transcript
                    .sample_vec(log2_num_instance_rounds)
                    .to_vec(),
            );

            gkr_circuit
                .verify(
                    log2_num_instance_rounds,
                    gkr_proof.clone(),
                    &out_evals,
                    &[],
                    &mut verifier_transcript,
                )
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
    Ok(gkr_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ext::GoldilocksExt2;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_keccakf() {
        type E = GoldilocksExt2;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 8;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.gen()));
        }
        // TODO enable check
        let _ = run_faster_keccakf(setup_gkr_circuit::<E>(), states, true, true);
    }

    #[ignore]
    #[test]
    fn test_keccakf_nonpow2() {
        type E = GoldilocksExt2;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 5;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.gen()));
        }

        // TODO enable check
        let _ = run_faster_keccakf(setup_gkr_circuit::<E>(), states, true, true);
    }
}
