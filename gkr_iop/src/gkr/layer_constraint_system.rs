/// TODO: LayerConstrainSystem is deprecated
use std::{cmp::Ordering, collections::BTreeMap};

use crate::{
    evaluation::EvalExpression,
    gkr::layer::{Layer, LayerType, ROTATION_OPENING_COUNT},
    selector::SelectorType,
    tables::LookupTable,
};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use multilinear_extensions::{Expression, Fixed, ToExpr, WitnessId, rlc_chip_record};
use p3::field::FieldAlgebra;

#[derive(Clone, Debug, Default)]
pub struct RotationParams<E: ExtensionField> {
    pub rotation_eqs: Option<[Expression<E>; ROTATION_OPENING_COUNT]>,
    pub rotation_cyclic_group_log2: usize,
    pub rotation_cyclic_subgroup_size: usize,
}

#[allow(clippy::type_complexity)]
pub struct LayerConstraintSystem<E: ExtensionField> {
    num_witin: usize,
    num_structural_witin: usize,
    #[allow(unused)]
    num_fixed: usize,

    eq_zero: Option<Expression<E>>,
    // expressions include zero & non-zero expression, differentiate via evals
    // zero expr represented as Linear with all 0 value
    // TODO we should define an Zero enum for it
    pub expressions: Vec<Expression<E>>,
    pub expr_names: Vec<String>,
    pub evals: Vec<(SelectorType<E>, EvalExpression<E>)>,

    pub rotations: Vec<(Expression<E>, Expression<E>)>,
    pub rotation_params: Option<RotationParams<E>>,

    pub and_lookups: Vec<Expression<E>>,
    pub xor_lookups: Vec<Expression<E>>,
    pub range_lookups: Vec<Expression<E>>,

    pub ram_read: Vec<Expression<E>>,
    pub ram_write: Vec<Expression<E>>,

    // global challenge
    pub alpha: Expression<E>,
    pub beta: Expression<E>,
}

impl<E: ExtensionField> LayerConstraintSystem<E> {
    pub fn new(
        num_witin: usize,
        num_structural_witin: usize,
        num_fixed: usize,
        eq_zero: Option<Expression<E>>,
        alpha: Expression<E>,
        beta: Expression<E>,
    ) -> Self {
        LayerConstraintSystem {
            num_witin,
            num_structural_witin,
            num_fixed,
            eq_zero,
            rotations: vec![],
            rotation_params: None,
            expressions: vec![],
            expr_names: vec![],
            evals: vec![],
            and_lookups: vec![],
            xor_lookups: vec![],
            range_lookups: vec![],
            ram_read: vec![],
            ram_write: vec![],
            alpha,
            beta,
        }
    }

    pub fn add_zero_constraint(&mut self, expr: Expression<E>, name: String) {
        assert!(self.eq_zero.is_some());
        self.expressions.push(expr);
        self.evals.push((
            SelectorType::Whole(self.eq_zero.clone().unwrap()),
            EvalExpression::Zero,
        ));
        self.expr_names.push(name);
    }

    pub fn add_non_zero_constraint(
        &mut self,
        expr: Expression<E>,
        eval: (SelectorType<E>, EvalExpression<E>),
        name: String,
    ) {
        self.expressions.push(expr);
        self.evals.push(eval);
        self.expr_names.push(name);
    }

    pub fn lookup_and8(&mut self, a: Expression<E>, b: Expression<E>, c: Expression<E>) {
        let rlc_record = rlc_chip_record(
            vec![
                E::BaseField::from_canonical_u64(LookupTable::And as u64).expr(),
                a,
                b,
                c,
            ],
            self.alpha.clone(),
            self.beta.clone(),
        );
        self.and_lookups.push(rlc_record);
    }

    pub fn lookup_xor8(&mut self, a: Expression<E>, b: Expression<E>, c: Expression<E>) {
        let rlc_record = rlc_chip_record(
            vec![
                E::BaseField::from_canonical_u64(LookupTable::Xor as u64).expr(),
                a,
                b,
                c,
            ],
            self.alpha.clone(),
            self.beta.clone(),
        );
        self.xor_lookups.push(rlc_record);
    }

    /// Generates U16 lookups to prove that `value` fits on `size < 16` bits.
    /// In general it can be done by two U16 checks: one for `value` and one for
    /// `value << (16 - size)`.
    pub fn lookup_range(&mut self, value: Expression<E>, size: usize) {
        assert!(size <= 16);
        let rlc_record = rlc_chip_record(
            vec![
                // TODO: layer constrain system is deprecated
                E::BaseField::from_canonical_u64(LookupTable::Dynamic as u64).expr(),
                value.clone(),
            ],
            self.alpha.clone(),
            self.beta.clone(),
        );
        self.range_lookups.push(rlc_record);
        if size < 16 {
            let rlc_record = rlc_chip_record(
                vec![
                    E::BaseField::from_canonical_u64(LookupTable::Dynamic as u64).expr(),
                    value * E::BaseField::from_canonical_u64(1 << (16 - size)).expr(),
                ],
                self.alpha.clone(),
                self.beta.clone(),
            );
            self.range_lookups.push(rlc_record)
        }
    }

    pub fn constrain_eq(&mut self, lhs: Expression<E>, rhs: Expression<E>, name: String) {
        self.add_zero_constraint(lhs - rhs, name);
    }

    // Constrains that lhs and rhs encode the same value of SIZE bits
    // WARNING: Assumes that forall i, (lhs[i].1 < (2 ^ lhs[i].0))
    // This needs to be constrained separately
    pub fn constrain_reps_eq<const SIZE: usize>(
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
    pub fn constrain_left_rotation64(
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

    pub fn set_rotation_params(&mut self, params: RotationParams<E>) {
        assert!(self.rotation_params.is_none());
        self.rotation_params = Some(params);
    }

    pub fn rotate_and_assert_eq(&mut self, a: Expression<E>, b: Expression<E>) {
        self.rotations.push((a, b));
    }

    pub fn into_layer_with_lookup_eval_iter(
        mut self,
        layer_name: String,
        in_expr_evals: Vec<usize>,
        n_challenges: usize,
        ram_write_evals: impl ExactSizeIterator<Item = (SelectorType<E>, usize)>,
        ram_read_evals: impl ExactSizeIterator<Item = (SelectorType<E>, usize)>,
        lookup_evals: impl ExactSizeIterator<Item = (SelectorType<E>, usize)>,
    ) -> Layer<E> {
        // process ram read/write record
        assert_eq!(ram_write_evals.len(), self.ram_write.len(),);
        assert_eq!(ram_read_evals.len(), self.ram_read.len(),);

        for (idx, ram_expr, ram_eval) in izip!(
            0..,
            chain!(self.ram_write.clone(), self.ram_read.clone(),),
            ram_write_evals.chain(ram_read_evals)
        ) {
            self.add_non_zero_constraint(
                ram_expr - E::BaseField::ONE.expr(), // ONE is for padding
                (ram_eval.0, EvalExpression::Single(ram_eval.1)),
                format!("round 0th: {idx}th ram read/write operation"),
            );
        }

        // process lookup records
        assert_eq!(
            lookup_evals.len(),
            self.and_lookups.len() + self.xor_lookups.len() + self.range_lookups.len()
        );
        for (idx, lookup, lookup_eval) in izip!(
            0..,
            chain!(
                self.and_lookups.clone(),
                self.xor_lookups.clone(),
                self.range_lookups.clone()
            ),
            lookup_evals
        ) {
            self.add_non_zero_constraint(
                lookup,
                (lookup_eval.0, EvalExpression::Single(lookup_eval.1)),
                format!("round 0th: {idx}th lookup felt"),
            );
        }

        self.into_layer(layer_name, in_expr_evals, n_challenges)
    }

    /// n_challenges: num of challenges dedicated to this layer
    pub fn into_layer(
        self,
        layer_name: String,
        in_eval_expr: Vec<usize>,
        n_challenges: usize,
    ) -> Layer<E> {
        let witin_offset = 0 as WitnessId;
        let structural_witin_offset = witin_offset + (self.num_witin as WitnessId);
        let fixed_offset = structural_witin_offset + (self.num_structural_witin as WitnessId);

        // Sort expressions, expr_names, and evals according to eval.0 and classify evals.
        let Self {
            expr_names,
            mut expressions,
            evals,
            rotation_params,
            rotations,
            ..
        } = self;

        let mut is_layer_linear =
            expressions
                .iter_mut()
                .fold(rotations.is_empty(), |is_linear_so_far, t| {
                    // replace `Fixed` and `StructuralWitIn` with `WitIn`, keep other unchanged
                    *t = t.transform_all(
                        &|Fixed(fixed_id)| {
                            Expression::WitIn(fixed_offset + (*fixed_id as WitnessId))
                        },
                        &|id| Expression::WitIn(id),
                        &|structural_wit_id, _| {
                            Expression::WitIn(structural_witin_offset + structural_wit_id)
                        },
                        &|i| Expression::InstanceScalar(i),
                        &|i| Expression::Instance(i),
                        &|c| Expression::Constant(c),
                        &|cid, pow, s, o| Expression::Challenge(cid, pow, s, o),
                    );
                    is_linear_so_far && t.is_linear()
                });

        // process evaluation group by eq expression
        let mut eq_map = BTreeMap::new();
        izip!(
            evals.into_iter(),
            expr_names.into_iter(),
            expressions.into_iter()
        )
        .for_each(|((sel_type, eval), name, expr)| {
            let (eval_group, names, exprs) =
                eq_map.entry(sel_type).or_insert((vec![], vec![], vec![]));
            eval_group.push(eval);
            names.push(name);
            exprs.push(expr);
        });
        let mut expr_evals = vec![];
        let mut expr_names = vec![];
        let mut expressions = vec![];
        eq_map
            .into_iter()
            .for_each(|(sel_type, (evals, names, exprs))| {
                expr_evals.push((sel_type, evals));
                expr_names.extend(names);
                expressions.extend(exprs);
            });

        is_layer_linear = is_layer_linear && expr_evals.len() == 1;

        let layer_type = if is_layer_linear {
            LayerType::Linear
        } else {
            LayerType::Zerocheck
        };

        if rotations.is_empty() {
            Layer::new(
                layer_name,
                layer_type,
                self.num_witin,
                0,
                self.num_fixed,
                0,
                expressions,
                n_challenges,
                in_eval_expr,
                expr_evals,
                ((None, vec![]), 0, 0),
                expr_names,
                vec![],
                vec![],
            )
        } else {
            let Some(RotationParams {
                rotation_eqs,
                rotation_cyclic_group_log2,
                rotation_cyclic_subgroup_size,
            }) = rotation_params
            else {
                panic!("rotation params not set");
            };
            Layer::new(
                layer_name,
                layer_type,
                self.num_witin,
                0,
                self.num_fixed,
                0,
                expressions,
                n_challenges,
                in_eval_expr,
                expr_evals,
                (
                    (rotation_eqs, rotations),
                    rotation_cyclic_group_log2,
                    rotation_cyclic_subgroup_size,
                ),
                expr_names,
                vec![],
                vec![],
            )
        }
    }
}

pub fn expansion_expr<E: ExtensionField, const SIZE: usize>(
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
pub fn rotation_split(delta: usize) -> (Vec<usize>, usize) {
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
