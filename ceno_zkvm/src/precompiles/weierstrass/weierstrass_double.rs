// The crate weierstrass double circuit is modified from succinctlabs/sp1 under MIT license

// The MIT License (MIT)

// Copyright (c) 2023 Succinct Labs

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use std::{array, fmt::Debug, sync::Arc};

use ceno_emul::{ByteAddr, MemOp, StepRecord};
use core::{borrow::BorrowMut, mem::size_of};
use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::Unsigned};
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    cpu::{CpuBackend, CpuProver},
    default_out_eval_groups,
    error::{BackendError, CircuitBuilderError},
    gkr::{GKRCircuit, GKRProof, GKRProverOutput, layer::Layer, mock::MockProver},
    selector::{SelectorContext, SelectorType},
};
use itertools::{Itertools, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, ToExpr, WitIn,
    util::{ceil_log2, max_usable_threads},
};
use num::BigUint;

use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    prelude::{IntoParallelRefIterator, ParallelSlice},
};
use sp1_curves::{
    AffinePoint, CurveType, EllipticCurve,
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    polynomial::Polynomial,
    weierstrass::WeierstrassParameters,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::MemoryExpr,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::{FieldOperation, field_op::FieldOpCols, util_expr::poly_mul_expr},
    instructions::riscv::insn_base::{StateInOut, WriteMEM},
    precompiles::{
        SelectorTypeLayout,
        utils::merge_u8_slice_to_u16_limbs_pairs_and_extend,
        weierstrass::{
            EllipticCurveDoubleInstance, compact_field_relation::CompactFieldRelationCols,
        },
    },
    scheme::utils::gkr_witness,
    structs::PointAndEval,
    witness::LkMultiplicity,
};
use p3::field::PrimeCharacteristicRing;

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct GenericWeierstrassDoubleAssignWitCols<WitT, P: FieldParameters + NumLimbs> {
    pub p_x: Limbs<WitT, P::Limbs>,
    pub p_y: Limbs<WitT, P::Limbs>,
    pub(crate) slope_denominator: FieldOpCols<WitT, P>,
    pub(crate) slope_numerator: FieldOpCols<WitT, P>,
    pub(crate) slope: FieldOpCols<WitT, P>,
    pub(crate) p_x_squared: FieldOpCols<WitT, P>,
    pub(crate) p_x_squared_times_3: FieldOpCols<WitT, P>,
    pub(crate) slope_squared: FieldOpCols<WitT, P>,
    pub(crate) p_x_plus_p_x: FieldOpCols<WitT, P>,
    pub(crate) x3_ins: FieldOpCols<WitT, P>,
    pub(crate) p_x_minus_x: FieldOpCols<WitT, P>,
    pub(crate) y3_ins: FieldOpCols<WitT, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<WitT, P>,
}

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct CompactSecp256k1DoubleAssignWitCols<WitT, P: FieldParameters + NumLimbs> {
    pub p_x: Limbs<WitT, P::Limbs>,
    pub p_y: Limbs<WitT, P::Limbs>,
    pub(crate) slope: Limbs<WitT, P::Limbs>,
    pub(crate) x3: Limbs<WitT, P::Limbs>,
    pub(crate) y3: Limbs<WitT, P::Limbs>,
    pub(crate) slope_relation: CompactFieldRelationCols<WitT, P>,
    pub(crate) x_relation: CompactFieldRelationCols<WitT, P>,
    pub(crate) y_relation: CompactFieldRelationCols<WitT, P>,
}

/// Weierstrass double is implemented by a single layer.
#[derive(Clone, Debug)]
pub enum WeierstrassDoubleAssignLayer<WitT, P: FieldParameters + NumWords> {
    Generic(GenericWeierstrassDoubleAssignWitCols<WitT, P>),
    CompactSecp256k1(CompactSecp256k1DoubleAssignWitCols<WitT, P>),
}

#[derive(Clone, Debug)]
pub struct WeierstrassDoubleAssignLayout<E: ExtensionField, EC: EllipticCurve> {
    pub layer_exprs: WeierstrassDoubleAssignLayer<WitIn, EC::BaseField>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs: GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsCurvePoint>,
    pub output32_exprs: GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsCurvePoint>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters>
    WeierstrassDoubleAssignLayout<E, EC>
{
    fn assert_compact_secp256k1_limb_bytes(
        blu_events: &mut LkMultiplicity,
        cols: &CompactSecp256k1DoubleAssignWitCols<E::BaseField, EC::BaseField>,
    ) {
        blu_events.assert_byte_fields(&cols.p_x.0);
        blu_events.assert_byte_fields(&cols.p_y.0);
        blu_events.assert_byte_fields(&cols.slope.0);
        blu_events.assert_byte_fields(&cols.x3.0);
        blu_events.assert_byte_fields(&cols.y3.0);
    }

    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => WeierstrassDoubleAssignLayer::CompactSecp256k1(
                CompactSecp256k1DoubleAssignWitCols {
                    p_x: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_x"))),
                    p_y: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_y"))),
                    slope: Limbs(GenericArray::generate(|_| cb.create_witin(|| "slope"))),
                    x3: Limbs(GenericArray::generate(|_| cb.create_witin(|| "x3"))),
                    y3: Limbs(GenericArray::generate(|_| cb.create_witin(|| "y3"))),
                    slope_relation: CompactFieldRelationCols::create(cb, || "slope_relation"),
                    x_relation: CompactFieldRelationCols::create(cb, || "x_relation"),
                    y_relation: CompactFieldRelationCols::create(cb, || "y_relation"),
                },
            ),
            _ => WeierstrassDoubleAssignLayer::Generic(GenericWeierstrassDoubleAssignWitCols {
                p_x: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_x"))),
                p_y: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_y"))),
                slope_denominator: FieldOpCols::create(cb, || "slope_denominator"),
                slope_numerator: FieldOpCols::create(cb, || "slope_numerator"),
                slope: FieldOpCols::create(cb, || "slope"),
                p_x_squared: FieldOpCols::create(cb, || "p_x_squared"),
                p_x_squared_times_3: FieldOpCols::create(cb, || "p_x_squared_times_3"),
                slope_squared: FieldOpCols::create(cb, || "slope_squared"),
                p_x_plus_p_x: FieldOpCols::create(cb, || "p_x_plus_p_x"),
                x3_ins: FieldOpCols::create(cb, || "x3_ins"),
                p_x_minus_x: FieldOpCols::create(cb, || "p_x_minus_x"),
                y3_ins: FieldOpCols::create(cb, || "y3_ins"),
                slope_times_p_x_minus_x: FieldOpCols::create(cb, || "slope_times_p_x_minus_x"),
            }),
        };

        let eq = cb.create_placeholder_structural_witin(|| "weierstrass_double_eq");
        let sel = SelectorType::Prefix(eq.expr());
        let selector_type_layout = SelectorTypeLayout {
            sel_first: None,
            sel_last: None,
            sel_all: sel.clone(),
        };

        let input32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsCurvePoint,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));
        let output32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsCurvePoint,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: wits,
            selector_type_layout,
            input32_exprs,
            output32_exprs,
            n_fixed: 0,
            n_committed: 0,
            n_structural_witin: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_generic_field_ops(
        blu_events: &mut LkMultiplicity,
        cols: &mut GenericWeierstrassDoubleAssignWitCols<E::BaseField, EC::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a = EC::a_int();
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared
                        .populate(blu_events, &p_x, &p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                &BigUint::from(2u32),
                &p_y,
                FieldOperation::Mul,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate(blu_events, &p_x, &p_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_p_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x = cols
                .p_x_minus_x
                .populate(blu_events, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
        }
    }

    fn populate_compact_secp256k1_field_ops(
        blu_events: &mut LkMultiplicity,
        cols: &mut CompactSecp256k1DoubleAssignWitCols<E::BaseField, EC::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        let modulus = EC::BaseField::modulus();
        let two = BigUint::from(2u32);
        let three = BigUint::from(3u32);
        let slope_denominator = (&two * &p_y) % &modulus;
        let slope_numerator = (&three * &p_x * &p_x) % &modulus;
        let slope = (&slope_numerator
            * slope_denominator.modpow(&(modulus.clone() - 2u32), &modulus))
            % &modulus;
        let x3 = (&slope * &slope + &modulus - (&two * &p_x % &modulus)) % &modulus;
        let y3 = (&slope * ((&p_x + &modulus - &x3) % &modulus) + &modulus - &p_y) % &modulus;

        cols.slope = EC::BaseField::to_limbs_field(&slope);
        cols.x3 = EC::BaseField::to_limbs_field(&x3);
        cols.y3 = EC::BaseField::to_limbs_field(&y3);

        let p_slope: Polynomial<E::BaseField> = cols.slope.clone().into();
        let p_x_poly: Polynomial<E::BaseField> = EC::BaseField::to_limbs_field(&p_x).into();
        let p_y_poly: Polynomial<E::BaseField> = EC::BaseField::to_limbs_field(&p_y).into();
        let p_x3: Polynomial<E::BaseField> = cols.x3.clone().into();
        let p_y3: Polynomial<E::BaseField> = cols.y3.clone().into();

        let p_two = Polynomial::from_coefficients(&[E::BaseField::from_u8(2)]);
        let p_three = Polynomial::from_coefficients(&[E::BaseField::from_u8(3)]);
        let p_modulus = Polynomial::from_iter(EC::BaseField::modulus_field_iter::<E::BaseField>());

        let slope_lhs = &p_slope * &(&p_two * &p_y_poly);
        let slope_rhs = &p_three * &(&p_x_poly * &p_x_poly);
        Self::populate_compact_relation(
            &mut cols.slope_relation,
            blu_events,
            &slope_lhs,
            &slope_rhs,
            &(&three * &modulus),
            &(&slope * &two * &p_y),
            &(&three * &p_x * &p_x),
        );

        let x_lhs = &p_x3 + &(&p_two * &p_x_poly);
        let x_rhs = &p_slope * &p_slope;
        Self::populate_compact_relation(
            &mut cols.x_relation,
            blu_events,
            &x_lhs,
            &x_rhs,
            &modulus,
            &(&x3 + &two * &p_x),
            &(&slope * &slope),
        );

        let y_lhs = &p_y3 + &p_y_poly;
        let y_rhs = &p_slope * &(&p_x_poly + &p_modulus - &p_x3);
        Self::populate_compact_relation(
            &mut cols.y_relation,
            blu_events,
            &y_lhs,
            &y_rhs,
            &(&two * &modulus),
            &(&y3 + &p_y),
            &(&slope * (&p_x + &modulus - &x3)),
        );
    }

    fn populate_compact_relation(
        relation: &mut CompactFieldRelationCols<E::BaseField, EC::BaseField>,
        blu_events: &mut LkMultiplicity,
        lhs: &Polynomial<E::BaseField>,
        rhs: &Polynomial<E::BaseField>,
        positive_modulus_offset: &BigUint,
        lhs_eval: &BigUint,
        rhs_eval: &BigUint,
    ) {
        let modulus = EC::BaseField::modulus();
        let numerator = lhs_eval + positive_modulus_offset * &modulus - rhs_eval;
        debug_assert_eq!(&numerator % &modulus, BigUint::from(0u32));
        let quotient = numerator / &modulus;
        relation.populate(blu_events, lhs, rhs, positive_modulus_offset, &quotient);
    }
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters> ProtocolBuilder<E>
    for WeierstrassDoubleAssignLayout<E, EC>
{
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = WeierstrassDoubleAssignLayout::new(cb);
        let (p_x, p_y, x3, y3) = match &layout.layer_exprs {
            WeierstrassDoubleAssignLayer::Generic(wits) => {
                // `a` in the Weierstrass form: y^2 = x^3 + a * x + b.
                let a = EC::BaseField::to_limbs_expr::<E>(&EC::a_int());

                // slope = slope_numerator / slope_denominator.
                let slope = {
                    // slope_numerator = a + (p.x * p.x) * 3.
                    {
                        wits.p_x_squared
                            .eval(cb, &wits.p_x, &wits.p_x, FieldOperation::Mul)?;

                        wits.p_x_squared_times_3.eval(
                            cb,
                            &wits.p_x_squared.result,
                            &EC::BaseField::to_limbs_expr::<E>(&BigUint::from(3u32)),
                            FieldOperation::Mul,
                        )?;

                        wits.slope_numerator.eval(
                            cb,
                            &a,
                            &wits.p_x_squared_times_3.result,
                            FieldOperation::Add,
                        )?;
                    };

                    // slope_denominator = 2 * y.
                    wits.slope_denominator.eval(
                        cb,
                        &EC::BaseField::to_limbs_expr::<E>(&BigUint::from(2u32)),
                        &wits.p_y,
                        FieldOperation::Mul,
                    )?;

                    wits.slope.eval(
                        cb,
                        &wits.slope_numerator.result,
                        &wits.slope_denominator.result,
                        FieldOperation::Div,
                    )?;

                    &wits.slope.result
                };

                // x = slope * slope - (p.x + p.x).
                let x = {
                    wits.slope_squared
                        .eval(cb, slope, slope, FieldOperation::Mul)?;
                    wits.p_x_plus_p_x
                        .eval(cb, &wits.p_x, &wits.p_x, FieldOperation::Add)?;
                    wits.x3_ins.eval(
                        cb,
                        &wits.slope_squared.result,
                        &wits.p_x_plus_p_x.result,
                        FieldOperation::Sub,
                    )?;
                    &wits.x3_ins.result
                };

                // y = slope * (p.x - x) - p.y.
                {
                    wits.p_x_minus_x
                        .eval(cb, &wits.p_x, x, FieldOperation::Sub)?;
                    wits.slope_times_p_x_minus_x.eval(
                        cb,
                        slope,
                        &wits.p_x_minus_x.result,
                        FieldOperation::Mul,
                    )?;
                    wits.y3_ins.eval(
                        cb,
                        &wits.slope_times_p_x_minus_x.result,
                        &wits.p_y,
                        FieldOperation::Sub,
                    )?;
                }
                (
                    &wits.p_x,
                    &wits.p_y,
                    &wits.x3_ins.result,
                    &wits.y3_ins.result,
                )
            }
            WeierstrassDoubleAssignLayer::CompactSecp256k1(wits) => {
                cb.assert_bytes(|| "compact secp256k1 double p_x", &wits.p_x.0)?;
                cb.assert_bytes(|| "compact secp256k1 double p_y", &wits.p_y.0)?;
                cb.assert_bytes(|| "compact secp256k1 double slope", &wits.slope.0)?;
                cb.assert_bytes(|| "compact secp256k1 double x3", &wits.x3.0)?;
                cb.assert_bytes(|| "compact secp256k1 double y3", &wits.y3.0)?;

                let p_slope: Polynomial<Expression<E>> = wits.slope.clone().into();
                let p_x: Polynomial<Expression<E>> = wits.p_x.clone().into();
                let p_y: Polynomial<Expression<E>> = wits.p_y.clone().into();
                let p_x3: Polynomial<Expression<E>> = wits.x3.clone().into();
                let p_y3: Polynomial<Expression<E>> = wits.y3.clone().into();
                let p_two = Polynomial::new(vec![E::BaseField::from_u8(2).expr()]);
                let p_three = Polynomial::new(vec![E::BaseField::from_u8(3).expr()]);
                let p_modulus = Polynomial::from_iter(
                    EC::BaseField::modulus_field_iter::<E::BaseField>().map(|x| x.expr()),
                );
                let modulus = EC::BaseField::modulus();

                let slope_lhs = poly_mul_expr(&p_slope, &poly_mul_expr(&p_two, &p_y));
                let slope_rhs = poly_mul_expr(&p_three, &poly_mul_expr(&p_x, &p_x));
                wits.slope_relation.eval(
                    cb,
                    &slope_lhs,
                    &slope_rhs,
                    &(BigUint::from(3u32) * &modulus),
                )?;

                let x_lhs = &p_x3 + &poly_mul_expr(&p_two, &p_x);
                let x_rhs = poly_mul_expr(&p_slope, &p_slope);
                wits.x_relation.eval(cb, &x_lhs, &x_rhs, &modulus)?;

                let y_lhs = &p_y3 + &p_y;
                let y_rhs = poly_mul_expr(&p_slope, &(&p_x + &p_modulus - &p_x3));
                wits.y_relation
                    .eval(cb, &y_lhs, &y_rhs, &(BigUint::from(2u32) * &modulus))?;

                (&wits.p_x, &wits.p_y, &wits.x3, &wits.y3)
            }
        };

        // Constraint output32 from wits.x3_ins || wits.y3_ins by converting 8-bit limbs to 2x16-bit felts
        let mut output32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE);
        for limbs in [x3, y3] {
            merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&limbs.0, &mut output32);
        }
        let output32 = output32.try_into().unwrap();

        let mut p_input32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE);
        for limbs in [p_x, p_y] {
            merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&limbs.0, &mut p_input32);
        }
        let p_input32 = p_input32.try_into().unwrap();

        // set input32/output32 expr
        layout.input32_exprs = p_input32;
        layout.output32_exprs = output32;

        Ok(layout)
    }

    fn finalize(&mut self, name: String, cb: &mut CircuitBuilder<E>) -> Chip<E> {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_structural_witin = cb.cs.num_structural_witin as usize;

        // register selector to legacy constrain system
        cb.cs.r_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.w_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.lk_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.zero_selector = Some(self.selector_type_layout.sel_all.clone());

        let out_evals = default_out_eval_groups(cb);
        let mut chip = Chip::new_from_cb(cb);
        let layer = Layer::from_circuit_builder(cb, name, out_evals);
        chip.add_layer(layer);
        chip
    }

    fn n_committed(&self) -> usize {
        todo!()
    }

    fn n_fixed(&self) -> usize {
        todo!()
    }

    fn n_evaluations(&self) -> usize {
        todo!()
    }

    fn n_layers(&self) -> usize {
        todo!()
    }
}

#[derive(Clone, Default)]
pub struct WeierstrassDoubleAssignTrace<P: NumWords> {
    pub instances: Vec<EllipticCurveDoubleInstance<P>>,
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters> ProtocolWitnessGenerator<E>
    for WeierstrassDoubleAssignLayout<E, EC>
{
    type Trace = WeierstrassDoubleAssignTrace<EC::BaseField>;

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        let num_instances = wits[0].num_instances();
        let nthreads = max_usable_threads();
        let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);
        let first_wit_id = self.first_wit_id();
        let num_wit_cols = self.num_arithmetic_wit_cols();

        let [wits, structural_wits] = wits;
        let raw_witin_iter = wits.par_batch_iter_mut(num_instance_per_batch);
        let raw_structural_wits_iter = structural_wits.par_batch_iter_mut(num_instance_per_batch);
        raw_witin_iter
            .zip_eq(raw_structural_wits_iter)
            .zip_eq(phase1.instances.par_chunks(num_instance_per_batch))
            .for_each(|((rows, eqs), phase1_instances)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                rows.chunks_mut(self.n_committed)
                    .zip_eq(eqs.chunks_mut(self.n_structural_witin))
                    .zip_eq(phase1_instances)
                    .for_each(|((row, eqs), phase1_instance)| {
                        self.populate_row_from_slice(
                            phase1_instance,
                            &mut row[first_wit_id..][..num_wit_cols],
                            &mut lk_multiplicity,
                        );
                        for x in eqs.iter_mut() {
                            *x = E::BaseField::ONE;
                        }
                    });
            });
    }
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters>
    WeierstrassDoubleAssignLayout<E, EC>
{
    pub fn populate_row(
        event: &EllipticCurveDoubleInstance<EC::BaseField>,
        cols: &mut GenericWeierstrassDoubleAssignWitCols<E::BaseField, EC::BaseField>,
        new_byte_lookup_events: &mut LkMultiplicity,
    ) {
        // Decode affine points.
        let p = &event.p;
        let p = AffinePoint::<EC>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);

        // Populate basic columns.
        cols.p_x = EC::BaseField::to_limbs_field(&p_x);
        cols.p_y = EC::BaseField::to_limbs_field(&p_y);

        Self::populate_generic_field_ops(new_byte_lookup_events, cols, p_x, p_y);
    }

    fn populate_compact_secp256k1_row(
        event: &EllipticCurveDoubleInstance<EC::BaseField>,
        cols: &mut CompactSecp256k1DoubleAssignWitCols<E::BaseField, EC::BaseField>,
        new_byte_lookup_events: &mut LkMultiplicity,
    ) {
        let p = &event.p;
        let p = AffinePoint::<EC>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);

        cols.p_x = EC::BaseField::to_limbs_field(&p_x);
        cols.p_y = EC::BaseField::to_limbs_field(&p_y);

        Self::populate_compact_secp256k1_field_ops(new_byte_lookup_events, cols, p_x, p_y);
        Self::assert_compact_secp256k1_limb_bytes(new_byte_lookup_events, cols);
    }

    fn populate_row_from_slice(
        &self,
        event: &EllipticCurveDoubleInstance<EC::BaseField>,
        row: &mut [E::BaseField],
        new_byte_lookup_events: &mut LkMultiplicity,
    ) {
        match &self.layer_exprs {
            WeierstrassDoubleAssignLayer::Generic(_) => {
                let cols: &mut GenericWeierstrassDoubleAssignWitCols<E::BaseField, EC::BaseField> =
                    row.borrow_mut();
                Self::populate_row(event, cols, new_byte_lookup_events);
            }
            WeierstrassDoubleAssignLayer::CompactSecp256k1(_) => {
                let cols: &mut CompactSecp256k1DoubleAssignWitCols<E::BaseField, EC::BaseField> =
                    row.borrow_mut();
                Self::populate_compact_secp256k1_row(event, cols, new_byte_lookup_events);
            }
        }
    }

    fn first_wit_id(&self) -> usize {
        match &self.layer_exprs {
            WeierstrassDoubleAssignLayer::Generic(wits) => wits.p_x.0[0].id as usize,
            WeierstrassDoubleAssignLayer::CompactSecp256k1(wits) => wits.p_x.0[0].id as usize,
        }
    }

    fn num_arithmetic_wit_cols(&self) -> usize {
        match &self.layer_exprs {
            WeierstrassDoubleAssignLayer::Generic(_) => {
                size_of::<GenericWeierstrassDoubleAssignWitCols<u8, EC::BaseField>>()
            }
            WeierstrassDoubleAssignLayer::CompactSecp256k1(_) => {
                size_of::<CompactSecp256k1DoubleAssignWitCols<u8, EC::BaseField>>()
            }
        }
    }

    fn output_limb_start_ids(&self) -> (usize, usize) {
        match &self.layer_exprs {
            WeierstrassDoubleAssignLayer::Generic(wits) => (
                wits.x3_ins.result[0].id as usize,
                wits.y3_ins.result[0].id as usize,
            ),
            WeierstrassDoubleAssignLayer::CompactSecp256k1(wits) => {
                (wits.x3[0].id as usize, wits.y3[0].id as usize)
            }
        }
    }
}

/// this is for testing purpose
pub struct TestWeierstrassDoubleLayout<E: ExtensionField, EC: EllipticCurve> {
    layout: WeierstrassDoubleAssignLayout<E, EC>,
    mem_rw: Vec<WriteMEM>,
    vm_state: StateInOut<E>,
    _point_ptr_0: WitIn,
}

#[allow(clippy::type_complexity)]
pub fn setup_gkr_circuit<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters>()
-> Result<(TestWeierstrassDoubleLayout<E, EC>, GKRCircuit<E>, u16, u16), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "weierstrass_double");
    let mut cb = CircuitBuilder::<E>::new(&mut cs);

    // constrain vmstate
    let vm_state = StateInOut::construct_circuit(&mut cb, false)?;

    let point_ptr_0 = cb.create_witin(|| "state_ptr_0");

    let mut layout = WeierstrassDoubleAssignLayout::build_layer_logic(&mut cb, ())?;

    // Write the result to the same address of the first input point.
    let mem_rw = izip!(&layout.input32_exprs, &layout.output32_exprs)
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := state_ptr_0 + i
                point_ptr_0.expr() + E::BaseField::from_u32(i as u32).expr(),
                val_before.clone(),
                val_after.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    let chip = layout.finalize("weierstrass_double".to_string(), &mut cb);

    Ok((
        TestWeierstrassDoubleLayout {
            layout,
            vm_state,
            _point_ptr_0: point_ptr_0,
            mem_rw,
        },
        chip.gkr_circuit(),
        cs.num_witin,
        cs.num_structural_witin,
    ))
}

#[tracing::instrument(
    skip_all,
    name = "run_weierstrass_double",
    level = "trace",
    fields(profiling_1)
)]
pub fn run_weierstrass_double<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    EC: EllipticCurve + WeierstrassParameters,
>(
    (layout, gkr_circuit, num_witin, num_structural_witin): (
        TestWeierstrassDoubleLayout<E, EC>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    points: Vec<GenericArray<u32, <EC::BaseField as NumWords>::WordsCurvePoint>>,
    verify: bool,
    test_outputs: bool,
) -> Result<GKRProof<E>, BackendError> {
    let mut shard_ctx = ShardContext::default();
    let num_instances = points.len();
    let log2_num_instance = ceil_log2(num_instances);
    let num_threads = optimal_sumcheck_threads(log2_num_instance);
    let mut instances: Vec<EllipticCurveDoubleInstance<EC::BaseField>> =
        Vec::with_capacity(num_instances);

    let span = entered_span!("instances", profiling_2 = true);
    for p in &points {
        let instance = EllipticCurveDoubleInstance { p: p.clone() };
        instances.push(instance);
    }
    exit_span!(span);

    let span = entered_span!("phase1_witness", profiling_2 = true);
    let nthreads = max_usable_threads();
    let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);

    let mut lk_multiplicity = LkMultiplicity::default();
    let mut phase1_witness = RowMajorMatrix::<E::BaseField>::new(
        instances.len(),
        num_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let mut structural_witness = RowMajorMatrix::<E::BaseField>::new(
        instances.len(),
        num_structural_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let raw_witin_iter = phase1_witness.par_batch_iter_mut(num_instance_per_batch);
    let shard_ctx_vec = shard_ctx.get_forked();
    raw_witin_iter
        .zip_eq(instances.par_chunks(num_instance_per_batch))
        .zip(shard_ctx_vec)
        .for_each(|((instances, steps), mut shard_ctx)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin as usize)
                .zip_eq(steps)
                .for_each(|(instance, _step)| {
                    layout
                        .vm_state
                        .assign_instance(
                            instance,
                            &shard_ctx,
                            &StepRecord::new_ecall_any(10, ByteAddr::from(0)),
                        )
                        .expect("assign vm_state error");
                    layout.mem_rw.iter().for_each(|mem_config| {
                        mem_config
                            .assign_op(
                                instance,
                                &mut shard_ctx,
                                &mut lk_multiplicity,
                                10,
                                &MemOp {
                                    previous_cycle: 0,
                                    addr: ByteAddr::from(0).waddr(),
                                    value: Default::default(),
                                },
                            )
                            .expect("assign error");
                    });
                })
        });

    layout.layout.phase1_witness_group(
        WeierstrassDoubleAssignTrace { instances },
        [&mut phase1_witness, &mut structural_witness],
        &mut lk_multiplicity,
    );

    exit_span!(span);

    if test_outputs {
        // test got output == expected output
        // n_points x (result_x_words || result_y_words) in little endian
        let expected_outputs = points
            .iter()
            .map(|a| {
                let a = AffinePoint::<EC>::from_words_le(a);
                let c = EC::ec_double(&a);
                c.to_words_le()
                    .into_iter()
                    .flat_map(|word| {
                        [
                            word & 0xFF,
                            (word >> 8) & 0xFF,
                            (word >> 16) & 0xFF,
                            (word >> 24) & 0xFF,
                        ]
                    })
                    .collect_vec()
            })
            .collect_vec();

        let (x_output_index_start, y_output_index_start) = layout.layout.output_limb_start_ids();
        let got_outputs = phase1_witness
            .iter_rows()
            .take(num_instances)
            .map(|cols| {
                [
                    cols[x_output_index_start..][..<EC::BaseField as NumLimbs>::Limbs::USIZE]
                        .iter()
                        .map(|x| x.to_canonical_u64() as u32)
                        .collect_vec(),
                    cols[y_output_index_start..][..<EC::BaseField as NumLimbs>::Limbs::USIZE]
                        .iter()
                        .map(|y| y.to_canonical_u64() as u32)
                        .collect_vec(),
                ]
                .concat()
            })
            .collect_vec();
        assert_eq!(expected_outputs, got_outputs);
    }

    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");
    let challenges = [
        prover_transcript.read_challenge().elements,
        prover_transcript.read_challenge().elements,
    ];

    let span = entered_span!("gkr_witness", profiling_2 = true);
    let phase1_witness_group = phase1_witness
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    let structural_witness = structural_witness
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    let fixed = layout
        .layout
        .fixed_witness_group()
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    #[allow(clippy::type_complexity)]
    let (gkr_witness, gkr_output) = gkr_witness::<E, PCS, CpuBackend<E, PCS>, CpuProver<_>>(
        &gkr_circuit,
        &phase1_witness_group,
        &structural_witness,
        &fixed,
        &[],
        &[],
        &challenges,
        None,
    );
    exit_span!(span);

    let span = entered_span!("out_eval", profiling_2 = true);
    let out_evals = {
        let mut point = Vec::with_capacity(log2_num_instance);
        point.extend(prover_transcript.sample_vec(log2_num_instance).to_vec());

        let out_evals = gkr_output
            .0
            .par_iter()
            .map(|wit| {
                let point = point[point.len() - wit.num_vars()..point.len()].to_vec();
                PointAndEval {
                    point: point.clone(),
                    eval: wit.evaluate(&point),
                }
            })
            .collect::<Vec<_>>();

        if out_evals.is_empty() {
            vec![PointAndEval {
                point: point[point.len() - log2_num_instance..point.len()].to_vec(),
                eval: E::ZERO,
            }]
        } else {
            out_evals
        }
    };
    exit_span!(span);

    if cfg!(debug_assertions) {
        // mock prover
        let out_wits = gkr_output.0.0.clone();
        MockProver::check(&gkr_circuit, &gkr_witness, out_wits, challenges.to_vec())
            .expect("mock prover failed");
    }

    let span = entered_span!("create_proof", profiling_2 = true);
    let selector_ctxs = vec![SelectorContext::new(0, num_instances, log2_num_instance); 1];
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instance,
            gkr_witness,
            &out_evals,
            &[],
            &challenges,
            &mut prover_transcript,
            &selector_ctxs,
        )
        .expect("Failed to prove phase");
    exit_span!(span);

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");
            let challenges = [
                verifier_transcript.read_challenge().elements,
                verifier_transcript.read_challenge().elements,
            ];

            // This is to make prover/verifier match
            let mut point = Vec::with_capacity(log2_num_instance);
            point.extend(verifier_transcript.sample_vec(log2_num_instance).to_vec());

            gkr_circuit
                .verify(
                    log2_num_instance,
                    gkr_proof.clone(),
                    &out_evals,
                    &[],
                    &challenges,
                    &mut verifier_transcript,
                    &selector_ctxs,
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
    use ff_ext::BabyBearExt4;
    use mpcs::BasefoldDefault;
    use sp1_curves::weierstrass::{
        SwCurve, WeierstrassParameters, bls12_381::Bls12381, bn254::Bn254, secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    };

    use crate::precompiles::weierstrass::test_utils::random_points;

    fn test_weierstrass_double_helper<WP: WeierstrassParameters>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let points = random_points::<WP>(8);

        let _ = run_weierstrass_double::<E, Pcs, SwCurve<WP>>(
            setup_gkr_circuit::<E, SwCurve<WP>>().expect("setup gkr circuit failed"),
            points,
            true,
            true,
        )
        .inspect_err(|err| {
            eprintln!("{:?}", err);
        })
        .expect("run_weierstrass_double failed");
    }

    #[test]
    fn test_weierstrass_double_bn254() {
        test_weierstrass_double_helper::<Bn254>();
    }

    #[test]
    fn test_weierstrass_double_bls12381() {
        test_weierstrass_double_helper::<Bls12381>();
    }

    #[test]
    fn test_weierstrass_double_secp256k1() {
        test_weierstrass_double_helper::<Secp256k1>();
    }

    #[test]
    fn test_weierstrass_double_secp256r1() {
        test_weierstrass_double_helper::<Secp256r1>();
    }

    fn test_weierstrass_double_nonpow2_helper<WP: WeierstrassParameters>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let points = random_points::<WP>(5);
        let _ = run_weierstrass_double::<E, Pcs, SwCurve<WP>>(
            setup_gkr_circuit::<E, SwCurve<WP>>().expect("setup gkr circuit failed"),
            points,
            true,
            true,
        )
        .inspect_err(|err| {
            eprintln!("{:?}", err);
        })
        .expect("test_weierstrass_double_nonpow2_helper failed");
    }

    #[test]
    fn test_weierstrass_double_nonpow2_bn254() {
        test_weierstrass_double_nonpow2_helper::<Bn254>();
    }

    #[test]
    fn test_weierstrass_double_nonpow2_bls12381() {
        test_weierstrass_double_nonpow2_helper::<Bls12381>();
    }

    #[test]
    fn test_weierstrass_double_nonpow2_secp256k1() {
        test_weierstrass_double_nonpow2_helper::<Secp256k1>();
    }

    #[test]
    fn test_weierstrass_double_nonpow2_secp256r1() {
        test_weierstrass_double_nonpow2_helper::<Secp256r1>();
    }
}
