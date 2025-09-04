use std::{array, fmt::Debug, sync::Arc};

use ceno_emul::{ByteAddr, MemOp, StepRecord};
use core::{borrow::BorrowMut, mem::size_of};
use ff_ext::ExtensionField;
use generic_array::{GenericArray, sequence::GenericSequence, typenum::Unsigned};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    cpu::{CpuBackend, CpuProver},
    error::{BackendError, CircuitBuilderError},
    gkr::{GKRCircuit, GKRProof, GKRProverOutput, layer::Layer, mock::MockProver},
    selector::SelectorType,
};
use itertools::{Itertools, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitIn,
    macros::{entered_span, exit_span},
    util::{ceil_log2, max_usable_threads},
};
use num::{BigUint, Zero};
use p3::field::{FieldAlgebra, PrimeField32};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    prelude::{IntoParallelRefIterator, ParallelBridge, ParallelSlice},
};
use sp1_curves::{
    AffinePoint, EllipticCurve,
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    polynomial::Polynomial,
};
use sp1_derive::AlignedBorrow;
use sumcheck::util::optimal_sumcheck_threads;
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::MemoryExpr,
    error::ZKVMError,
    gadgets::{FieldOperation, field_op::FieldOpCols},
    instructions::riscv::insn_base::{StateInOut, WriteMEM},
    precompiles::{
        SelectorTypeLayout,
        utils::merge_u8_limbs_to_u16_limbs_pairs_and_extend,
        weierstrass::{
            EllipticCurveAddInstance, EllipticCurveAddStateInstance, EllipticCurveAddWitInstance,
        },
    },
    structs::PointAndEval,
    witness::LkMultiplicity,
};

pub const fn num_weierstrass_add_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassAddAssignWitCols<u8, P>>()
}

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignWitCols<WitT, P: FieldParameters + NumLimbs> {
    pub clk: WitT,
    pub p_ptr: WitT,
    pub q_ptr: WitT,
    pub p_x: Limbs<WitT, P::Limbs>,
    pub p_y: Limbs<WitT, P::Limbs>,
    pub q_x: Limbs<WitT, P::Limbs>,
    pub q_y: Limbs<WitT, P::Limbs>,
    pub(crate) slope_denominator: FieldOpCols<WitT, P>,
    pub(crate) slope_numerator: FieldOpCols<WitT, P>,
    pub(crate) slope: FieldOpCols<WitT, P>,
    pub(crate) slope_squared: FieldOpCols<WitT, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<WitT, P>,
    pub(crate) x3_ins: FieldOpCols<WitT, P>,
    pub(crate) p_x_minus_x: FieldOpCols<WitT, P>,
    pub(crate) y3_ins: FieldOpCols<WitT, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<WitT, P>,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct WeierstrassAddAssignLayer<WitT, EqT, P: FieldParameters + NumWords> {
    pub wits: WeierstrassAddAssignWitCols<WitT, P>,
    pub eq: EqT,
}

#[derive(Clone, Debug)]
pub struct WeierstrassAddAssignLayout<E: ExtensionField, EC: EllipticCurve> {
    pub layer_exprs: WeierstrassAddAssignLayer<WitIn, StructuralWitIn, EC::BaseField>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs:
        [GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsCurvePoint>; 2],
    pub output32_exprs: GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsCurvePoint>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField, EC: EllipticCurve> WeierstrassAddAssignLayout<E, EC>
where
    E::BaseField: PrimeField32,
{
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = WeierstrassAddAssignWitCols {
            clk: cb.create_witin(|| "clk"),
            p_ptr: cb.create_witin(|| "p_ptr"),
            q_ptr: cb.create_witin(|| "q_ptr"),
            p_x: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_x"))),
            p_y: Limbs(GenericArray::generate(|_| cb.create_witin(|| "p_y"))),
            q_x: Limbs(GenericArray::generate(|_| cb.create_witin(|| "q_x"))),
            q_y: Limbs(GenericArray::generate(|_| cb.create_witin(|| "q_y"))),
            slope_denominator: FieldOpCols::create(cb, || "slope_denominator"),
            slope_numerator: FieldOpCols::create(cb, || "slope_numerator"),
            slope: FieldOpCols::create(cb, || "slope"),
            slope_squared: FieldOpCols::create(cb, || "slope_squared"),
            p_x_plus_q_x: FieldOpCols::create(cb, || "p_x_plus_q_x"),
            x3_ins: FieldOpCols::create(cb, || "x3_ins"),
            p_x_minus_x: FieldOpCols::create(cb, || "p_x_minus_x"),
            y3_ins: FieldOpCols::create(cb, || "y3_ins"),
            slope_times_p_x_minus_x: FieldOpCols::create(cb, || "slope_times_p_x_minus_x"),
        };

        let eq = cb.create_structural_witin(
            || "weierstrass_eq",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );
        let selector_type_layout = SelectorTypeLayout {
            sel_mem_read: SelectorType::Prefix(E::BaseField::ONE, eq.expr()),
            sel_mem_write: SelectorType::Prefix(E::BaseField::ONE, eq.expr()),
            sel_lookup: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
            sel_zero: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
        };

        let input32_exprs: [GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsCurvePoint,
        >; 2] = array::from_fn(|_| {
            GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)))
        });
        let output32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsCurvePoint,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: WeierstrassAddAssignLayer { wits, eq },
            selector_type_layout,
            input32_exprs,
            output32_exprs,
            n_fixed: 0,
            n_committed: num_weierstrass_add_cols::<EC::BaseField>(),
            n_challenges: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops(
        blu_events: &mut LkMultiplicity,
        cols: &mut WeierstrassAddAssignWitCols<E::BaseField, EC::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // This populates necessary field operations to calculate the addition of two points on a
        // Weierstrass curve.

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator =
                cols.slope_numerator
                    .populate(blu_events, &q_y, &p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate(blu_events, &q_x, &p_x, FieldOperation::Sub);

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x
                    .populate(blu_events, &p_x, &q_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x_3n) - p.y.
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
}

impl<E: ExtensionField, EC: EllipticCurve> ProtocolBuilder<E> for WeierstrassAddAssignLayout<E, EC>
where
    E::BaseField: PrimeField32,
{
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = WeierstrassAddAssignLayout::new(cb);
        let wits = &layout.layer_exprs.wits;

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            wits.slope_numerator
                .eval(cb, &wits.q_y, &wits.p_y, FieldOperation::Sub)?;

            wits.slope_denominator
                .eval(cb, &wits.q_x, &wits.p_x, FieldOperation::Sub)?;

            wits.slope.eval(
                cb,
                &wits.slope_numerator.result,
                &wits.slope_denominator.result,
                FieldOperation::Div,
            )?;

            &wits.slope.result
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            wits.slope_squared
                .eval(cb, slope, slope, FieldOperation::Mul)?;

            wits.p_x_plus_q_x
                .eval(cb, &wits.p_x, &wits.q_x, FieldOperation::Add)?;

            wits.x3_ins.eval(
                cb,
                &wits.slope_squared.result,
                &wits.p_x_plus_q_x.result,
                FieldOperation::Sub,
            )?;

            &wits.x3_ins.result
        };

        // y = slope * (p.x - x_3n) - q.y.
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

        // Constraint output32 from wits.x3_ins || wits.y3_ins by converting 8-bit limbs to 2x16-bit felts
        let mut output32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE);
        for limbs in [&wits.x3_ins.result, &wits.y3_ins.result] {
            merge_u8_limbs_to_u16_limbs_pairs_and_extend::<E, EC::BaseField>(limbs, &mut output32);
        }
        let output32 = output32.try_into().unwrap();

        let mut p_input32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE);
        for limbs in [&wits.p_x, &wits.p_y] {
            merge_u8_limbs_to_u16_limbs_pairs_and_extend::<E, EC::BaseField>(limbs, &mut p_input32);
        }
        let p_input32 = p_input32.try_into().unwrap();

        let mut q_input32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE);
        for limbs in [&wits.q_x, &wits.q_y] {
            merge_u8_limbs_to_u16_limbs_pairs_and_extend::<E, EC::BaseField>(limbs, &mut q_input32);
        }
        let q_input32 = q_input32.try_into().unwrap();

        // set input32/output32 expr
        layout.input32_exprs = [p_input32, q_input32];
        layout.output32_exprs = output32;

        Ok(layout)
    }

    fn finalize(&mut self, cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_challenges = 0;

        // register selector to legacy constrain system
        cb.cs.r_selector = Some(self.selector_type_layout.sel_mem_read.clone());
        cb.cs.w_selector = Some(self.selector_type_layout.sel_mem_write.clone());
        cb.cs.lk_selector = Some(self.selector_type_layout.sel_lookup.clone());
        cb.cs.zero_selector = Some(self.selector_type_layout.sel_zero.clone());

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        (
            [
                // r_record
                (0..r_len).collect_vec(),
                // w_record
                (r_len..r_len + w_len).collect_vec(),
                // lk_record
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                // zero_record
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb, self.n_challenges),
        )
    }

    fn n_committed(&self) -> usize {
        todo!()
    }

    fn n_fixed(&self) -> usize {
        todo!()
    }

    fn n_challenges(&self) -> usize {
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
pub struct WeierstrassAddAssignTrace<P: NumWords> {
    pub instances: Vec<EllipticCurveAddInstance<P>>,
}

impl<E: ExtensionField, EC: EllipticCurve> ProtocolWitnessGenerator<E>
    for WeierstrassAddAssignLayout<E, EC>
where
    E::BaseField: PrimeField32,
{
    type Trace = WeierstrassAddAssignTrace<EC::BaseField>;

    fn phase1_witin_rmm_height(&self, num_instances: usize) -> usize {
        num_instances.next_power_of_two()
    }

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        let phase1 = &phase1.instances;
        let num_cols = num_weierstrass_add_cols::<EC::BaseField>();
        let chunk_size = 64;

        let mut dummy_row = vec![E::BaseField::ZERO; num_weierstrass_add_cols::<EC::BaseField>()];
        let cols: &mut WeierstrassAddAssignWitCols<E::BaseField, EC::BaseField> =
            dummy_row.as_mut_slice().borrow_mut();
        let zero = BigUint::zero();
        Self::populate_field_ops(
            lk_multiplicity,
            cols,
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero,
        );

        wits[0]
            .values
            .chunks_mut(chunk_size * num_cols)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                rows.chunks_mut(num_cols).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    if idx < phase1.len() {
                        let cols: &mut WeierstrassAddAssignWitCols<E::BaseField, EC::BaseField> =
                            row.borrow_mut();
                        Self::populate_row(&phase1[idx], cols, &mut lk_multiplicity);
                    } else {
                        row.copy_from_slice(&dummy_row);
                    }
                });
            });
    }
}

impl<E: ExtensionField, EC: EllipticCurve> WeierstrassAddAssignLayout<E, EC>
where
    E::BaseField: PrimeField32,
{
    pub fn populate_row(
        event: &EllipticCurveAddInstance<EC::BaseField>,
        cols: &mut WeierstrassAddAssignWitCols<E::BaseField, EC::BaseField>,
        new_byte_lookup_events: &mut LkMultiplicity,
    ) {
        // Decode affine points.
        let p = &event.witin.p;
        let q = &event.witin.q;
        let p = AffinePoint::<EC>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);
        let q = AffinePoint::<EC>::from_words_le(q);
        let (q_x, q_y) = (q.x, q.y);

        // Populate basic columns.
        cols.clk = E::BaseField::from_canonical_u32(event.state.cur_ts as u32);
        cols.p_ptr = E::BaseField::from_canonical_u32(event.state.addrs[0].0);
        cols.q_ptr = E::BaseField::from_canonical_u32(event.state.addrs[1].0);

        Self::populate_field_ops(new_byte_lookup_events, cols, p_x, p_y, q_x, q_y);
    }
}

/// this is for testing purpose
pub struct TestWeierstrassAddLayout<E: ExtensionField, EC: EllipticCurve> {
    layout: WeierstrassAddAssignLayout<E, EC>,
    mem_rw: Vec<WriteMEM>,
    vm_state: StateInOut<E>,
    _state_ptr: WitIn,
}

pub fn setup_gkr_circuit<E: ExtensionField, EC: EllipticCurve>()
-> Result<(TestWeierstrassAddLayout<E, EC>, GKRCircuit<E>, u16, u16), ZKVMError>
where
    E::BaseField: PrimeField32,
{
    let mut cs = ConstraintSystem::new(|| "weierstrass_add");
    let mut cb = CircuitBuilder::<E>::new(&mut cs);

    // constrain vmstate
    let vm_state = StateInOut::construct_circuit(&mut cb, false)?;

    let state_ptr = cb.create_witin(|| "state_ptr");

    let mut layout = WeierstrassAddAssignLayout::build_layer_logic(&mut cb, ())?;

    // Write the result to the same address of the first input point.
    let mut mem_rw = izip!(&layout.input32_exprs[0], &layout.output32_exprs)
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := state_ptr + i
                state_ptr.expr() + E::BaseField::from_canonical_u32(i as u32).expr(),
                val_before.clone(),
                val_after.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    // Keep the second input point unchanged in memory.
    mem_rw.extend(
        layout.input32_exprs[1]
            .iter()
            .enumerate()
            .map(|(i, val_before)| {
                WriteMEM::construct_circuit(
                    &mut cb,
                    // mem address := state_ptr + i
                    state_ptr.expr() + E::BaseField::from_canonical_u32(i as u32).expr(),
                    val_before.clone(),
                    val_before.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?,
    );

    let (out_evals, mut chip) = layout.finalize(&mut cb);

    let layer =
        Layer::from_circuit_builder(&cb, "Rounds".to_string(), layout.n_challenges, out_evals);
    chip.add_layer(layer);

    Ok((
        TestWeierstrassAddLayout {
            layout,
            vm_state,
            _state_ptr: state_ptr,
            mem_rw,
        },
        chip.gkr_circuit(),
        cs.num_witin,
        cs.num_structural_witin,
    ))
}

#[tracing::instrument(
    skip_all,
    name = "run_faster_keccakf",
    level = "trace",
    fields(profiling_1)
)]
pub fn run_weierstrass_add<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    EC: EllipticCurve,
>(
    (layout, gkr_circuit, num_witin, num_structual_witin): (
        TestWeierstrassAddLayout<E, EC>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    points: Vec<[GenericArray<u32, <EC::BaseField as NumWords>::WordsCurvePoint>; 2]>,
    verify: bool,
    test_outputs: bool,
) -> Result<GKRProof<E>, BackendError>
where
    E::BaseField: PrimeField32,
{
    let num_instances = points.len();
    let log2_num_instance = ceil_log2(num_instances);
    let num_threads = optimal_sumcheck_threads(log2_num_instance);
    let mut instances = Vec::with_capacity(num_instances);

    let span = entered_span!("instances", profiling_2 = true);
    for [p, q] in points {
        let instance = EllipticCurveAddInstance {
            state: EllipticCurveAddStateInstance {
                addrs: [ByteAddr::from(0); 2],
                cur_ts: 0,
                read_ts: [GenericArray::default(), GenericArray::default()],
            },
            witin: EllipticCurveAddWitInstance { p, q },
        };
        instances.push(instance);
    }
    exit_span!(span);

    let span = entered_span!("phase1_witness", profiling_2 = true);
    let nthreads = max_usable_threads();
    let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);

    let mut lk_multiplicity = LkMultiplicity::default();
    let mut phase1_witness = RowMajorMatrix::<E::BaseField>::new(
        layout.layout.phase1_witin_rmm_height(num_instances),
        num_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let mut structural_witness = RowMajorMatrix::<E::BaseField>::new(
        layout.layout.phase1_witin_rmm_height(num_instances),
        num_structual_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let raw_witin_iter = phase1_witness.par_batch_iter_mut(num_instance_per_batch);
    raw_witin_iter
        .zip_eq(instances.par_chunks(num_instance_per_batch))
        .for_each(|(instances, steps)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin as usize)
                .zip_eq(steps)
                .for_each(|(instance_with_rotation, _step)| {
                    // assign full rotation with same witness
                    for instance in instance_with_rotation.chunks_mut(num_witin as usize) {
                        layout
                            .vm_state
                            .assign_instance(
                                instance,
                                &StepRecord::new_ecall_any(10, ByteAddr::from(0)),
                            )
                            .expect("assign vm_state error");
                        layout.mem_rw.iter().for_each(|mem_config| {
                            mem_config
                                .assign_op(
                                    instance,
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
                    }
                })
        });

    layout.layout.phase1_witness_group(
        WeierstrassAddAssignTrace { instances },
        [&mut phase1_witness, &mut structural_witness],
        &mut lk_multiplicity,
    );

    exit_span!(span);

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
    let (gkr_witness, gkr_output) = layout
        .layout
        .gkr_witness::<CpuBackend<E, PCS>, CpuProver<_>>(
            &gkr_circuit,
            &phase1_witness_group,
            &structural_witness,
            &fixed,
            &[],
            &challenges,
        );
    exit_span!(span);

    let span = entered_span!("out_eval", profiling_2 = true);
    let out_evals = {
        let mut point = Vec::with_capacity(log2_num_instance);
        point.extend(prover_transcript.sample_vec(log2_num_instance).to_vec());

        if test_outputs {
            // Confront outputs with tiny_keccak::keccakf call
            let mut instance_outputs = vec![vec![]; num_instances];
            for base in gkr_witness
                .layers
                .last()
                .unwrap()
                .iter()
                .take(<EC::BaseField as NumWords>::WordsCurvePoint::USIZE)
            {
                assert_eq!(base.evaluations().len(), num_instances.next_power_of_two());

                for (i, instance_output) in
                    instance_outputs.iter_mut().enumerate().take(num_instances)
                {
                    instance_output.push(base.get_base_field_vec()[i]);
                }
            }
        }

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

        // assert_eq!(out_evals.len(), KECCAK_OUT_EVAL_SIZE);

        out_evals
    };
    exit_span!(span);

    if cfg!(debug_assertions) {
        // mock prover
        let out_wits = gkr_output.0.0.clone();
        MockProver::check(&gkr_circuit, &gkr_witness, out_wits, challenges.to_vec())
            .expect("mock prover failed");
    }

    let span = entered_span!("create_proof", profiling_2 = true);
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instance,
            gkr_witness,
            &out_evals,
            &[],
            &challenges,
            &mut prover_transcript,
            num_instances,
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
                    num_instances,
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
    use rand::{RngCore, SeedableRng};
    use sp1_curves::weierstrass::{bls12_381::Bls12381, bn254::Bn254, secp256k1::Secp256k1};

    fn test_weierstrass_add_helper<EC: EllipticCurve>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 8;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.next_u64()));
        }
        let _ = run_weierstrass_add::<E, Pcs, EC>(
            setup_gkr_circuit::<E, EC>().expect("setup gkr circuit failed"),
            states,
            true,
            true,
        );
    }

    #[test]
    fn test_weierstrass_add_bn254() {
        test_weierstrass_add_helper::<Bn254>();
    }

    #[test]
    fn test_weierstrass_add_bls12381() {
        test_weierstrass_add_helper::<Bls12381>();
    }

    #[test]
    fn test_weierstrass_add_secp256k1() {
        test_weierstrass_add_helper::<Secp256k1>();
    }

    fn test_weierstrass_add_nonpow2_helper<EC: EllipticCurve>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 5;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.next_u64()));
        }

        let _ = run_weierstrass_add::<E, Pcs, EC>(
            setup_gkr_circuit::<E, EC>().expect("setup gkr circuit failed"),
            states,
            true,
            true,
        );
    }

    #[test]
    fn test_weierstrass_add_nonpow2_bn254() {
        test_weierstrass_add_nonpow2_helper::<Bn254>();
    }

    #[test]
    fn test_weierstrass_add_nonpow2_bls12381() {
        test_weierstrass_add_nonpow2_helper::<Bls12381>();
    }

    #[test]
    fn test_weierstrass_add_nonpow2_secp256k1() {
        test_weierstrass_add_nonpow2_helper::<Secp256k1>();
    }
}
