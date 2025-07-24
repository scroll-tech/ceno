use std::{array, mem::transmute};

use ceno_emul::{ByteAddr, Change, Cycle, MemOp, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    circuit_builder::{
        CircuitBuilder, ConstraintSystem, RotationParams, expansion_expr, rotation_split,
    },
    cpu::{CpuBackend, CpuProver},
    error::{BackendError, CircuitBuilderError},
    gkr::{
        GKRCircuit, GKRProof, GKRProverOutput,
        booleanhypercube::{BooleanHypercube, CYCLIC_POW2_5},
        layer::Layer,
        mock::MockProver,
    },
    selector::SelectorType,
    utils::lk_multiplicity::LkMultiplicity,
};
use itertools::{Itertools, iproduct, izip, zip_eq};
use keccakf::Permutation;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, StructuralWitIn, ToExpr, WitIn,
    mle::PointAndEval,
    util::{ceil_log2, max_usable_threads},
};
use ndarray::{ArrayView, Ix2, Ix3, s};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    error::ZKVMError,
    instructions::riscv::insn_base::{StateInOut, WriteMEM},
    precompiles::utils::{
        MaskRepresentation, not8_expr, set_slice_felts_from_u64 as push_instance,
    },
};

pub const ROUNDS: usize = 24;
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

pub const KECCAK_INPUT32_SIZE: usize = 50;
pub const KECCAK_OUTPUT32_SIZE: usize = 50;

// number of non zero out within keccak circuit
pub const KECCAK_OUT_EVAL_SIZE: usize = size_of::<KeccakOutEvals<u8>>();

const AND_LOOKUPS_PER_ROUND: usize = 200;
const XOR_LOOKUPS_PER_ROUND: usize = 608;
const RANGE_LOOKUPS_PER_ROUND: usize = 290;
const LOOKUP_FELTS_PER_ROUND: usize =
    AND_LOOKUPS_PER_ROUND + XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND;

pub const AND_LOOKUPS: usize = AND_LOOKUPS_PER_ROUND;
pub const XOR_LOOKUPS: usize = XOR_LOOKUPS_PER_ROUND;
pub const RANGE_LOOKUPS: usize = RANGE_LOOKUPS_PER_ROUND;
pub const STRUCTURAL_WITIN: usize = 6;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakInOutCols<T> {
    pub output32: [T; KECCAK_OUTPUT32_SIZE],
    pub input32: [T; KECCAK_INPUT32_SIZE],
}

#[derive(Clone, Debug)]
pub struct KeccakParams;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakOutEvals<T> {
    pub lookup_entries: [T; LOOKUP_FELTS_PER_ROUND],
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakFixedCols<T> {
    pub rc: [T; 8],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakWitCols<T> {
    pub input8: [T; 200],
    pub c_aux: [T; 200],
    pub c_temp: [T; 30],
    pub c_rot: [T; 40],
    pub d: [T; 40],
    pub theta_output: [T; 200],
    pub rotation_witness: [T; 146],
    pub rhopi_output: [T; 200],
    pub nonlinear: [T; 200],
    pub chi_output: [T; 8],
    pub iota_output: [T; 200],
    // TODO temporarily define rc as witness
    pub rc: [T; 8],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakLayer<WitT, EqT> {
    pub wits: KeccakWitCols<WitT>,
    //  pub fixed: KeccakFixedCols<FixedT>,
    pub(crate) eq_rotation_left: EqT,
    pub(crate) eq_rotation_right: EqT,
    pub(crate) eq_rotation: EqT,
}

#[derive(Clone, Debug)]
pub struct SelectorTypeLayout<E: ExtensionField> {
    pub sel_mem_read: SelectorType<E>,
    pub sel_mem_write: SelectorType<E>,
    pub sel_lookup: SelectorType<E>,
    pub sel_zero: SelectorType<E>,
}

#[derive(Clone, Debug)]
pub struct KeccakLayout<E: ExtensionField> {
    pub params: KeccakParams,
    pub layer_exprs: KeccakLayer<WitIn, StructuralWitIn>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs: [Expression<E>; KECCAK_INPUT32_SIZE],
    pub output32_exprs: [Expression<E>; KECCAK_OUTPUT32_SIZE],
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField> KeccakLayout<E> {
    fn new(cb: &mut CircuitBuilder<E>, params: KeccakParams) -> Self {
        // allocate witnesses, fixed, and eqs
        let (
            wits,
            // fixed,
            [
                sel_mem_read,
                sel_mem_write,
                eq_zero,
                eq_rotation_left,
                eq_rotation_right,
                eq_rotation,
            ],
        ): (KeccakWitCols<WitIn>, [StructuralWitIn; STRUCTURAL_WITIN]) = unsafe {
            (
                transmute::<[WitIn; size_of::<KeccakWitCols<u8>>()], KeccakWitCols<WitIn>>(
                    array::from_fn(|id| cb.create_witin(|| format!("keccak_witin_{}", id))),
                ),
                // transmute::<[Fixed; 8], KeccakFixedCols<Fixed>>(array::from_fn(|id| {
                //     cb.create_fixed(|| format!("keccak_fixed_{}", id))
                // })),
                array::from_fn(|id| {
                    cb.create_structural_witin(|| format!("keccak_eq_{}", id), 0, 0, 0, false)
                }),
            )
        };

        // indices to activate zero/lookup constraints
        let checked_indices = CYCLIC_POW2_5
            .iter()
            .take(ROUNDS)
            .sorted()
            .copied()
            .map(|v| v as usize)
            .collect_vec();
        Self {
            params,
            layer_exprs: KeccakLayer {
                wits,
                // fixed,
                eq_rotation_left,
                eq_rotation_right,
                eq_rotation,
            },
            selector_type_layout: SelectorTypeLayout {
                sel_mem_read: SelectorType::OrderedSparse32 {
                    indices: vec![CYCLIC_POW2_5[0] as usize],
                    expression: sel_mem_read.expr(),
                },
                sel_mem_write: SelectorType::OrderedSparse32 {
                    indices: vec![CYCLIC_POW2_5[ROUNDS - 1] as usize],
                    expression: sel_mem_write.expr(),
                },
                sel_lookup: SelectorType::OrderedSparse32 {
                    indices: checked_indices.clone(),
                    expression: eq_zero.expr(),
                },
                sel_zero: SelectorType::OrderedSparse32 {
                    indices: checked_indices,
                    expression: eq_zero.expr(),
                },
            },
            input32_exprs: array::from_fn(|_| Expression::WitIn(0)),
            output32_exprs: array::from_fn(|_| Expression::WitIn(0)),
            n_fixed: 0,
            n_committed: 0,
            n_structural_witin: STRUCTURAL_WITIN,
            n_challenges: 0,
        }
    }
}

impl<E: ExtensionField> ProtocolBuilder<E> for KeccakLayout<E> {
    type Params = KeccakParams;

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = Self::new(cb, params);
        let system = cb;

        let KeccakWitCols {
            input8,
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
            rc,
        } = &layout.layer_exprs.wits;

        // let KeccakFixedCols { rc } = &layout.layer_exprs.fixed;

        // TODO: ndarrays can be replaced with normal arrays
        // Input state of the round in 8-bit chunks
        let state8: ArrayView<WitIn, Ix3> = ArrayView::from_shape((5, 5, 8), input8).unwrap();

        // The purpose is to compute the auxiliary array
        // c[i] = XOR (state[j][i]) for j in 0..5
        // We unroll it into
        // c_aux[i][j] = XOR (state[k][i]) for k in 0..j
        // We use c_aux[i][4] instead of c[i]
        // c_aux is also stored in 8-bit chunks
        let c_aux: ArrayView<WitIn, Ix3> = ArrayView::from_shape((5, 5, 8), c_aux).unwrap();

        for i in 0..5 {
            for k in 0..8 {
                // Initialize first element
                system.require_equal(
                    || "init c_aux".to_string(),
                    state8[[0, i, k]].into(),
                    c_aux[[i, 0, k]].into(),
                )?;
            }
            for j in 1..5 {
                // Check xor using lookups over all chunks
                for k in 0..8 {
                    system.lookup_xor_byte(
                        c_aux[[i, j - 1, k]].into(),
                        state8[[j, i, k]].into(),
                        c_aux[[i, j, k]].into(),
                    )?;
                }
            }
        }

        // Compute c_rot[i] = c[i].rotate_left(1)
        // To understand how rotations are performed in general, consult the
        // documentation of `constrain_left_rotation64`. Here c_temp is the split
        // witness for a 1-rotation.

        let c_temp: ArrayView<WitIn, Ix2> = ArrayView::from_shape((5, 6), c_temp).unwrap();
        let c_rot: ArrayView<WitIn, Ix2> = ArrayView::from_shape((5, 8), c_rot).unwrap();

        let (sizes, _) = rotation_split(1);

        for i in 0..5 {
            assert_eq!(c_temp.slice(s![i, ..]).iter().len(), sizes.iter().len());

            system.require_left_rotation64(
                || format!("theta rotation_{i}"),
                &c_aux
                    .slice(s![i, 4, ..])
                    .iter()
                    .map(|e| e.expr())
                    .collect_vec(),
                &zip_eq(c_temp.slice(s![i, ..]).iter(), sizes.iter())
                    .map(|(e, sz)| (*sz, e.expr()))
                    .collect_vec(),
                &c_rot
                    .slice(s![i, ..])
                    .iter()
                    .map(|e| e.expr())
                    .collect_vec(),
                1,
            )?;
        }

        // d is computed simply as XOR of required elements of c (and rotations)
        // again stored as 8-bit chunks
        let d: ArrayView<WitIn, Ix2> = ArrayView::from_shape((5, 8), d).unwrap();

        for i in 0..5 {
            for k in 0..8 {
                system.lookup_xor_byte(
                    c_aux[[(i + 5 - 1) % 5, 4, k]].into(),
                    c_rot[[(i + 1) % 5, k]].into(),
                    d[[i, k]].into(),
                )?;
            }
        }

        // output state of the Theta sub-round, simple XOR, in 8-bit chunks
        let theta_output: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), theta_output).unwrap();

        for i in 0..5 {
            for j in 0..5 {
                for k in 0..8 {
                    system.lookup_xor_byte(
                        state8[[j, i, k]].into(),
                        d[[i, k]].into(),
                        theta_output[[j, i, k]].into(),
                    )?
                }
            }
        }

        // output state after applying both Rho and Pi sub-rounds
        // sub-round Pi is a simple permutation of 64-bit lanes
        // sub-round Rho requires rotations
        let rhopi_output: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), rhopi_output).unwrap();

        // iterator over split witnesses
        let mut rotation_witness = rotation_witness.iter();

        for i in 0..5 {
            #[allow(clippy::needless_range_loop)]
            for j in 0..5 {
                let arg = theta_output
                    .slice(s!(j, i, ..))
                    .iter()
                    .map(|e| e.expr())
                    .collect_vec();
                let (sizes, _) = rotation_split(ROTATION_CONSTANTS[j][i]);
                let many = sizes.len();
                let rep_split = zip_eq(sizes, rotation_witness.by_ref().take(many))
                    .map(|(sz, wit)| (sz, wit.expr()))
                    .collect_vec();
                let arg_rotated = rhopi_output
                    .slice(s!((2 * i + 3 * j) % 5, j, ..))
                    .iter()
                    .map(|e| e.expr())
                    .collect_vec();
                system.require_left_rotation64(
                    || format!("RHOPI {i}, {j}"),
                    &arg,
                    &rep_split,
                    &arg_rotated,
                    ROTATION_CONSTANTS[j][i],
                )?;
            }
        }

        let mut chi_output = chi_output.to_vec();
        chi_output.extend(iota_output[8..].to_vec());
        let chi_output: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), &chi_output).unwrap();

        // for the Chi sub-round, we use an intermediate witness storing the result of
        // the required AND
        let nonlinear: ArrayView<WitIn, Ix3> = ArrayView::from_shape((5, 5, 8), nonlinear).unwrap();

        for i in 0..5 {
            for j in 0..5 {
                for k in 0..8 {
                    system.lookup_and_byte(
                        not8_expr(rhopi_output[[j, (i + 1) % 5, k]].into()),
                        rhopi_output[[j, (i + 2) % 5, k]].into(),
                        nonlinear[[j, i, k]].into(),
                    )?;

                    system.lookup_xor_byte(
                        rhopi_output[[j, i, k]].into(),
                        nonlinear[[j, i, k]].into(),
                        chi_output[[j, i, k]].into(),
                    )?;
                }
            }
        }

        let iota_output_arr: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), iota_output).unwrap();

        for k in 0..8 {
            system.lookup_xor_byte(
                chi_output[[0, 0, k]].into(),
                rc[k].into(),
                iota_output_arr[[0, 0, k]].into(),
            )?;
        }

        let keccak_input8: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), input8).unwrap();
        let keccak_output8: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), iota_output).unwrap();

        // process keccak output
        let mut keccak_output32 = Vec::with_capacity(KECCAK_OUTPUT32_SIZE);
        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    keccak_output32.push(expansion_expr::<E, 32>(
                        &keccak_output8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.expr()))
                            .collect_vec(),
                    ))
                }
            }
        }

        let mut keccak_input32 = Vec::with_capacity(KECCAK_INPUT32_SIZE);
        // process keccak input
        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    keccak_input32.push(expansion_expr::<E, 32>(
                        keccak_input8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.expr()))
                            .collect_vec()
                            .as_slice(),
                    ))
                }
            }
        }
        // set input/output32 expr
        layout.input32_exprs = keccak_input32.try_into().unwrap();
        layout.output32_exprs = keccak_output32.try_into().unwrap();

        // rotation constrain: rotation(keccak_input8).next() == keccak_output8
        izip!(keccak_input8, keccak_output8)
            .for_each(|(input, output)| system.rotate_and_assert_eq(input.expr(), output.expr()));
        system.set_rotation_params(RotationParams {
            rotation_eqs: Some([
                layout.layer_exprs.eq_rotation_left.expr(),
                layout.layer_exprs.eq_rotation_right.expr(),
                layout.layer_exprs.eq_rotation.expr(),
            ]),
            rotation_cyclic_group_log2: ROUNDS_CEIL_LOG2,
            rotation_cyclic_subgroup_size: ROUNDS - 1,
        });

        Ok(layout)
    }

    fn finalize(&mut self, cb: &CircuitBuilder<E>) -> (OutEvalGroups<E>, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_challenges = self.n_challenges();

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        (
            [
                // r_record
                (
                    self.selector_type_layout.sel_mem_read.clone(),
                    (0..r_len).collect_vec(),
                ),
                // w_record
                (
                    self.selector_type_layout.sel_mem_write.clone(),
                    (r_len..r_len + w_len).collect_vec(),
                ),
                // lk_record
                (
                    self.selector_type_layout.sel_lookup.clone(),
                    (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                ),
                // zero_record
                (
                    self.selector_type_layout.sel_zero.clone(),
                    (0..zero_len).collect_vec(),
                ),
            ],
            Chip::new_from_cb(cb, self.n_challenges()),
        )
    }

    fn n_committed(&self) -> usize {
        unimplemented!("retrieve from constrain system")
    }

    fn n_fixed(&self) -> usize {
        unimplemented!("retrieve from constrain system")
    }

    fn n_challenges(&self) -> usize {
        0
    }

    fn n_layers(&self) -> usize {
        1
    }

    fn n_evaluations(&self) -> usize {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct KeccakStateInstance {
    pub state_ptr_address: ByteAddr,
    pub cur_ts: Cycle,
    pub read_ts: [Cycle; KECCAK_INPUT32_SIZE],
}

impl Default for KeccakStateInstance {
    fn default() -> Self {
        Self {
            state_ptr_address: Default::default(),
            cur_ts: Default::default(),
            read_ts: [Cycle::default(); KECCAK_INPUT32_SIZE],
        }
    }
}

#[derive(Clone)]
pub struct KeccakWitInstance {
    pub instance: [u32; KECCAK_INPUT32_SIZE],
}

impl Default for KeccakWitInstance {
    fn default() -> Self {
        Self {
            instance: [0u32; KECCAK_INPUT32_SIZE],
        }
    }
}

#[derive(Clone, Default)]
pub struct KeccakInstance {
    pub state: KeccakStateInstance,
    pub witin: KeccakWitInstance,
}

#[derive(Clone, Default)]
pub struct KeccakTrace {
    pub instances: Vec<KeccakInstance>,
}

impl<E> ProtocolWitnessGenerator<E> for KeccakLayout<E>
where
    E: ExtensionField,
{
    type Trace = KeccakTrace;

    // 1 instance will derive 24 round result + 8 round padding to pow2 for easiler rotation design
    fn phase1_witin_rmm_height(&self, num_instances: usize) -> usize {
        num_instances * ROUNDS.next_power_of_two()
    }

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        // TODO remove this after recover RC
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
        // RowMajorMatrix::new_by_values(
        //     RC.iter()
        //         .flat_map(|x| {
        //             (0..8)
        //                 .map(|i| E::BaseField::from_canonical_u64((x >> (i << 3)) & 0xFF))
        //                 .collect_vec()
        //         })
        //         .collect_vec(),
        //     8,
        //     InstancePaddingStrategy::Default,
        // )
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        // TODO assign eq (selectors) to _structural_wits
        let [wits, _structural_wits] = wits;
        let KeccakLayer {
            wits:
                KeccakWitCols {
                    input8: input8_witin,
                    c_aux: c_aux_witin,
                    c_temp: c_temp_witin,
                    c_rot: c_rot_witin,
                    d: d_witin,
                    theta_output: theta_output_witin,
                    rotation_witness: rotation_witness_witin,
                    rhopi_output: rhopi_output_witin,
                    nonlinear: nonlinear_witin,
                    chi_output: chi_output_witin,
                    iota_output: iota_output_witin,
                    rc: rc_witin,
                },
            ..
        } = self.layer_exprs;

        let num_instances = phase1.instances.len();

        fn conv64to8(input: u64) -> [u64; 8] {
            MaskRepresentation::new(vec![(64, input).into()])
                .convert(vec![8; 8])
                .values()
                .try_into()
                .unwrap()
        }

        // keccak instance full rounds (24 rounds + 8 round padding) as chunk size
        // we need to do assignment on respective 31 cyclic group index
        wits.values
            .par_chunks_mut(self.n_committed * ROUNDS.next_power_of_two())
            .take(num_instances)
            .zip(&phase1.instances)
            .for_each(|(wits, KeccakInstance { witin, .. })| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                let state_32_iter = witin.instance.iter().map(|e| *e as u64);
                let mut state64 = [[0u64; 5]; 5];
                zip_eq(iproduct!(0..5, 0..5), state_32_iter.tuples())
                    .map(|((x, y), (lo, hi))| {
                        state64[x][y] = lo | (hi << 32);
                    })
                    .count();

                let bh = BooleanHypercube::new(ROUNDS_CEIL_LOG2);
                let mut cyclic_group = bh.into_iter();

                #[allow(clippy::needless_range_loop)]
                for round in 0..ROUNDS {
                    let round_index = cyclic_group.next().unwrap();
                    let wits =
                        &mut wits[round_index as usize * self.n_committed..][..self.n_committed];
                    let mut state8 = [[[0u64; 8]; 5]; 5];
                    for x in 0..5 {
                        for y in 0..5 {
                            state8[x][y] = conv64to8(state64[x][y]);
                        }
                    }

                    push_instance::<E, _>(
                        wits,
                        input8_witin[0].id.into(),
                        state8.into_iter().flatten().flatten(),
                    );

                    let mut c_aux64 = [[0u64; 5]; 5];
                    let mut c_aux8 = [[[0u64; 8]; 5]; 5];

                    for i in 0..5 {
                        c_aux64[i][0] = state64[0][i];
                        c_aux8[i][0] = conv64to8(c_aux64[i][0]);
                        for j in 1..5 {
                            c_aux64[i][j] = state64[j][i] ^ c_aux64[i][j - 1];
                            for k in 0..8 {
                                lk_multiplicity
                                    .lookup_xor_byte(state8[j][i][k], c_aux8[i][j - 1][k]);
                            }
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
                            .convert(vec![16, 15, 1, 16, 15, 1])
                            .values();
                        for (j, size) in [16, 15, 1, 16, 15, 1].iter().enumerate() {
                            lk_multiplicity.assert_ux_in_u16(*size, rep[j]);
                        }
                        c_temp[i] = rep.try_into().unwrap();
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
                        for k in 0..8 {
                            lk_multiplicity.lookup_xor_byte(
                                crot8[(x + 1) % 5][k],
                                c_aux8[(x + 5 - 1) % 5][4][k],
                            );
                        }
                        d8[x] = conv64to8(d64[x]);
                    }

                    let mut theta_state64 = state64;
                    let mut theta_state8 = [[[0u64; 8]; 5]; 5];
                    let mut rotation_witness = vec![];

                    for x in 0..5 {
                        for y in 0..5 {
                            theta_state64[y][x] ^= d64[x];
                            for k in 0..8 {
                                lk_multiplicity.lookup_xor_byte(state8[y][x][k], d8[x][k])
                            }
                            theta_state8[y][x] = conv64to8(theta_state64[y][x]);

                            let (sizes, _) = rotation_split(ROTATION_CONSTANTS[y][x]);
                            let rep =
                                MaskRepresentation::new(vec![(64, theta_state64[y][x]).into()])
                                    .convert(sizes.clone())
                                    .values();
                            for (j, size) in sizes.iter().enumerate() {
                                if *size != 32 {
                                    lk_multiplicity.assert_ux_in_u16(*size, rep[j]);
                                }
                            }
                            rotation_witness.extend(rep);
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
                            for k in 0..8 {
                                lk_multiplicity.lookup_and_byte(
                                    0xFF - rhopi_output8[y][(x + 1) % 5][k],
                                    rhopi_output8[y][(x + 2) % 5][k],
                                );
                            }
                            nonlinear8[y][x] = conv64to8(nonlinear64[y][x]);
                        }
                    }

                    let mut chi_output64 = [[0u64; 5]; 5];
                    let mut chi_output8 = [[[0u64; 8]; 5]; 5];
                    for x in 0..5 {
                        for y in 0..5 {
                            chi_output64[y][x] = nonlinear64[y][x] ^ rhopi_output64[y][x];
                            for k in 0..8 {
                                lk_multiplicity
                                    .lookup_xor_byte(rhopi_output8[y][x][k], nonlinear8[y][x][k]);
                            }
                            chi_output8[y][x] = conv64to8(chi_output64[y][x]);
                        }
                    }

                    // Iota step
                    let mut iota_output64 = chi_output64;
                    let mut iota_output8 = [[[0u64; 8]; 5]; 5];
                    // TODO figure out how to deal with RC, since it's not a constant in rotation
                    iota_output64[0][0] ^= RC[round];

                    for k in 0..8 {
                        let rc8 = conv64to8(RC[round]);
                        lk_multiplicity.lookup_xor_byte(chi_output8[0][0][k], rc8[k]);
                    }

                    for x in 0..5 {
                        for y in 0..5 {
                            iota_output8[x][y] = conv64to8(iota_output64[x][y]);
                        }
                    }

                    // set witness
                    push_instance::<E, _>(
                        wits,
                        c_aux_witin[0].id.into(),
                        c_aux8.into_iter().flatten().flatten(),
                    );
                    push_instance::<E, _>(
                        wits,
                        c_temp_witin[0].id.into(),
                        c_temp.into_iter().flatten(),
                    );
                    push_instance::<E, _>(
                        wits,
                        c_rot_witin[0].id.into(),
                        crot8.into_iter().flatten(),
                    );
                    push_instance::<E, _>(wits, d_witin[0].id.into(), d8.into_iter().flatten());
                    push_instance::<E, _>(
                        wits,
                        theta_output_witin[0].id.into(),
                        theta_state8.into_iter().flatten().flatten(),
                    );
                    push_instance::<E, _>(
                        wits,
                        rotation_witness_witin[0].id.into(),
                        rotation_witness.into_iter(),
                    );
                    push_instance::<E, _>(
                        wits,
                        rhopi_output_witin[0].id.into(),
                        rhopi_output8.into_iter().flatten().flatten(),
                    );
                    push_instance::<E, _>(
                        wits,
                        nonlinear_witin[0].id.into(),
                        nonlinear8.into_iter().flatten().flatten(),
                    );
                    push_instance::<E, _>(
                        wits,
                        chi_output_witin[0].id.into(),
                        chi_output8[0][0].iter().copied(),
                    );
                    push_instance::<E, _>(
                        wits,
                        iota_output_witin[0].id.into(),
                        iota_output8.into_iter().flatten().flatten(),
                    );
                    // TODO temporarily move RC to witness
                    push_instance::<E, _>(
                        wits,
                        rc_witin[0].id.into(),
                        (0..8).map(|i| ((RC[round] >> (i << 3)) & 0xFF)),
                    );

                    state64 = iota_output64;
                }
            });
    }
}

/// this is for testing purpose
pub struct TestKeccakLayout<E: ExtensionField> {
    layout: KeccakLayout<E>,
    mem_rw: Vec<WriteMEM>,
    vm_state: StateInOut<E>,
    _state_ptr: WitIn,
}

pub fn setup_gkr_circuit<E: ExtensionField>()
-> Result<(TestKeccakLayout<E>, GKRCircuit<E>, u16, u16), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "lookup_keccak");
    let mut cb = CircuitBuilder::<E>::new(&mut cs);

    // constrain vmstate
    let vm_state = StateInOut::construct_circuit(&mut cb, false)?;

    let state_ptr = cb.create_witin(|| "state_ptr");

    let mut layout = KeccakLayout::build_layer_logic(&mut cb, KeccakParams {})?;

    let mem_rw = izip!(&layout.input32_exprs, &layout.output32_exprs)
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := state_ptr + i
                state_ptr.expr() + E::BaseField::from_canonical_u32(i as u32).expr(),
                val_before.expr(),
                val_after.expr(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    let (out_evals, mut chip) = layout.finalize(&cb);

    let layer =
        Layer::from_circuit_builder(&cb, "Rounds".to_string(), layout.n_challenges(), out_evals);
    chip.add_layer(layer);

    cb.finalize();
    Ok((
        TestKeccakLayout {
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
pub fn run_faster_keccakf<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    (layout, gkr_circuit, num_witin, num_structual_witin): (
        TestKeccakLayout<E>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    states: Vec<[u64; 25]>,
    verify: bool,
    test_outputs: bool,
) -> Result<GKRProof<E>, BackendError> {
    let num_instances = states.len();
    let num_instances_rounds = num_instances * ROUNDS.next_power_of_two();
    let log2_num_instance_rounds = ceil_log2(num_instances_rounds);
    let num_threads = optimal_sumcheck_threads(log2_num_instance_rounds);
    let mut instances = Vec::with_capacity(num_instances);
    let mut instances_outputu32: Vec<[u32; KECCAK_OUTPUT32_SIZE]> =
        Vec::with_capacity(num_instances);

    let span = entered_span!("instances", profiling_2 = true);
    for state in &states {
        let state_mask64 = MaskRepresentation::from(state.iter().map(|e| (64, *e)).collect_vec());
        let state_mask32 = state_mask64.convert(vec![32; 50]);

        let instance = KeccakInstance {
            state: KeccakStateInstance {
                state_ptr_address: ByteAddr::from(0),
                cur_ts: 0,
                read_ts: [0; KECCAK_INPUT32_SIZE],
            },
            witin: KeccakWitInstance {
                instance: state_mask32
                    .values()
                    .iter()
                    .map(|e| *e as u32)
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            },
        };
        instances.push(instance);
        instances_outputu32.push({
            let mut state = *state;
            state.permute();
            let state_mask64 =
                MaskRepresentation::from(state.iter().map(|e| (64, *e)).collect_vec());
            let state_mask32 = state_mask64.convert(vec![32; 50]);
            state_mask32
                .values()
                .iter()
                .map(|e| *e as u32)
                .collect_vec()
                .try_into()
                .unwrap()
        })
    }
    exit_span!(span);

    let span = entered_span!("phase1_witness", profiling_2 = true);
    let nthreads = max_usable_threads();
    let num_instance_per_batch = states.len().div_ceil(nthreads).max(1);

    let mut lk_multiplicity = LkMultiplicity::default();
    let mut phase1_witness = RowMajorMatrix::<E::BaseField>::new(
        layout.layout.phase1_witin_rmm_height(states.len()),
        num_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let mut structural_witness = RowMajorMatrix::<E::BaseField>::new(
        layout.layout.phase1_witin_rmm_height(states.len()),
        num_structual_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let raw_witin_iter =
        phase1_witness.par_batch_iter_mut(num_instance_per_batch * ROUNDS.next_power_of_two());
    raw_witin_iter
        .zip_eq(instances.par_chunks(num_instance_per_batch))
        .zip_eq(instances_outputu32.par_chunks(num_instance_per_batch))
        .for_each(|((instances, steps), out32s)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin as usize * ROUNDS.next_power_of_two())
                .zip_eq(steps)
                .zip_eq(out32s)
                .for_each(|((instance_with_rotation, step), out32)| {
                    // assign full rotation with same witness
                    for instance in instance_with_rotation.chunks_mut(num_witin as usize) {
                        layout
                            .vm_state
                            .assign_instance(
                                instance,
                                &StepRecord::new_ecall_any(10, ByteAddr::from(0)),
                            )
                            .expect("assign vm_state error");
                        layout
                            .mem_rw
                            .iter()
                            .zip_eq(step.witin.instance)
                            .zip_eq(out32.iter())
                            .for_each(|((mem_config, input_32), output_32)| {
                                mem_config
                                    .assign_op(
                                        instance,
                                        &mut lk_multiplicity,
                                        10,
                                        &MemOp {
                                            previous_cycle: 0,
                                            addr: ByteAddr::from(0).waddr(),
                                            value: Change {
                                                before: input_32,
                                                after: *output_32,
                                            },
                                        },
                                    )
                                    .expect("assign error");
                            });
                    }
                })
        });

    layout.layout.phase1_witness_group(
        KeccakTrace { instances },
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
    let fixed = layout.layout.fixed_witness_group();
    #[allow(clippy::type_complexity)]
    let (gkr_witness, gkr_output) = layout
        .layout
        .gkr_witness::<CpuBackend<E, PCS>, CpuProver<_>>(
            &gkr_circuit,
            &phase1_witness,
            &fixed,
            &challenges,
        );
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
                .iter()
                .take(KECCAK_OUTPUT32_SIZE)
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
        MockProver::check(
            &gkr_circuit,
            &gkr_witness,
            out_wits,
            challenges.to_vec(),
            num_instances,
        )
        .expect("mock prover failed");
    }

    let span = entered_span!("create_proof", profiling_2 = true);
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instance_rounds,
            gkr_witness,
            &out_evals,
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
    use ff_ext::GoldilocksExt2;
    use mpcs::BasefoldDefault;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_keccakf() {
        type E = GoldilocksExt2;
        type Pcs = BasefoldDefault<E>;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 8;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.next_u64()));
        }
        let _ = run_faster_keccakf::<E, Pcs>(
            setup_gkr_circuit::<E>().expect("setup gkr circuit failed"),
            states,
            true,
            true,
        );
    }

    #[test]
    fn test_keccakf_nonpow2() {
        type E = GoldilocksExt2;
        type Pcs = BasefoldDefault<E>;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 5;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.next_u64()));
        }

        let _ = run_faster_keccakf::<E, Pcs>(
            setup_gkr_circuit::<E>().expect("setup gkr circuit failed"),
            states,
            true,
            true,
        );
    }
}
