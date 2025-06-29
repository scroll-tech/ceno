use std::{marker::PhantomData, mem::transmute};

use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct, izip, zip_eq};
use multilinear_extensions::{Fixed, ToExpr, WitIn, mle::PointAndEval, util::ceil_log2};
use ndarray::{ArrayView, Ix2, Ix3, s};
use p3_field::FieldAlgebra;
use p3_util::indices_arr;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
        ParallelIterator,
    },
    slice::ParallelSliceMut,
};
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
        booleanhypercube::BooleanHypercube,
        layer_constraint_system::{
            LayerConstraintSystem, RotationParams, expansion_expr, rotation_split,
        },
        mock::MockProver,
    },
    precompiles::utils::{
        MaskRepresentation, not8_expr, set_slice_felts_from_u64 as push_instance,
    },
    utils::{indices_arr_with_offset, wits_fixed_and_eqs},
};

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

pub const KECCAK_INPUT32_SIZE: usize = 50;
pub const KECCAK_OUTPUT32_SIZE: usize = 50;

pub const KECCAK_OUT_EVAL_SIZE: usize = size_of::<KeccakOutEvals<u8>>();
pub const KECCAK_WIT_SIZE: usize = size_of::<KeccakWitCols<u8>>();
const KECCAK_FIXED_SIZE: usize = size_of::<KeccakFixedCols<u8>>();
const KECCAK_LAYER_SIZE: usize = size_of::<KeccakLayer<u8, u8, ()>>();

const AND_LOOKUPS_PER_ROUND: usize = 200;
const XOR_LOOKUPS_PER_ROUND: usize = 608;
const RANGE_LOOKUPS_PER_ROUND: usize = 290;
const LOOKUP_FELTS_PER_ROUND: usize =
    3 * AND_LOOKUPS_PER_ROUND + 3 * XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND;

pub const AND_LOOKUPS: usize = AND_LOOKUPS_PER_ROUND;
pub const XOR_LOOKUPS: usize = XOR_LOOKUPS_PER_ROUND;
pub const RANGE_LOOKUPS: usize = RANGE_LOOKUPS_PER_ROUND;

#[derive(Clone, Debug)]
pub struct KeccakParams {}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakOutEvals<T> {
    pub output32: [T; KECCAK_OUTPUT32_SIZE],
    pub input32: [T; KECCAK_INPUT32_SIZE],
    pub lookup_entries: [T; LOOKUP_FELTS_PER_ROUND],
}

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
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct KeccakLayer<WitT, FixedT, EqT> {
    pub wits: KeccakWitCols<WitT>,
    pub fixed: KeccakFixedCols<FixedT>,
    pub eq_zero: EqT,
    pub eq_rotation_left: EqT,
    pub eq_rotation_right: EqT,
    pub eq_rotation: EqT,
}

#[derive(Clone, Debug)]
pub struct KeccakLayout<E> {
    layer_exprs: KeccakLayer<WitIn, Fixed, WitIn>,
    layer_in_evals: [usize; KECCAK_LAYER_SIZE],
    final_out_evals: KeccakOutEvals<usize>,
    _marker: PhantomData<E>,
}

impl<E: ExtensionField> Default for KeccakLayout<E> {
    fn default() -> Self {
        // allocate evaluation expressions
        // TODO we can rlc lookup via alpha/beta challenge, so gkr output layer only got rlc result
        let final_out_evals = indices_arr::<KECCAK_OUT_EVAL_SIZE>();
        let final_out_evals = unsafe {
            transmute::<[usize; KECCAK_OUT_EVAL_SIZE], KeccakOutEvals<usize>>(final_out_evals)
        };
        let layer_in_evals = indices_arr_with_offset::<KECCAK_LAYER_SIZE, KECCAK_OUT_EVAL_SIZE>();

        // allocate witnesses, fixed, and eqs
        let (wits, fixed, eqs) = wits_fixed_and_eqs::<KECCAK_WIT_SIZE, KECCAK_FIXED_SIZE, 4>();
        let wits = unsafe { transmute::<[WitIn; KECCAK_WIT_SIZE], KeccakWitCols<WitIn>>(wits) };
        let fixed = unsafe { transmute::<[Fixed; 8], KeccakFixedCols<Fixed>>(fixed) };
        let [eq_zero, eq_rotation_left, eq_rotation_right, eq_rotation] = eqs;

        Self {
            layer_exprs: KeccakLayer {
                wits,
                fixed,
                eq_zero,
                eq_rotation_left,
                eq_rotation_right,
                eq_rotation,
            },
            layer_in_evals,
            final_out_evals,
            _marker: PhantomData,
        }
    }
}

impl<E: ExtensionField> ProtocolBuilder<E> for KeccakLayout<E> {
    type Params = KeccakParams;

    fn init(_params: Self::Params) -> Self {
        Self::default()
    }

    fn build_gkr_chip(&self) -> Chip<E> {
        let mut system = LayerConstraintSystem::new(
            KECCAK_WIT_SIZE,
            0,
            KECCAK_WIT_SIZE,
            Some(self.layer_exprs.eq_zero.expr()),
        );

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
        } = &self.layer_exprs.wits;

        let KeccakFixedCols { rc } = &self.layer_exprs.fixed;

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
                system.constrain_eq(
                    state8[[0, i, k]].into(),
                    c_aux[[i, 0, k]].into(),
                    "init c_aux".to_string(),
                );
            }
            for j in 1..5 {
                // Check xor using lookups over all chunks
                for k in 0..8 {
                    system.lookup_xor8(
                        c_aux[[i, j - 1, k]].into(),
                        state8[[j, i, k]].into(),
                        c_aux[[i, j, k]].into(),
                    );
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

            system.constrain_left_rotation64(
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
                "theta rotation".to_string(),
            );
        }

        // d is computed simply as XOR of required elements of c (and rotations)
        // again stored as 8-bit chunks
        let d: ArrayView<WitIn, Ix2> = ArrayView::from_shape((5, 8), d).unwrap();

        for i in 0..5 {
            for k in 0..8 {
                system.lookup_xor8(
                    c_aux[[(i + 5 - 1) % 5, 4, k]].into(),
                    c_rot[[(i + 1) % 5, k]].into(),
                    d[[i, k]].into(),
                )
            }
        }

        // output state of the Theta sub-round, simple XOR, in 8-bit chunks
        let theta_output: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), theta_output).unwrap();

        for i in 0..5 {
            for j in 0..5 {
                for k in 0..8 {
                    system.lookup_xor8(
                        state8[[j, i, k]].into(),
                        d[[i, k]].into(),
                        theta_output[[j, i, k]].into(),
                    )
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
                system.constrain_left_rotation64(
                    &arg,
                    &rep_split,
                    &arg_rotated,
                    ROTATION_CONSTANTS[j][i],
                    format!("RHOPI {i}, {j}"),
                );
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
                    system.lookup_and8(
                        not8_expr(rhopi_output[[j, (i + 1) % 5, k]].into()),
                        rhopi_output[[j, (i + 2) % 5, k]].into(),
                        nonlinear[[j, i, k]].into(),
                    );

                    system.lookup_xor8(
                        rhopi_output[[j, i, k]].into(),
                        nonlinear[[j, i, k]].into(),
                        chi_output[[j, i, k]].into(),
                    );
                }
            }
        }

        let iota_output_arr: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), iota_output).unwrap();

        for k in 0..8 {
            system.lookup_xor8(
                chi_output[[0, 0, k]].into(),
                rc[k].into(),
                iota_output_arr[[0, 0, k]].into(),
            );
        }

        let keccak_input8: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), input8).unwrap();
        let mut keccak_input32_iter = self
            .final_out_evals
            .input32
            .iter()
            .map(|x| EvalExpression::Single(*x));

        let keccak_output8: ArrayView<WitIn, Ix3> =
            ArrayView::from_shape((5, 5, 8), iota_output).unwrap();
        let mut keccak_output32_iter = self
            .final_out_evals
            .output32
            .iter()
            .map(|x| EvalExpression::Single(*x));

        // process keccak output
        for x in 0..5 {
            for y in 0..5 {
                for k in 0..2 {
                    // create an expression combining 4 elements of state8 into a single 32-bit felt
                    let expr = expansion_expr::<E, 32>(
                        &keccak_output8
                            .slice(s![x, y, 4 * k..4 * (k + 1)])
                            .iter()
                            .map(|e| (8, e.expr()))
                            .collect_vec(),
                    );
                    system.add_non_zero_constraint(
                        expr,
                        (
                            Some(self.layer_exprs.eq_zero.expr()),
                            keccak_output32_iter.next().unwrap(),
                        ),
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
                            .map(|e| (8, e.expr()))
                            .collect_vec()
                            .as_slice(),
                    );
                    system.add_non_zero_constraint(
                        expr,
                        (
                            Some(self.layer_exprs.eq_zero.expr()),
                            keccak_input32_iter.next().unwrap(),
                        ),
                        format!("build 32-bit input: {x}, {y}, {k}"),
                    );
                }
            }
        }

        // rotation constrain: rotation(keccak_input8).next() == keccak_output8
        izip!(keccak_input8, keccak_output8)
            .for_each(|(input, output)| system.rotate_and_assert_eq(input.expr(), output.expr()));
        system.set_rotation_params(RotationParams {
            rotation_eqs: Some([
                self.layer_exprs.eq_rotation_left.expr(),
                self.layer_exprs.eq_rotation_right.expr(),
                self.layer_exprs.eq_rotation.expr(),
            ]),
            rotation_cyclic_group_log2: ROUNDS_CEIL_LOG2,
            rotation_cyclic_subgroup_size: ROUNDS - 1,
        });

        assert_eq!(system.and_lookups.len(), AND_LOOKUPS);
        assert_eq!(system.xor_lookups.len(), XOR_LOOKUPS);
        assert_eq!(system.range_lookups.len(), RANGE_LOOKUPS);

        let mut chip = Chip {
            n_fixed: self.n_fixed(),
            n_committed: self.n_committed(),
            n_challenges: self.n_challenges(),
            n_evaluations: self.n_evaluations(),
            n_nonzero_out_evals: self.n_nonzero_out_evals(),
            final_out_evals: unsafe {
                transmute::<KeccakOutEvals<usize>, [usize; KECCAK_OUT_EVAL_SIZE]>(
                    self.final_out_evals.clone(),
                )
            }
            .to_vec(),
            layers: vec![],
        };

        let lookup_evals_iter = self
            .final_out_evals
            .lookup_entries
            .iter()
            .cloned()
            .map(|id| (Some(self.layer_exprs.eq_zero.expr()), id));
        let layer = system.into_layer_with_lookup_eval_iter(
            "Rounds".to_string(),
            self.layer_in_evals.to_vec(),
            vec![],
            lookup_evals_iter,
        );
        chip.add_layer(layer);
        chip
    }

    fn n_committed(&self) -> usize {
        KECCAK_WIT_SIZE
    }

    fn n_fixed(&self) -> usize {
        KECCAK_FIXED_SIZE
    }

    fn n_challenges(&self) -> usize {
        0
    }

    fn n_nonzero_out_evals(&self) -> usize {
        KECCAK_OUT_EVAL_SIZE
    }

    fn n_layers(&self) -> usize {
        1
    }

    fn n_evaluations(&self) -> usize {
        self.n_committed() + self.n_fixed() + self.n_nonzero_out_evals()
    }
}

#[derive(Clone, Default)]
pub struct KeccakTrace {
    pub instances: Vec<[u32; KECCAK_INPUT32_SIZE]>,
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
                for round in 0..ROUNDS {
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
                    iota_output64[0][0] ^= RC[round];

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
    let rc_witness = RC
        .iter()
        .map(|x| {
            (0..8)
                .map(|i| E::BaseField::from_canonical_u64((x >> (i << 3)) & 0xFF))
                .collect_vec()
        })
        .collect_vec();
    let (gkr_witness, gkr_output) =
        layout.gkr_witness(&gkr_circuit, &phase1_witness, &rc_witness, &[]);
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

    if cfg!(debug_assertions) {
        // mock prover
        let out_wits = gkr_output
            .0
            .iter()
            .map(|poly| poly.evaluations())
            .collect_vec();
        MockProver::check(gkr_circuit.clone(), &gkr_witness, out_wits, vec![])
            .expect("mock prover failed");
    }

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
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_keccakf() {
        type E = GoldilocksExt2;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_instances = 8;
        let mut states: Vec<[u64; 25]> = Vec::with_capacity(num_instances);
        for _ in 0..num_instances {
            states.push(std::array::from_fn(|_| rng.next_u64()));
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
            states.push(std::array::from_fn(|_| rng.next_u64()));
        }

        // TODO enable check
        let _ = run_faster_keccakf(setup_gkr_circuit::<E>(), states, true, true);
    }
}
