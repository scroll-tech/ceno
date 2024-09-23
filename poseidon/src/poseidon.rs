use crate::constants::{
    ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_ROUNDS, SPONGE_WIDTH,
};
use goldilocks::SmallField;
use unroll::unroll_for_loops;

pub trait Poseidon: AdaptedField {
    // Total number of round constants required: width of the input
    // times number of rounds.
    const N_ROUND_CONSTANTS: usize = SPONGE_WIDTH * N_ROUNDS;

    // The MDS matrix we use is C + D, where C is the circulant matrix whose first
    // row is given by `MDS_MATRIX_CIRC`, and D is the diagonal matrix whose
    // diagonal is given by `MDS_MATRIX_DIAG`.
    const MDS_MATRIX_CIRC: [u64; SPONGE_WIDTH];
    const MDS_MATRIX_DIAG: [u64; SPONGE_WIDTH];

    // Precomputed constants for the fast Poseidon calculation. See
    // the paper.
    const FAST_PARTIAL_FIRST_ROUND_CONSTANT: [u64; SPONGE_WIDTH];
    const FAST_PARTIAL_ROUND_CONSTANTS: [u64; N_PARTIAL_ROUNDS];
    const FAST_PARTIAL_ROUND_VS: [[u64; SPONGE_WIDTH - 1]; N_PARTIAL_ROUNDS];
    const FAST_PARTIAL_ROUND_W_HATS: [[u64; SPONGE_WIDTH - 1]; N_PARTIAL_ROUNDS];
    const FAST_PARTIAL_ROUND_INITIAL_MATRIX: [[u64; SPONGE_WIDTH - 1]; SPONGE_WIDTH - 1];

    #[inline]
    fn poseidon(input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        let mut state = input;
        let mut round_ctr = 0;

        Self::full_rounds(&mut state, &mut round_ctr);
        Self::partial_rounds(&mut state, &mut round_ctr);
        Self::full_rounds(&mut state, &mut round_ctr);
        debug_assert_eq!(round_ctr, N_ROUNDS);

        state
    }

    #[inline]
    fn full_rounds(state: &mut [Self; SPONGE_WIDTH], round_ctr: &mut usize) {
        for _ in 0..HALF_N_FULL_ROUNDS {
            Self::constant_layer(state, *round_ctr);
            Self::sbox_layer(state);
            *state = Self::mds_layer(state);
            *round_ctr += 1;
        }
    }

    #[inline]
    fn partial_rounds(state: &mut [Self; SPONGE_WIDTH], round_ctr: &mut usize) {
        Self::partial_first_constant_layer(state);
        *state = Self::mds_partial_layer_init(state);

        for i in 0..N_PARTIAL_ROUNDS {
            state[0] = Self::sbox_monomial(state[0]);
            unsafe {
                state[0] = state[0].add_canonical_u64(Self::FAST_PARTIAL_ROUND_CONSTANTS[i]);
            }
            *state = Self::mds_partial_layer_fast(state, i);
        }
        *round_ctr += N_PARTIAL_ROUNDS;
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn constant_layer(state: &mut [Self; SPONGE_WIDTH], round_ctr: usize) {
        for i in 0..12 {
            if i < SPONGE_WIDTH {
                let round_constant = ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr];
                unsafe {
                    state[i] = state[i].add_canonical_u64(round_constant);
                }
            }
        }
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn sbox_layer(state: &mut [Self; SPONGE_WIDTH]) {
        for i in 0..12 {
            if i < SPONGE_WIDTH {
                state[i] = Self::sbox_monomial(state[i]);
            }
        }
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn mds_layer(state_: &[Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        let mut result = [Self::ZERO; SPONGE_WIDTH];

        let mut state = [0u64; SPONGE_WIDTH];
        for r in 0..SPONGE_WIDTH {
            state[r] = state_[r].to_noncanonical_u64();
        }

        // This is a hacky way of fully unrolling the loop.
        for r in 0..12 {
            if r < SPONGE_WIDTH {
                let sum = Self::mds_row_shf(r, &state);
                let sum_lo = sum as u64;
                let sum_hi = (sum >> 64) as u32;
                result[r] = Self::from_noncanonical_u96(sum_lo, sum_hi);
            }
        }

        result
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn partial_first_constant_layer(state: &mut [Self; SPONGE_WIDTH]) {
        for i in 0..12 {
            if i < SPONGE_WIDTH {
                state[i] += Self::from_canonical_u64(Self::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]);
            }
        }
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn mds_partial_layer_init(state: &[Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        let mut result = [Self::ZERO; SPONGE_WIDTH];

        // Initial matrix has first row/column = [1, 0, ..., 0];

        // c = 0
        result[0] = state[0];

        for r in 1..12 {
            if r < SPONGE_WIDTH {
                for c in 1..12 {
                    if c < SPONGE_WIDTH {
                        // NB: FAST_PARTIAL_ROUND_INITIAL_MATRIX is stored in
                        // row-major order so that this dot product is cache
                        // friendly.
                        let t = Self::from_canonical_u64(
                            Self::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1],
                        );
                        result[c] += state[r] * t;
                    }
                }
            }
        }
        result
    }

    #[inline(always)]
    fn sbox_monomial(x: Self) -> Self {
        // Observed a performance improvement by using x*x rather than x.square().
        // In Plonky2, where this function originates, operations might be over an algebraic extension field.
        // Specialized square functions could leverage the field's structure for potential savings.
        // Adding this note in case future generalizations or optimizations are considered.

        // x |--> x^7
        let x2 = x * x;
        let x4 = x2 * x2;
        let x3 = x * x2;
        x3 * x4
    }

    /// Computes s*A where s is the state row vector and A is the matrix
    ///
    ///    [ M_00  | v  ]
    ///    [ ------+--- ]
    ///    [ w_hat | Id ]
    ///
    /// M_00 is a scalar, v is 1x(t-1), w_hat is (t-1)x1 and Id is the
    /// (t-1)x(t-1) identity matrix.
    #[inline(always)]
    #[unroll_for_loops]
    fn mds_partial_layer_fast(state: &[Self; SPONGE_WIDTH], r: usize) -> [Self; SPONGE_WIDTH] {
        // Set d = [M_00 | w^] dot [state]

        let mut d_sum = (0u128, 0u32); // u160 accumulator
        for i in 1..12 {
            if i < SPONGE_WIDTH {
                let t = Self::FAST_PARTIAL_ROUND_W_HATS[r][i - 1] as u128;
                let si = state[i].to_noncanonical_u64() as u128;
                d_sum = add_u160_u128(d_sum, si * t);
            }
        }
        let s0 = state[0].to_noncanonical_u64() as u128;
        let mds0to0 = (Self::MDS_MATRIX_CIRC[0] + Self::MDS_MATRIX_DIAG[0]) as u128;
        d_sum = add_u160_u128(d_sum, s0 * mds0to0);
        let d = reduce_u160::<Self>(d_sum);

        // result = [d] concat [state[0] * v + state[shift up by 1]]
        let mut result = [Self::ZERO; SPONGE_WIDTH];
        result[0] = d;
        for i in 1..12 {
            if i < SPONGE_WIDTH {
                let t = Self::from_canonical_u64(Self::FAST_PARTIAL_ROUND_VS[r][i - 1]);
                result[i] = state[i].multiply_accumulate(state[0], t);
            }
        }
        result
    }

    #[inline(always)]
    #[unroll_for_loops]
    fn mds_row_shf(r: usize, v: &[u64; SPONGE_WIDTH]) -> u128 {
        debug_assert!(r < SPONGE_WIDTH);
        // The values of `MDS_MATRIX_CIRC` and `MDS_MATRIX_DIAG` are
        // known to be small, so we can accumulate all the products for
        // each row and reduce just once at the end (done by the
        // caller).

        // NB: Unrolling this, calculating each term independently, and
        // summing at the end, didn't improve performance for me.
        let mut res = 0u128;

        // This is a hacky way of fully unrolling the loop.
        for i in 0..12 {
            if i < SPONGE_WIDTH {
                res += (v[(i + r) % SPONGE_WIDTH] as u128) * (Self::MDS_MATRIX_CIRC[i] as u128);
            }
        }
        res += (v[r] as u128) * (Self::MDS_MATRIX_DIAG[r] as u128);

        res
    }
}

#[inline(always)]
const fn add_u160_u128((x_lo, x_hi): (u128, u32), y: u128) -> (u128, u32) {
    let (res_lo, over) = x_lo.overflowing_add(y);
    let res_hi = x_hi + (over as u32);
    (res_lo, res_hi)
}

#[inline(always)]
fn reduce_u160<F: AdaptedField>((n_lo, n_hi): (u128, u32)) -> F {
    let n_lo_hi = (n_lo >> 64) as u64;
    let n_lo_lo = n_lo as u64;
    let reduced_hi: u64 = F::from_noncanonical_u96(n_lo_hi, n_hi).to_noncanonical_u64();
    let reduced128: u128 = ((reduced_hi as u128) << 64) + (n_lo_lo as u128);
    F::from_noncanonical_u128(reduced128)
}

pub trait AdaptedField: SmallField {
    const ORDER: u64;

    fn from_noncanonical_u96(n_lo: u64, n_hi: u32) -> Self;

    fn from_noncanonical_u128(n: u128) -> Self;

    fn multiply_accumulate(&self, x: Self, y: Self) -> Self;

    /// Returns `n`. Assumes that `n` is already in canonical form, i.e. `n < Self::order()`.
    // TODO: Should probably be unsafe.
    fn from_canonical_u64(n: u64) -> Self {
        debug_assert!(n < Self::ORDER);
        Self::from(n)
    }

    /// # Safety
    /// Equivalent to *self + Self::from_canonical_u64(rhs), but may be cheaper. The caller must
    /// ensure that 0 <= rhs < Self::ORDER. The function may return incorrect results if this
    /// precondition is not met. It is marked unsafe for this reason.
    #[inline]
    unsafe fn add_canonical_u64(&self, rhs: u64) -> Self {
        // Default implementation.
        *self + Self::from_canonical_u64(rhs)
    }
}
