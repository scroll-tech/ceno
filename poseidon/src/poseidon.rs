use ff_ext::SmallField;
use p3_field::PrimeField;

use crate::constants::{N_PARTIAL_ROUNDS, N_ROUNDS, SPONGE_WIDTH};

pub trait PoseidonField: SmallField + PrimeField {
    // Total number of round constants required: width of the input
    // times number of rounds.

    const SPONGE_WIDTH: usize = SPONGE_WIDTH;
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
}
