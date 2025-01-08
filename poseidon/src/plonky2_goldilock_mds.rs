//! this is just for compatible with plonky2 poseidon result, refer from plonky3 commit
//! https://github.com/Plonky3/Plonky3/commit/13ad333f3c74e5986df161dd7189eac3fe73e520
//! once upgrade to poseidon2 we can remove this functionality
use p3_field::FieldAlgebra;
use p3_goldilocks::Goldilocks;
use p3_mds::MdsPermutation;
use p3_symmetric::Permutation;
use unroll::unroll_for_loops;

use crate::SPONGE_WIDTH;
#[derive(Clone)]

pub struct P2MdsMatrixGoldilocks {
    pub matrix: [[Goldilocks; SPONGE_WIDTH]; SPONGE_WIDTH],
}

impl Permutation<[Goldilocks; SPONGE_WIDTH]> for P2MdsMatrixGoldilocks {
    #[unroll_for_loops]
    #[allow(clippy::needless_range_loop)]
    fn permute(&self, input: [Goldilocks; SPONGE_WIDTH]) -> [Goldilocks; SPONGE_WIDTH] {
        let mut output = [Goldilocks::ZERO; SPONGE_WIDTH];
        for i in 0..SPONGE_WIDTH {
            for j in 0..SPONGE_WIDTH {
                output[i] += self.matrix[i][j] * input[j];
            }
        }
        output
    }
    fn permute_mut(&self, input: &mut [Goldilocks; 12]) {
        *input = self.permute(*input);
    }
}

impl MdsPermutation<Goldilocks, SPONGE_WIDTH> for P2MdsMatrixGoldilocks {}

impl P2MdsMatrixGoldilocks {
    const CIRC: [u64; SPONGE_WIDTH] = [17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20];
    const DIAG: [u64; SPONGE_WIDTH] = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

impl Default for P2MdsMatrixGoldilocks {
    #[allow(clippy::needless_range_loop)]
    fn default() -> Self {
        let mut matrix = [[Goldilocks::ZERO; SPONGE_WIDTH]; SPONGE_WIDTH];
        for i in 0..SPONGE_WIDTH {
            for j in 0..SPONGE_WIDTH {
                matrix[i][j] = Goldilocks::from_canonical_u64(
                    Self::CIRC[(SPONGE_WIDTH + j - i) % SPONGE_WIDTH],
                );
                if i == j {
                    matrix[i][j] += Goldilocks::from_canonical_u64(Self::DIAG[i]);
                }
            }
        }
        Self { matrix }
    }
}
