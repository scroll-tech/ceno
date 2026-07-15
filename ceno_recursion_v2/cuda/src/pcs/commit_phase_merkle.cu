#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct PcsCommitPhaseMerkleCols {
    T is_enabled;
    T proof_idx;
    T query_idx;
    T round;
    T step;
    T is_first;
    T is_last;
    T idx_in;
    T idx_bit;
    T idx_out;
    T current[DIGEST_SIZE];
    T sibling[DIGEST_SIZE];
    T left[DIGEST_SIZE];
    T right[DIGEST_SIZE];
    T output[DIGEST_SIZE];
};

__global__ void pcs_commit_phase_merkle_tracegen(
    Fp *trace,
    size_t height,
    const PcsCommitPhaseMerkleData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const PcsCommitPhaseMerkleData &record = records[row_idx];
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, query_idx, record.query_idx);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, round, record.round);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, step, record.step);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, is_first, record.is_first);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, is_last, record.is_last);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, idx_in, record.idx_in);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, idx_bit, record.idx_bit);
        COL_WRITE_VALUE(row, PcsCommitPhaseMerkleCols, idx_out, record.idx_out);
        COL_WRITE_ARRAY(row, PcsCommitPhaseMerkleCols, current, record.current);
        COL_WRITE_ARRAY(row, PcsCommitPhaseMerkleCols, sibling, record.sibling);
        COL_WRITE_ARRAY(row, PcsCommitPhaseMerkleCols, left, record.left);
        COL_WRITE_ARRAY(row, PcsCommitPhaseMerkleCols, right, record.right);
        COL_WRITE_ARRAY(row, PcsCommitPhaseMerkleCols, output, record.output);
    } else {
        row.fill_zero(0, sizeof(PcsCommitPhaseMerkleCols<uint8_t>));
    }
}

extern "C" int _pcs_commit_phase_merkle_tracegen(
    Fp *d_trace,
    size_t height,
    const PcsCommitPhaseMerkleData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    pcs_commit_phase_merkle_tracegen<<<grid, block, 0, stream>>>(
        d_trace, height, d_records, num_records
    );
    return CHECK_KERNEL();
}
