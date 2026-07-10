#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct ForkedTranscriptCols {
    T proof_idx;
    T is_proof_start;
    T tidx;
    T is_sample;
    T mask[8];
    T prev_state[16];
    T post_state[16];
    T is_fork_start;
    T is_fork;
    T fork_id;
};

__global__ void transcript_tracegen(
    Fp *trace,
    size_t height,
    const TranscriptRowData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const TranscriptRowData &record = records[row_idx];
        COL_WRITE_VALUE(row, ForkedTranscriptCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, is_proof_start, record.is_proof_start);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, tidx, record.tidx);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, is_sample, record.is_sample);
        COL_WRITE_ARRAY(row, ForkedTranscriptCols, mask, record.mask);
        COL_WRITE_ARRAY(row, ForkedTranscriptCols, prev_state, record.prev_state);
        COL_WRITE_ARRAY(row, ForkedTranscriptCols, post_state, record.post_state);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, is_fork_start, record.is_fork_start);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, is_fork, record.is_fork);
        COL_WRITE_VALUE(row, ForkedTranscriptCols, fork_id, record.fork_id);
    } else {
        row.fill_zero(0, sizeof(ForkedTranscriptCols<uint8_t>));
    }
}

extern "C" int _transcript_tracegen(
    Fp *d_trace,
    size_t height,
    const TranscriptRowData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    transcript_tracegen<<<grid, block, 0, stream>>>(d_trace, height, d_records, num_records);
    return CHECK_KERNEL();
}
