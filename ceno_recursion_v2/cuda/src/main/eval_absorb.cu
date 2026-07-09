#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct MainEvalAbsorbCols {
    T is_enabled;
    T proof_idx;
    T idx;
    T eval_idx;
    T tidx;
    T lookup_count;
    T value[D_EF];
};

__global__ void main_eval_absorb_tracegen(
    Fp *trace,
    size_t height,
    const MainEvalData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        MainEvalData record = records[row_idx];
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, idx, record.idx);
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, eval_idx, record.eval_idx);
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, tidx, record.tidx);
        COL_WRITE_VALUE(row, MainEvalAbsorbCols, lookup_count, record.lookup_count);
        COL_WRITE_ARRAY(row, MainEvalAbsorbCols, value, record.value);
    } else {
        row.fill_zero(0, sizeof(MainEvalAbsorbCols<uint8_t>));
    }
}

extern "C" int _main_eval_absorb_tracegen(
    Fp *d_trace,
    size_t height,
    const MainEvalData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height);
    main_eval_absorb_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
