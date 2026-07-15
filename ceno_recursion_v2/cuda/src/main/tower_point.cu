#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct MainTowerPointEqCols {
    T is_enabled;
    T proof_idx;
    T idx;
    T round_idx;
    T global_value[D_EF];
    T tower_value[D_EF];
    T eq_in[D_EF];
    T eq_out[D_EF];
};

__global__ void main_tower_point_eq_tracegen(
    Fp *trace,
    size_t height,
    const MainTowerPointEqData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        MainTowerPointEqData record = records[row_idx];
        COL_WRITE_VALUE(row, MainTowerPointEqCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, MainTowerPointEqCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, MainTowerPointEqCols, idx, record.idx);
        COL_WRITE_VALUE(row, MainTowerPointEqCols, round_idx, record.round_idx);
        COL_WRITE_ARRAY(row, MainTowerPointEqCols, global_value, record.global_value);
        COL_WRITE_ARRAY(row, MainTowerPointEqCols, tower_value, record.tower_value);
        COL_WRITE_ARRAY(row, MainTowerPointEqCols, eq_in, record.eq_in);
        COL_WRITE_ARRAY(row, MainTowerPointEqCols, eq_out, record.eq_out);
    } else {
        row.fill_zero(0, sizeof(MainTowerPointEqCols<uint8_t>));
    }
}

extern "C" int _main_tower_point_eq_tracegen(
    Fp *d_trace,
    size_t height,
    const MainTowerPointEqData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height);
    main_tower_point_eq_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
