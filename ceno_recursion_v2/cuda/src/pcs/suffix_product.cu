#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct PcsSuffixProductCols {
    T is_enabled;
    T proof_idx;
    T round_idx;
    T term_idx;
    T coord_idx;
    T step_idx;
    T is_first;
    T is_last;
    T has_factor;
    T point[D_EF];
    T acc_in[D_EF];
    T acc_out[D_EF];
};

__global__ void pcs_suffix_product_tracegen(
    Fp *trace,
    size_t height,
    const PcsSuffixProductData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const PcsSuffixProductData &record = records[row_idx];
        COL_WRITE_VALUE(row, PcsSuffixProductCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, PcsSuffixProductCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, round_idx, record.round_idx);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, term_idx, record.term_idx);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, coord_idx, record.coord_idx);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, step_idx, record.step_idx);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, is_first, record.is_first);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, is_last, record.is_last);
        COL_WRITE_VALUE(row, PcsSuffixProductCols, has_factor, record.has_factor);
        COL_WRITE_ARRAY(row, PcsSuffixProductCols, point, record.point);
        COL_WRITE_ARRAY(row, PcsSuffixProductCols, acc_in, record.acc_in);
        COL_WRITE_ARRAY(row, PcsSuffixProductCols, acc_out, record.acc_out);
    } else {
        row.fill_zero(0, sizeof(PcsSuffixProductCols<uint8_t>));
    }
}

extern "C" int _pcs_suffix_product_tracegen(
    Fp *d_trace,
    size_t height,
    const PcsSuffixProductData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    pcs_suffix_product_tracegen<<<grid, block, 0, stream>>>(
        d_trace, height, d_records, num_records
    );
    return CHECK_KERNEL();
}
