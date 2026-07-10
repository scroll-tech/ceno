#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct PcsEqProductCols {
    T is_enabled;
    T proof_idx;
    T kind;
    T source;
    T round_idx;
    T term_idx;
    T bit_idx;
    T is_first;
    T is_last;
    T lookup_count;
    T point_tidx;
    T sumcheck_idx;
    T point_round;
    T index_bit;
    T index_pow2;
    T index_acc_in;
    T index_acc_out;
    T point[D_EF];
    T acc_in[D_EF];
    T acc_out[D_EF];
};

__global__ void pcs_eq_product_tracegen(
    Fp *trace,
    size_t height,
    const PcsEqProductData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const PcsEqProductData &record = records[row_idx];
        COL_WRITE_VALUE(row, PcsEqProductCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, PcsEqProductCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, PcsEqProductCols, kind, record.kind);
        COL_WRITE_VALUE(row, PcsEqProductCols, source, record.source);
        COL_WRITE_VALUE(row, PcsEqProductCols, round_idx, record.round_idx);
        COL_WRITE_VALUE(row, PcsEqProductCols, term_idx, record.term_idx);
        COL_WRITE_VALUE(row, PcsEqProductCols, bit_idx, record.bit_idx);
        COL_WRITE_VALUE(row, PcsEqProductCols, is_first, record.is_first);
        COL_WRITE_VALUE(row, PcsEqProductCols, is_last, record.is_last);
        COL_WRITE_VALUE(row, PcsEqProductCols, lookup_count, record.lookup_count);
        COL_WRITE_VALUE(row, PcsEqProductCols, point_tidx, record.point_tidx);
        COL_WRITE_VALUE(row, PcsEqProductCols, sumcheck_idx, record.sumcheck_idx);
        COL_WRITE_VALUE(row, PcsEqProductCols, point_round, record.point_round);
        COL_WRITE_VALUE(row, PcsEqProductCols, index_bit, record.index_bit);
        COL_WRITE_VALUE(row, PcsEqProductCols, index_pow2, record.index_pow2);
        COL_WRITE_VALUE(row, PcsEqProductCols, index_acc_in, record.index_acc_in);
        COL_WRITE_VALUE(row, PcsEqProductCols, index_acc_out, record.index_acc_out);
        COL_WRITE_ARRAY(row, PcsEqProductCols, point, record.point);
        COL_WRITE_ARRAY(row, PcsEqProductCols, acc_in, record.acc_in);
        COL_WRITE_ARRAY(row, PcsEqProductCols, acc_out, record.acc_out);
    } else {
        row.fill_zero(0, sizeof(PcsEqProductCols<uint8_t>));
    }
}

extern "C" int _pcs_eq_product_tracegen(
    Fp *d_trace,
    size_t height,
    const PcsEqProductData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    pcs_eq_product_tracegen<<<grid, block, 0, stream>>>(d_trace, height, d_records, num_records);
    return CHECK_KERNEL();
}
