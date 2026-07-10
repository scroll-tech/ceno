#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct TowerLayerSumcheckCols {
    T is_enabled;
    T proof_idx;
    T idx;
    T fork_id;
    T layer_idx;
    T is_first_idx;
    T is_first_layer;
    T is_first_round;
    T is_dummy;
    T is_last_layer;
    T round;
    T tidx;
    T ev1[D_EF];
    T ev2[D_EF];
    T ev3[D_EF];
    T claim_in[D_EF];
    T claim_out[D_EF];
    T prev_challenge[D_EF];
    T challenge[D_EF];
    T eq_in[D_EF];
    T eq_out[D_EF];
};

__global__ void tower_sumcheck_tracegen(
    Fp *trace,
    size_t height,
    const TowerSumcheckData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const TowerSumcheckData &record = records[row_idx];
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, idx, record.idx);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, fork_id, record.fork_id);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, layer_idx, record.layer_idx);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_first_idx, record.is_first_idx);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_first_layer, record.is_first_layer);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_first_round, record.is_first_round);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_dummy, record.is_dummy);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, is_last_layer, record.is_last_layer);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, round, record.round);
        COL_WRITE_VALUE(row, TowerLayerSumcheckCols, tidx, record.tidx);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, ev1, record.ev1);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, ev2, record.ev2);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, ev3, record.ev3);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, claim_in, record.claim_in);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, claim_out, record.claim_out);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, prev_challenge, record.prev_challenge);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, challenge, record.challenge);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, eq_in, record.eq_in);
        COL_WRITE_ARRAY(row, TowerLayerSumcheckCols, eq_out, record.eq_out);
    } else {
        row.fill_zero(0, sizeof(TowerLayerSumcheckCols<uint8_t>));
    }
}

extern "C" int _tower_sumcheck_tracegen(
    Fp *d_trace,
    size_t height,
    const TowerSumcheckData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    tower_sumcheck_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
