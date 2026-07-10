#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct MainFrontloadTermCols {
    T is_enabled;
    T proof_idx;
    T idx;
    T row_idx;
    T node_idx;
    T eval_idx;
    T has_eval_factor;
    T instance_idx;
    T challenge_idx;
    T global_round_idx;
    T has_global_factor;
    T is_wit;
    T is_const;
    T is_instance;
    T is_challenge;
    T is_add;
    T is_sub;
    T is_neg;
    T is_mul;
    T is_fold;
    T is_tail;
    T constraint_idx;
    T alpha[D_EF];
    T arg0[D_EF];
    T arg1[D_EF];
    T value[D_EF];
    T chip_acc_in[D_EF];
    T chip_acc_out[D_EF];
    T is_last_chip_step;
};

__global__ void main_frontload_term_tracegen(
    Fp *trace,
    size_t height,
    const MainFrontloadTermData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const MainFrontloadTermData &record = records[row_idx];
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, MainFrontloadTermCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, idx, record.idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, row_idx, record.row_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, node_idx, record.node_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, eval_idx, record.eval_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, has_eval_factor, record.has_eval_factor);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, instance_idx, record.instance_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, challenge_idx, record.challenge_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, global_round_idx, record.global_round_idx);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, has_global_factor, record.has_global_factor);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_wit, record.is_wit);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_const, record.is_const);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_instance, record.is_instance);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_challenge, record.is_challenge);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_add, record.is_add);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_sub, record.is_sub);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_neg, record.is_neg);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_mul, record.is_mul);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_fold, record.is_fold);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_tail, record.is_tail);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, constraint_idx, record.constraint_idx);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, alpha, record.alpha);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, arg0, record.arg0);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, arg1, record.arg1);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, value, record.value);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, chip_acc_in, record.chip_acc_in);
        COL_WRITE_ARRAY(row, MainFrontloadTermCols, chip_acc_out, record.chip_acc_out);
        COL_WRITE_VALUE(row, MainFrontloadTermCols, is_last_chip_step, record.is_last_chip_step);
    } else {
        row.fill_zero(0, sizeof(MainFrontloadTermCols<uint8_t>));
    }
}

extern "C" int _main_frontload_term_tracegen(
    Fp *d_trace,
    size_t height,
    const MainFrontloadTermData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    main_frontload_term_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
