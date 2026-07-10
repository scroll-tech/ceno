#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct PcsJaggedAssistQCols {
    T is_enabled;
    T proof_idx;
    T round_idx;
    T sumcheck_idx;
    T commitment_kind;
    T term_idx;
    T step_idx;
    T robp_idx;
    T is_first;
    T is_last;
    T is_first_step;
    T is_last_step;
    T term_is_last;
    T is_next_term;
    T eq_col[D_EF];
    T t_lo;
    T t_hi;
    T c_bit;
    T d_bit;
    T bit_pow2;
    T c_acc_in;
    T c_acc_out;
    T d_acc_in;
    T d_acc_out;
    T rho_star_c[D_EF];
    T rho_star_d[D_EF];
    T factor[D_EF];
    T term_acc_in[D_EF];
    T term_acc_out[D_EF];
    T q_acc_in[D_EF];
    T q_acc_out[D_EF];
};

__global__ void pcs_jagged_assist_q_tracegen(
    Fp *trace,
    size_t height,
    const PcsJaggedAssistQData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const PcsJaggedAssistQData &record = records[row_idx];
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, round_idx, record.round_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, sumcheck_idx, record.sumcheck_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, commitment_kind, record.commitment_kind);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, term_idx, record.term_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, step_idx, record.step_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, robp_idx, record.robp_idx);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, is_first, record.is_first);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, is_last, record.is_last);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, is_first_step, record.is_first_step);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, is_last_step, record.is_last_step);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, term_is_last, record.term_is_last);
        COL_WRITE_VALUE(
            row,
            PcsJaggedAssistQCols,
            is_next_term,
            record.is_last_step && !record.term_is_last
        );
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, eq_col, record.eq_col);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, t_lo, record.t_lo);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, t_hi, record.t_hi);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, c_bit, record.c_bit);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, d_bit, record.d_bit);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, bit_pow2, record.bit_pow2);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, c_acc_in, record.c_acc_in);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, c_acc_out, record.c_acc_out);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, d_acc_in, record.d_acc_in);
        COL_WRITE_VALUE(row, PcsJaggedAssistQCols, d_acc_out, record.d_acc_out);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, rho_star_c, record.rho_star_c);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, rho_star_d, record.rho_star_d);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, factor, record.factor);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, term_acc_in, record.term_acc_in);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, term_acc_out, record.term_acc_out);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, q_acc_in, record.q_acc_in);
        COL_WRITE_ARRAY(row, PcsJaggedAssistQCols, q_acc_out, record.q_acc_out);
    } else {
        row.fill_zero(0, sizeof(PcsJaggedAssistQCols<uint8_t>));
        row.write(COL_INDEX(PcsJaggedAssistQCols, factor), Fp::one());
    }
}

extern "C" int _pcs_jagged_assist_q_tracegen(
    Fp *d_trace,
    size_t height,
    const PcsJaggedAssistQData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    pcs_jagged_assist_q_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
